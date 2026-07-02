defmodule SigilGuard.Conformance.ConsumerContractsTest do
  @moduledoc false

  use ExUnit.Case, async: false
  use ExUnitProperties

  alias SigilGuard.Audit
  alias SigilGuard.Signer.Ed25519
  alias SigilGuard.Vault

  defmodule ActorPatternIdentity do
    @moduledoc false

    @behaviour SigilGuard.Identity

    @impl SigilGuard.Identity
    def identity(%{actor: actor}) when is_binary(actor), do: actor
    def identity(%{"actor" => actor}) when is_binary(actor), do: actor
    def identity(_), do: "host:anonymous"

    @impl SigilGuard.Identity
    def trust_level(%{actor: "host:operator:" <> _}), do: :high
    def trust_level(%{"actor" => "host:operator:" <> _}), do: :high
    def trust_level(%{actor: "host:user:" <> _}), do: :medium
    def trust_level(%{"actor" => "host:user:" <> _}), do: :medium
    def trust_level(_), do: :low

    @impl SigilGuard.Identity
    def bindings(context) do
      ["actor:" <> identity(context)]
    end
  end

  defmodule RequestSigningSigner do
    @moduledoc false

    @behaviour SigilGuard.Signer

    @seed :binary.list_to_bin(Enum.to_list(1..32))
    @signer Ed25519.new(@seed)

    @impl SigilGuard.Signer
    def sign(message), do: Ed25519.sign_with(@signer, message)

    @impl SigilGuard.Signer
    def public_key, do: @signer.public_key
  end

  defmodule DatabaseBackedVault do
    @moduledoc false

    @behaviour SigilGuard.Vault

    @table __MODULE__

    @spec init!() :: :ok
    def init! do
      case :ets.whereis(@table) do
        :undefined ->
          :ets.new(@table, [:named_table, :public, :set])
          :ok

        _ ->
          :ets.delete_all_objects(@table)
          :ok
      end
    end

    @impl SigilGuard.Vault
    def encrypt(plaintext, description) when is_binary(plaintext) and is_binary(description) do
      init_if_missing()

      id =
        "vault:" <>
          Base.encode16(:crypto.hash(:sha256, [description, "\0", plaintext]), case: :lower)

      true = :ets.insert(@table, {id, plaintext, description})
      {:ok, id}
    end

    @impl SigilGuard.Vault
    def decrypt(vault_id) when is_binary(vault_id) do
      init_if_missing()

      case :ets.lookup(@table, vault_id) do
        [{^vault_id, plaintext, _}] -> {:ok, plaintext}
        [] -> {:error, :not_found}
      end
    end

    @impl SigilGuard.Vault
    def exists?(vault_id) when is_binary(vault_id) do
      init_if_missing()
      :ets.member(@table, vault_id)
    end

    def exists?(_), do: false

    defp init_if_missing do
      if :ets.whereis(@table) == :undefined do
        init!()
      end
    end
  end

  @audit_fields [
    :action,
    :action_info,
    :actor,
    :actor_info,
    :event_type,
    :hmac,
    :id,
    :metadata,
    :prev_hmac,
    :result,
    :result_info,
    :timestamp,
    :type
  ]

  @ed25519_seed :binary.list_to_bin(Enum.to_list(1..32))
  @ed25519_message "sigilguard-consumer-contract"
  @ed25519_public_key Base.decode16!(
                        "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664",
                        case: :lower
                      )
  @ed25519_signature Base.decode16!(
                       "60f91352b3f1cce850fdd77a306dc330853ea94ca5fc4161708c26169de3bd2e19e5e3aad8b9eeb2469fcba20767759d10d5429f2067afc63f6c1335a013ea0d",
                       case: :lower
                     )

  setup do
    DatabaseBackedVault.init!()
    :ok
  end

  describe "D17 facade contracts" do
    test "scan/1 returns the stable clean and hit shapes" do
      assert {:ok, "safe text"} = SigilGuard.scan("safe text")

      assert {:hit, hits} = SigilGuard.scan("AKIAIOSFODNN7EXAMPLE")
      assert [_ | _] = hits
      assert Enum.all?(hits, &valid_hit?/1)
    end

    test "scan_and_redact/1 always returns a binary" do
      assert is_binary(SigilGuard.scan_and_redact("safe text"))
      assert is_binary(SigilGuard.scan_and_redact("token=supersecretvalue123"))
    end

    property "policy_verdict/3 only returns the stable facade vocabulary" do
      check all(
              action <- member_of(["read_file", "create_resource", "delete_database"]),
              trust <- member_of([:low, :medium, :high]),
              risk <- member_of([:low, :medium, :high])
            ) do
        verdict = SigilGuard.policy_verdict(action, trust, risk_level: risk)
        assert valid_policy_verdict?(verdict)
      end
    end

    test "foreign facade shapes are rejected by the conformance validators" do
      refute valid_policy_verdict?(:allow)
      refute valid_policy_verdict?({:confirm, :not_binary})
      refute valid_policy_verdict?({:quarantine, "reason"})

      refute valid_hit?(%{})
      refute valid_hit?(%{name: :aws_access_key})
      refute valid_hit?("aws_access_key")
    end
  end

  describe "behaviour contracts used by the reference consumer" do
    test "actor-pattern identity mapper implements the Identity behaviour shape" do
      context = %{actor: "host:operator:42"}

      assert ActorPatternIdentity.identity(context) == "host:operator:42"
      assert ActorPatternIdentity.trust_level(context) == :high
      assert ActorPatternIdentity.bindings(context) == ["actor:host:operator:42"]
      assert ActorPatternIdentity.trust_level(%{actor: "host:user:42"}) == :medium
      assert ActorPatternIdentity.trust_level(%{actor: "host:guest:42"}) == :low
    end

    test "request-signing signer implements the Signer behaviour shape" do
      signature = RequestSigningSigner.sign(@ed25519_message)

      assert byte_size(RequestSigningSigner.public_key()) == 32
      assert byte_size(signature) == 64
      assert Ed25519.verify(@ed25519_message, signature, RequestSigningSigner.public_key())
    end

    test "database-backed vault implements the Vault behaviour shape" do
      assert {:ok, id} = Vault.encrypt("secret-value", "api token", DatabaseBackedVault)

      assert DatabaseBackedVault.exists?(id)
      assert Vault.exists?(id, DatabaseBackedVault)
      assert Vault.decrypt(id, DatabaseBackedVault) == {:ok, "secret-value"}
      assert Vault.decrypt("vault:missing", DatabaseBackedVault) == {:error, :not_found}
    end
  end

  describe "Ed25519 golden vectors" do
    test "new/1 derives the byte-exact public key from the fixed seed" do
      signer = Ed25519.new(@ed25519_seed)

      assert signer.public_key == @ed25519_public_key
      assert signer.private_key == @ed25519_seed
    end

    test "sign_with/2 and verify/3 are byte-exact for the fixed vector" do
      signer = Ed25519.new(@ed25519_seed)

      assert Ed25519.sign_with(signer, @ed25519_message) == @ed25519_signature
      assert Ed25519.verify(@ed25519_message, @ed25519_signature, @ed25519_public_key)
      refute Ed25519.verify(@ed25519_message <> "!", @ed25519_signature, @ed25519_public_key)
    end
  end

  describe "Audit struct contract" do
    test "field set is asserted literally" do
      event = Audit.new_event("runtime.decision", "host:operator:42", "read_file", "success")

      fields =
        event
        |> Map.from_struct()
        |> Map.keys()
        |> Enum.sort()

      assert fields == @audit_fields
    end
  end

  defp valid_hit?(%{name: name}) when is_binary(name), do: true
  defp valid_hit?(_), do: false

  defp valid_policy_verdict?(:allowed), do: true
  defp valid_policy_verdict?(:blocked), do: true
  defp valid_policy_verdict?({:confirm, reason}) when is_binary(reason), do: true
  defp valid_policy_verdict?(_), do: false
end
