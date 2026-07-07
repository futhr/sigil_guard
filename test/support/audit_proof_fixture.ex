defmodule SigilGuard.AuditProofFixture do
  @moduledoc false

  # Deterministic golden vectors for audit inclusion proofs (SP.05). All inputs
  # are fixed, so `write!/0` regenerates byte-identical fixtures and a test can
  # assert stability. See SP.05 "Golden Vector: Five-Event Tree".

  alias SigilGuard.Audit
  alias SigilGuard.Audit.Checkpoint
  alias SigilGuard.Audit.Export
  alias SigilGuard.Audit.Proof
  alias SigilGuard.Canonical.JCS

  @root SigilGuard.FixturePath.path("audit_proofs")
  @key "sigil-guard-audit-proof-test-key"
  @issuer "did:web:test.example.org"
  @generated_at "2026-07-02T12:00:05.000Z"
  @count 5

  defmodule SeedSigner do
    @moduledoc false

    @behaviour SigilGuard.Signer
    @seed Base.decode16!("0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20")

    @impl SigilGuard.Signer
    def sign(message) do
      {_, private_key} = keypair()
      :crypto.sign(:eddsa, :none, message, [private_key, :ed25519])
    end

    @impl SigilGuard.Signer
    def public_key do
      {public_key, _} = keypair()
      public_key
    end

    defp keypair, do: :crypto.generate_key(:eddsa, :ed25519, @seed)
  end

  @doc false
  @spec signer() :: module()
  def signer, do: SeedSigner

  @doc false
  @spec signed_events() :: [Audit.t()]
  def signed_events do
    {events, _} =
      Enum.reduce(0..(@count - 1), {[], nil}, fn i, {acc, prev} ->
        signed = Audit.sign_event(event(i), @key, prev)
        {[signed | acc], signed.hmac}
      end)

    Enum.reverse(events)
  end

  @doc false
  @spec root(pos_integer()) :: String.t()
  def root(size) do
    {:ok, root} = Checkpoint.merkle_root(Enum.take(signed_events(), size))
    root
  end

  @doc false
  @spec inclusion_proofs() :: [map()]
  def inclusion_proofs do
    events = signed_events()
    Enum.map(0..(@count - 1), fn i -> elem(Proof.inclusion(events, i), 1) end)
  end

  @doc false
  @spec consistency_proof(pos_integer()) :: map()
  def consistency_proof(first_size) do
    elem(Proof.consistency(signed_events(), first_size), 1)
  end

  @doc false
  @spec checkpoint() :: map()
  def checkpoint do
    {:ok, unsigned} = Checkpoint.create(signed_events(), generated_at: @generated_at)
    Checkpoint.sign(unsigned, SeedSigner, issuer: @issuer, issued_at: @generated_at)
  end

  @doc false
  @spec statement() :: map()
  def statement do
    {:ok, statement} = Checkpoint.to_statement(checkpoint())
    statement
  end

  @doc false
  @spec export() :: map()
  def export do
    {:ok, export} =
      Export.create(signed_events(),
        generated_at: @generated_at,
        signer: SeedSigner,
        issuer: @issuer,
        issued_at: @generated_at,
        checkpoint_statement: true,
        inclusion_proofs: :all,
        consistency_proof: 3
      )

    export
  end

  # -- Fixture files ----------------------------------------------------------

  @doc false
  @spec write!() :: :ok
  def write! do
    File.mkdir_p!(@root)
    File.write!(path("events.json"), events_json())
    File.write!(path("tree.json"), tree_json())
    File.write!(path("inclusion_5.json"), inclusion_json())
    File.write!(path("consistency_3_5.json"), consistency_json(3))
    File.write!(path("consistency_4_5.json"), consistency_json(4))
    File.write!(path("checkpoint_5.json"), checkpoint_json())
    File.write!(path("expected.json"), expected_json())
    File.write!(path("export.json"), export_json())
    :ok
  end

  @doc false
  @spec path(String.t()) :: Path.t()
  def path(name), do: Path.join(@root, name)

  @doc false
  @spec events_json() :: binary()
  def events_json, do: encode(%{"events" => Enum.map(signed_events(), &event_map/1)})

  @doc false
  @spec tree_json() :: binary()
  def tree_json do
    events = signed_events()
    {:ok, leaves} = Checkpoint.leaf_hashes(events)
    [h0, h1, h2, h3, h4] = leaves
    n01 = Checkpoint.node_hash(h0, h1)
    n23 = Checkpoint.node_hash(h2, h3)
    n0123 = Checkpoint.node_hash(n01, n23)

    encode(%{
      "leaves" => Enum.map(leaves, &hex/1),
      "nodes" => %{"N01" => hex(n01), "N23" => hex(n23), "N0123" => hex(n0123), "H4" => hex(h4)},
      "roots" => Map.new(1..@count, fn size -> {Integer.to_string(size), root(size)} end)
    })
  end

  @doc false
  @spec inclusion_json() :: binary()
  def inclusion_json, do: encode(%{"proofs" => inclusion_proofs()})

  @doc false
  @spec consistency_json(pos_integer()) :: binary()
  def consistency_json(first_size), do: encode(consistency_proof(first_size))

  @doc false
  @spec checkpoint_json() :: binary()
  def checkpoint_json, do: encode(checkpoint())

  @doc false
  @spec expected_json() :: binary()
  def expected_json, do: encode(%{"checkpoint_statement" => statement()})

  @doc false
  @spec export_json() :: binary()
  def export_json, do: encode(export())

  # -- Helpers ----------------------------------------------------------------

  defp event(index) do
    %Audit{
      id: String.downcase(String.pad_leading(Integer.to_string(index + 1, 16), 32, "0")),
      type: "runtime.gate",
      actor: "spiffe://test.example.org/agents/proof-vector",
      action: "proof_vector",
      result: "allow",
      timestamp: "2026-07-02T12:00:0#{index}.000Z"
    }
  end

  defp event_map(%Audit{} = event) do
    %{
      "id" => event.id,
      "type" => event.type,
      "actor" => event.actor,
      "action" => event.action,
      "result" => event.result,
      "timestamp" => event.timestamp,
      "prev_hmac" => event.prev_hmac,
      "hmac" => event.hmac
    }
  end

  defp encode(map) do
    {:ok, encoded} = JCS.encode(map)
    encoded
  end

  defp hex(binary), do: Base.encode16(binary, case: :lower)
end
