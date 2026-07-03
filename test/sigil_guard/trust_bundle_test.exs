defmodule SigilGuard.TrustBundleTest do
  use ExUnit.Case, async: true

  alias __MODULE__.BundleSigner
  alias __MODULE__.RootSigner
  alias SigilGuard.Attestation.Envelope
  alias SigilGuard.Canonical.JCS
  alias SigilGuard.TrustBundle

  @now ~U[2026-07-03 12:00:00.000Z]

  describe "public API shell" do
    test "exposes the SP.02 struct fields and section accessors" do
      bundle = %TrustBundle{
        bundle_id: "example-org-trust",
        sequence: 1,
        root_version: 1,
        digest: String.duplicate("a", 64),
        document: %{
          "patterns" => [%{"id" => "pattern"}],
          "policies" => [%{"id" => "policy"}],
          "tools" => [%{"name" => "tool"}],
          "identity_issuers" => ["did:example:issuer"],
          "ignored" => "not a section"
        },
        envelope: %{"payload" => "encoded"},
        dev?: false,
        source: {:map, %{"payload" => "encoded"}}
      }

      assert TrustBundle.patterns(bundle) == [%{"id" => "pattern"}]
      assert TrustBundle.policies(bundle) == [%{"id" => "policy"}]
      assert TrustBundle.tools(bundle) == [%{"name" => "tool"}]
      assert TrustBundle.identity_issuers(bundle) == ["did:example:issuer"]
    end

    test "section accessors return empty lists for absent or non-list sections" do
      bundle = %TrustBundle{document: %{"patterns" => "bad"}}

      assert TrustBundle.patterns(bundle) == []
      assert TrustBundle.policies(bundle) == []
      assert TrustBundle.tools(bundle) == []
      assert TrustBundle.identity_issuers(bundle) == []
    end

    test "load source constructors route decoded envelopes to verification" do
      envelope = %{"payload" => "encoded"}

      assert TrustBundle.load({:map, envelope}, quarantine: false) == {:error, :invalid_envelope}

      assert TrustBundle.load({:binary, Jason.encode!(envelope)}, quarantine: false) ==
               {:error, :invalid_envelope}

      assert TrustBundle.load(:none, quarantine: false) == {:error, :invalid_source}

      assert TrustBundle.load({:binary, "not json"}, quarantine: false) ==
               {:error, :invalid_source}

      assert TrustBundle.load({:unknown, "source"}, quarantine: false) ==
               {:error, :invalid_source}

      assert TrustBundle.load({:map, "bad"}) == {:error, :invalid_source}

      assert TrustBundle.load({:file, "/definitely/missing"}, quarantine: false) ==
               {:error, :invalid_source}

      assert TrustBundle.load({:priv, :sigil_guard, "bundle.json"}, quarantine: false) ==
               {:error, :invalid_source}

      assert TrustBundle.load({:file, "/tmp/bundle.json"}, :bad_opts) == {:error, :invalid_source}
    end

    test "loads and verifies map, binary, file, and priv sources without opening ports" do
      envelope = envelope(bundle_document())
      encoded = Jason.encode!(envelope)

      file_path =
        Path.join(System.tmp_dir!(), "sigil_guard-trust-bundle-#{System.unique_integer()}.json")

      priv_rel = "test_trust_bundle/source-#{System.unique_integer()}/bundle.json"
      priv_path = Application.app_dir(:sigil_guard, Path.join("priv", priv_rel))

      on_exit(fn ->
        File.rm(file_path)
        File.rm_rf(Path.dirname(priv_path))
      end)

      File.mkdir_p!(Path.dirname(file_path))
      File.write!(file_path, encoded)
      File.mkdir_p!(Path.dirname(priv_path))
      File.write!(priv_path, encoded)

      before_ports = current_process_ports()

      assert {:ok, %TrustBundle{source: {:map, ^envelope}}} =
               TrustBundle.load({:map, envelope}, now: @now, quarantine: false)

      assert {:ok, %TrustBundle{source: {:binary, ^encoded}}} =
               TrustBundle.load({:binary, encoded}, now: @now, quarantine: false)

      assert {:ok, %TrustBundle{source: {:file, ^file_path}}} =
               TrustBundle.load({:file, file_path}, now: @now, quarantine: false)

      assert {:ok, %TrustBundle{source: {:priv, :sigil_guard, ^priv_rel}}} =
               TrustBundle.load({:priv, :sigil_guard, priv_rel}, now: @now, quarantine: false)

      assert {:ok, %TrustBundle{source: :none}} =
               TrustBundle.verify(envelope, now: @now, quarantine: false)

      assert current_process_ports() == before_ports
    end

    test "file and priv sources reject unreadable or non-json resources before verification" do
      file_path =
        Path.join(System.tmp_dir!(), "sigil_guard-not-json-#{System.unique_integer()}.json")

      priv_rel = "test_trust_bundle/not-json-#{System.unique_integer()}/bundle.json"
      priv_path = Application.app_dir(:sigil_guard, Path.join("priv", priv_rel))

      on_exit(fn ->
        File.rm(file_path)
        File.rm_rf(Path.dirname(priv_path))
      end)

      File.write!(file_path, "not json")
      File.mkdir_p!(Path.dirname(priv_path))
      File.write!(priv_path, "not json")

      assert TrustBundle.load({:file, file_path}, quarantine: false) == {:error, :invalid_source}

      assert TrustBundle.load({:priv, :sigil_guard, priv_rel}, quarantine: false) ==
               {:error, :invalid_source}

      assert TrustBundle.load({:priv, :missing_application, "bundle.json"}, quarantine: false) ==
               {:error, :invalid_source}
    end

    test "verify routes malformed envelopes through SP.01 errors and dev bundle fails closed" do
      assert TrustBundle.verify(%{"payload" => "encoded"}) == {:error, :invalid_envelope}
      assert TrustBundle.verify("bad") == {:error, :invalid_envelope}
      assert TrustBundle.verify(%{}, :bad_opts) == {:error, :invalid_bundle_format}

      assert TrustBundle.dev_bundle(seed: :crypto.strong_rand_bytes(32)) ==
               {:error, :invalid_bundle_format}

      assert TrustBundle.dev_bundle(:bad_opts) == {:error, :invalid_bundle_format}
    end
  end

  defp bundle_document do
    %{
      "profile" => "sigil_guard_trust_bundle/v1",
      "bundle_id" => "example-org-trust",
      "sequence" => "1",
      "issued_at" => "2026-07-03T11:00:00.000Z",
      "expires_at" => "2026-07-03T13:00:00.000Z",
      "roles" => %{
        "root" => %{
          "keyids" => [root_keyid()],
          "threshold" => 1,
          "version" => "1",
          "expires_at" => "2027-07-03T12:00:00.000Z"
        },
        "delegates" => [
          %{
            "name" => "bundle",
            "keyids" => [bundle_keyid()],
            "threshold" => 1,
            "expires_at" => "2026-07-03T14:00:00.000Z"
          }
        ]
      },
      "keys" => %{
        root_keyid() => key_descriptor(RootSigner),
        bundle_keyid() => key_descriptor(BundleSigner)
      },
      "rollback_floor" => "1"
    }
  end

  defp envelope(document) do
    {:ok, payload} = JCS.encode(document)
    {:ok, envelope} = Envelope.sign_many(payload, [BundleSigner])
    envelope
  end

  defp current_process_ports do
    owner = self()

    Port.list()
    |> Enum.filter(&(Port.info(&1, :connected) == {:connected, owner}))
    |> MapSet.new()
  end

  defp key_descriptor(signer) do
    %{
      "alg" => "ed25519",
      "public_key" => Base.url_encode64(signer.public_key(), padding: false)
    }
  end

  defp root_keyid, do: Envelope.keyid(RootSigner.public_key())
  defp bundle_keyid, do: Envelope.keyid(BundleSigner.public_key())

  defmodule RootSigner do
    @behaviour SigilGuard.Signer
    @seed :crypto.hash(:sha256, "trust-bundle-load-root")

    @impl SigilGuard.Signer
    def sign(message), do: :crypto.sign(:eddsa, :none, message, [private_key(), :ed25519])

    @impl SigilGuard.Signer
    def public_key do
      {public_key, _} = :crypto.generate_key(:eddsa, :ed25519, @seed)
      public_key
    end

    defp private_key do
      {_, private_key} = :crypto.generate_key(:eddsa, :ed25519, @seed)
      private_key
    end
  end

  defmodule BundleSigner do
    @behaviour SigilGuard.Signer
    @seed :crypto.hash(:sha256, "trust-bundle-load-delegate")

    @impl SigilGuard.Signer
    def sign(message), do: :crypto.sign(:eddsa, :none, message, [private_key(), :ed25519])

    @impl SigilGuard.Signer
    def public_key do
      {public_key, _} = :crypto.generate_key(:eddsa, :ed25519, @seed)
      public_key
    end

    defp private_key do
      {_, private_key} = :crypto.generate_key(:eddsa, :ed25519, @seed)
      private_key
    end
  end
end
