defmodule SigilGuard.TrustBundleTest do
  @moduledoc false

  use ExUnit.Case, async: false

  alias __MODULE__.BundleSigner
  alias __MODULE__.RootSigner
  alias SigilGuard.Attestation.Envelope
  alias SigilGuard.Canonical.JCS
  alias SigilGuard.TrustBundle
  alias SigilGuard.TrustBundle.Cache

  @now ~U[2026-07-03 12:00:00.000Z]

  doctest SigilGuard.TrustBundle

  setup do
    Cache.clear()

    on_exit(fn -> Cache.clear() end)
  end

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

    test "pattern_sets/1 resolves the verified patterns section into SP.04 sets" do
      bundle = %TrustBundle{
        document: %{
          "patterns" => [
            %{"set" => "injection", "name" => "inj", "regex" => "danger"}
          ]
        }
      }

      assert {:ok, sets} = TrustBundle.pattern_sets(bundle)
      assert Enum.map(sets.injection, & &1.id) == ["inj"]
      # secret and poisoning stay at their built-in defaults.
      assert length(sets.secret) == 6
      assert Enum.map(sets.poisoning, & &1.id) == [:tool_poisoning_directive]
    end

    test "pattern_sets/1 on an absent section yields all built-in defaults" do
      assert {:ok, sets} = TrustBundle.pattern_sets(%TrustBundle{document: %{}})
      built_in = SigilGuard.PatternSets.built_in()
      assert Enum.map(sets.secret, & &1.name) == Enum.map(built_in.secret, & &1.name)
      assert Enum.map(sets.injection, & &1.id) == Enum.map(built_in.injection, & &1.id)
      assert Enum.map(sets.poisoning, & &1.id) == Enum.map(built_in.poisoning, & &1.id)
    end

    test "pattern_sets/1 fails closed on a legacy entry without a set" do
      bundle = %TrustBundle{document: %{"patterns" => [%{"name" => "x", "regex" => "a"}]}}
      assert TrustBundle.pattern_sets(bundle) == {:error, :invalid_pattern_set}
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

      {priv_rel, priv_path, priv_root} = priv_bundle_fixture_path("source")

      on_exit(fn ->
        File.rm(file_path)
        File.rm_rf!(priv_root)
      end)

      File.mkdir_p!(Path.dirname(file_path))
      File.write!(file_path, encoded)
      File.mkdir_p!(Path.dirname(priv_path))
      File.write!(priv_path, encoded)

      before_ports = current_process_ports()

      assert {:ok, %TrustBundle{source: {:map, ^envelope}}} =
               TrustBundle.load({:map, envelope}, now: @now, quarantine: false, cache: false)

      assert {:ok, %TrustBundle{source: {:binary, ^encoded}}} =
               TrustBundle.load({:binary, encoded}, now: @now, quarantine: false, cache: false)

      assert {:ok, %TrustBundle{source: {:file, ^file_path}}} =
               TrustBundle.load({:file, file_path}, now: @now, quarantine: false, cache: false)

      assert {:ok, %TrustBundle{source: {:priv, :sigil_guard, ^priv_rel}}} =
               TrustBundle.load({:priv, :sigil_guard, priv_rel},
                 now: @now,
                 quarantine: false,
                 cache: false
               )

      assert {:ok, %TrustBundle{source: :none}} =
               TrustBundle.verify(envelope, now: @now, quarantine: false)

      assert current_process_ports() == before_ports
    end

    test "file and priv sources reject unreadable or non-json resources before verification" do
      file_path =
        Path.join(System.tmp_dir!(), "sigil_guard-not-json-#{System.unique_integer()}.json")

      {priv_rel, priv_path, priv_root} = priv_bundle_fixture_path("not-json")

      on_exit(fn ->
        File.rm(file_path)
        File.rm_rf!(priv_root)
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

    test "verify routes malformed envelopes through SP.01 errors" do
      assert TrustBundle.verify(%{"payload" => "encoded"}) == {:error, :invalid_envelope}
      assert TrustBundle.verify("bad") == {:error, :invalid_envelope}
      assert TrustBundle.verify(%{}, :bad_opts) == {:error, :invalid_bundle_format}
    end

    test "dev_bundle builds, verifies, caches, and marks a development bundle" do
      seed = :binary.copy(<<0x42>>, 32)

      assert {:ok, bundle} =
               TrustBundle.dev_bundle(
                 seed: seed,
                 now: @now,
                 ttl_ms: 60_000,
                 patterns: [%{"id" => "dev-pattern"}],
                 policies: [%{"id" => "dev-policy"}],
                 tools: [%{"name" => "dev-tool"}],
                 identity_issuers: ["did:example:dev"]
               )

      assert %TrustBundle{
               bundle_id: "sigilguard-dev",
               sequence: 1,
               root_version: 1,
               dev?: true,
               source: :dev
             } = bundle

      assert bundle.document["provenance"] == %{
               "builder" => "SigilGuard.TrustBundle.dev_bundle/1",
               "issuer_class" => "dev"
             }

      assert bundle.document["issued_at"] == "2026-07-03T12:00:00.000Z"
      assert bundle.document["expires_at"] == "2026-07-03T12:01:00.000Z"
      assert TrustBundle.patterns(bundle) == [%{"id" => "dev-pattern"}]
      assert TrustBundle.policies(bundle) == [%{"id" => "dev-policy"}]
      assert TrustBundle.tools(bundle) == [%{"name" => "dev-tool"}]
      assert TrustBundle.identity_issuers(bundle) == ["did:example:dev"]

      assert {:ok, ^bundle} = Cache.get("sigilguard-dev")
    end

    test "dev_bundle supports deterministic seeds and expires at ttl_ms" do
      seed = :binary.copy(<<0x43>>, 32)

      assert {:ok, first} = TrustBundle.dev_bundle(seed: seed, now: @now, cache: false)
      assert {:ok, second} = TrustBundle.dev_bundle(seed: seed, now: @now, cache: false)
      assert first.digest == second.digest
      assert first.envelope == second.envelope

      assert {:ok, expired} =
               TrustBundle.dev_bundle(seed: seed, now: @now, ttl_ms: 1_000, cache: false)

      assert TrustBundle.verify(expired.envelope,
               now: DateTime.add(@now, 1_001, :millisecond),
               max_skew_ms: 0,
               quarantine: false
             ) == {:error, :bundle_expired}
    end

    test "dev_bundle rejects malformed bootstrap options" do
      assert TrustBundle.dev_bundle(:bad_opts) == {:error, :invalid_bundle_format}
      assert TrustBundle.dev_bundle(seed: "short") == {:error, :invalid_bundle_format}
      assert TrustBundle.dev_bundle(now: "bad") == {:error, :invalid_bundle_format}
      assert TrustBundle.dev_bundle(ttl_ms: 0) == {:error, :invalid_bundle_format}
      assert TrustBundle.dev_bundle(patterns: "bad") == {:error, :invalid_bundle_format}
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

  test "load rejects a non-keyword option list without raising" do
    assert TrustBundle.load({:map, %{}}, [{:now}]) == {:error, :invalid_source}
  end

  defp current_process_ports do
    owner = self()

    Port.list()
    |> Enum.filter(&(Port.info(&1, :connected) == {:connected, owner}))
    |> MapSet.new()
  end

  defp priv_bundle_fixture_path(name) do
    root = "test_trust_bundle_#{System.unique_integer([:positive])}"
    rel_path = Path.join([root, name, "bundle.json"])

    {
      rel_path,
      Application.app_dir(:sigil_guard, Path.join("priv", rel_path)),
      Application.app_dir(:sigil_guard, Path.join("priv", root))
    }
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
