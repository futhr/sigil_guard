defmodule SigilGuard.TrustBundleTest do
  use ExUnit.Case, async: true

  alias SigilGuard.TrustBundle

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

      assert TrustBundle.load({:map, envelope}) == {:error, :invalid_envelope}

      assert TrustBundle.load({:binary, Jason.encode!(envelope)}) ==
               {:error, :invalid_envelope}

      assert TrustBundle.load(:none) == {:error, :invalid_source}
      assert TrustBundle.load({:binary, "not json"}) == {:error, :invalid_source}
      assert TrustBundle.load({:unknown, "source"}) == {:error, :invalid_source}
      assert TrustBundle.load({:map, "bad"}) == {:error, :invalid_source}
      assert TrustBundle.load({:file, "/definitely/missing"}) == {:error, :invalid_source}
      assert TrustBundle.load({:priv, :sigil_guard, "bundle.json"}) == {:error, :invalid_source}
      assert TrustBundle.load({:file, "/tmp/bundle.json"}, :bad_opts) == {:error, :invalid_source}
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
end
