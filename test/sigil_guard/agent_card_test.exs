defmodule SigilGuard.AgentCardTest do
  use ExUnit.Case, async: true

  alias SigilGuard.AgentCard
  alias SigilGuard.AgentCardFixtureGenerator
  alias SigilGuard.AgentCardFixtureGenerator.IssuerSigner
  alias SigilGuard.Attestation.Envelope
  alias SigilGuard.Canonical.JCS
  alias SigilGuard.TrustBundle

  @fixture_root Path.expand("../fixtures/agent_cards", __DIR__)
  @now ~U[2026-07-15 12:00:00.000Z]

  setup_all do
    Code.ensure_loaded!(IssuerSigner)
    :ok
  end

  defp issuer_public_key, do: AgentCardFixtureGenerator.issuer_public_key()
  defp issuer_keyid, do: Envelope.keyid(issuer_public_key())
  defp issuer_material, do: %{issuer_keyid() => issuer_public_key()}

  defp valid_card do
    agent_pub = AgentCardFixtureGenerator.agent_public_key()

    %{
      "kind" => "sigil_guard_agent_card",
      "schema_version" => "1",
      "agent_id" => "spiffe://prod.example.org/agents/research-peer",
      "name" => "research-peer",
      "version" => "2.1.0",
      "provider" => "spiffe://prod.example.org/operators/platform-team",
      "endpoints" => ["https://agents.example.org/research-peer/a2a"],
      "capabilities" => [
        %{"description" => "Summarize a document set", "name" => "summarize"},
        %{"description" => "Web research with citations", "name" => "web_research"}
      ],
      "protocols" => ["a2a/1.0"],
      "public_keys" => [
        %{
          "algorithm" => "ed25519",
          "keyid" => Envelope.keyid(agent_pub),
          "public_key" => Base.url_encode64(agent_pub, padding: false)
        }
      ],
      "scopes" => ["research:read"],
      "trust_zone" => "semi_trusted",
      "issued_at" => "2026-07-02T12:00:00.000Z",
      "expires_at" => "2026-08-01T12:00:00.000Z"
    }
  end

  describe "new/1" do
    test "normalizes and accepts a valid card" do
      assert {:ok, card} = AgentCard.new(valid_card())
      assert card["kind"] == "sigil_guard_agent_card"
      assert Enum.map(card["capabilities"], & &1["name"]) == ["summarize", "web_research"]
    end

    test "accepts empty endpoints and omitted optional fields" do
      card =
        valid_card()
        |> Map.put("endpoints", [])
        |> Map.drop(["description", "scopes"])

      assert {:ok, _} = AgentCard.new(card)
    end

    test "rejects malformed cards with :invalid_agent_card" do
      agent_pub = AgentCardFixtureGenerator.agent_public_key()

      cases = [
        {"unknown field", Map.put(valid_card(), "extra", true)},
        {"missing required field", Map.delete(valid_card(), "agent_id")},
        {"wrong kind", Map.put(valid_card(), "kind", "other")},
        {"wrong schema_version", Map.put(valid_card(), "schema_version", "2")},
        {"bad trust_zone", Map.put(valid_card(), "trust_zone", "root")},
        {"empty name", Map.put(valid_card(), "name", "")},
        {"unsorted capabilities",
         Map.put(valid_card(), "capabilities", [
           %{"name" => "web_research"},
           %{"name" => "summarize"}
         ])},
        {"duplicate capability names",
         Map.put(valid_card(), "capabilities", [
           %{"name" => "summarize"},
           %{"name" => "summarize"}
         ])},
        {"empty capabilities", Map.put(valid_card(), "capabilities", [])},
        {"capability extra key",
         Map.put(valid_card(), "capabilities", [%{"name" => "a", "role" => "x"}])},
        {"unsorted protocols", Map.put(valid_card(), "protocols", ["b/1.0", "a/1.0"])},
        {"non-absolute endpoint", Map.put(valid_card(), "endpoints", ["not-a-uri"])},
        {"public key algorithm",
         Map.put(valid_card(), "public_keys", [
           %{
             "algorithm" => "rsa",
             "keyid" => Envelope.keyid(agent_pub),
             "public_key" => Base.url_encode64(agent_pub, padding: false)
           }
         ])},
        {"keyid derivation mismatch",
         Map.put(valid_card(), "public_keys", [
           %{
             "algorithm" => "ed25519",
             "keyid" => "sha256:" <> String.duplicate("0", 64),
             "public_key" => Base.url_encode64(agent_pub, padding: false)
           }
         ])},
        {"wrong-length public key",
         Map.put(valid_card(), "public_keys", [
           %{
             "algorithm" => "ed25519",
             "keyid" => Envelope.keyid(agent_pub),
             "public_key" => Base.url_encode64(<<1, 2, 3>>, padding: false)
           }
         ])},
        {"expires before issued",
         Map.put(valid_card(), "expires_at", "2026-07-01T12:00:00.000Z")},
        {"bad timestamp format", Map.put(valid_card(), "issued_at", "2026-07-02 12:00:00Z")},
        {"capability not a map", Map.put(valid_card(), "capabilities", ["summarize"])},
        {"public key not a map", Map.put(valid_card(), "public_keys", ["key"])},
        {"non-binary endpoint", Map.put(valid_card(), "endpoints", [123])},
        {"empty description", Map.put(valid_card(), "description", "")},
        {"endpoints not a list", Map.put(valid_card(), "endpoints", "one")},
        {"protocols not a list", Map.put(valid_card(), "protocols", "a2a/1.0")},
        {"public_keys not a list", Map.put(valid_card(), "public_keys", "key")},
        {"scopes not a list", Map.put(valid_card(), "scopes", "research:read")},
        {"unsorted scopes", Map.put(valid_card(), "scopes", ["b", "a"])}
      ]

      for {label, card} <- cases do
        assert AgentCard.new(card) == {:error, :invalid_agent_card}, label
      end
    end

    test "rejects non-map input" do
      assert AgentCard.new("card") == {:error, :invalid_agent_card}
    end
  end

  describe "digest/1" do
    test "is deterministic over the normalized card" do
      assert {:ok, digest} = AgentCard.digest(valid_card())
      assert digest =~ ~r/^[0-9a-f]{64}$/
      assert {:ok, ^digest} = AgentCard.digest(valid_card())
    end

    test "rejects an invalid card" do
      assert AgentCard.digest(Map.delete(valid_card(), "agent_id")) ==
               {:error, :invalid_agent_card}
    end
  end

  describe "sign/verify round trip" do
    test "signs and verifies against the issuer key map" do
      assert {:ok, envelope} = AgentCard.sign(valid_card(), IssuerSigner)
      assert {:ok, card} = AgentCard.verify(envelope, issuer_material(), now: @now)
      assert card["agent_id"] == "spiffe://prod.example.org/agents/research-peer"
    end

    test "verify without trust material fails :missing_trust_bundle" do
      {:ok, envelope} = AgentCard.sign(valid_card(), IssuerSigner)
      assert AgentCard.verify(envelope, %{}, now: @now) == {:error, :missing_trust_bundle}
    end

    test "verify uses the current time when :now is omitted" do
      {:ok, envelope} = AgentCard.sign(valid_card(), IssuerSigner)
      assert {:ok, _} = AgentCard.verify(envelope, issuer_material())
    end
  end

  describe "golden vector" do
    test "committed fixtures regenerate byte-identically" do
      tmp = Path.join(System.tmp_dir!(), "sigil-agent-card-#{System.unique_integer([:positive])}")

      try do
        AgentCardFixtureGenerator.write!(tmp)

        for dir <- AgentCardFixtureGenerator.fixtures(),
            file <- ~w(card.json envelope.json expected.json) do
          committed = Path.join([@fixture_root, dir, file])
          regenerated = Path.join([tmp, dir, file])
          assert File.read!(regenerated) == File.read!(committed), "#{dir}/#{file}"
        end
      after
        File.rm_rf!(tmp)
      end
    end

    test "envelope verifies and matches the recorded digest and signature" do
      card_json = read_fixture("card.json")
      envelope = read_json("envelope.json")
      expected = read_json("expected.json")

      assert {:ok, ^card_json} = JCS.encode(Jason.decode!(card_json))
      assert sha256_hex(card_json) == expected["card_digest"]

      assert sha256_hex(Envelope.pae(Envelope.payload_type(), card_json)) ==
               expected["pae_sha256"]

      assert envelope["signatures"] == [
               %{"keyid" => expected["issuer_keyid"], "sig" => expected["signature"]}
             ]

      material = %{expected["issuer_keyid"] => issuer_public_key()}
      assert {:ok, card} = AgentCard.verify(envelope, material, now: @now)
      assert {:ok, digest} = AgentCard.digest(card)
      assert digest == expected["card_digest"]
    end
  end

  describe "tamper" do
    test "flipped payload byte fails :invalid_signature" do
      {:ok, envelope} = AgentCard.sign(valid_card(), IssuerSigner)
      tampered = Map.put(envelope, "payload", flip_first_byte(envelope["payload"]))

      assert AgentCard.verify(tampered, issuer_material(), now: @now) ==
               {:error, :invalid_signature}
    end

    test "non-canonical payload bytes fail :invalid_agent_card" do
      {:ok, card} = AgentCard.new(valid_card())
      {:ok, canonical} = JCS.encode(card)
      noncanonical = "  " <> canonical
      {:ok, envelope} = Envelope.sign(noncanonical, IssuerSigner)

      assert AgentCard.verify(envelope, issuer_material(), now: @now) ==
               {:error, :invalid_agent_card}
    end
  end

  describe "freshness" do
    setup do
      {:ok, envelope} = AgentCard.sign(valid_card(), IssuerSigner)
      %{envelope: envelope}
    end

    test "an expired card fails :card_expired past the skew boundary", %{envelope: envelope} do
      # expires_at 2026-08-01T12:00:00Z; skew 1000 ms.
      just_expired = ~U[2026-08-01 12:00:01.001Z]
      within_skew = ~U[2026-08-01 12:00:00.999Z]

      assert AgentCard.verify(envelope, issuer_material(), now: just_expired, max_skew_ms: 1000) ==
               {:error, :card_expired}

      assert {:ok, _} =
               AgentCard.verify(envelope, issuer_material(), now: within_skew, max_skew_ms: 1000)
    end

    test "a future-dated card fails :card_expired", %{envelope: envelope} do
      before_issue = ~U[2026-07-02 11:58:00.000Z]

      assert AgentCard.verify(envelope, issuer_material(), now: before_issue, max_skew_ms: 1000) ==
               {:error, :card_expired}
    end
  end

  describe "trust-bundle issuer resolution" do
    setup do
      {:ok, envelope} = AgentCard.sign(valid_card(), IssuerSigner)
      %{envelope: envelope}
    end

    test "resolves a keyid in the agent_card role", %{envelope: envelope} do
      bundle = bundle_with_role([issuer_keyid()], keys: %{issuer_keyid() => issuer_public_key()})
      assert {:ok, _} = AgentCard.verify(envelope, bundle, now: @now)
    end

    test "a resolvable non-issuer key fails :untrusted_issuer", %{envelope: envelope} do
      other =
        :binary.copy(<<0x09>>, 32) |> then(&elem(:crypto.generate_key(:eddsa, :ed25519, &1), 0))

      other_keyid = Envelope.keyid(other)

      bundle =
        bundle_with_role([other_keyid],
          keys: %{issuer_keyid() => issuer_public_key(), other_keyid => other}
        )

      assert AgentCard.verify(envelope, bundle, now: @now) == {:error, :untrusted_issuer}
    end

    test "an undeclared key fails :unknown_key_id", %{envelope: envelope} do
      other =
        :binary.copy(<<0x09>>, 32) |> then(&elem(:crypto.generate_key(:eddsa, :ed25519, &1), 0))

      other_keyid = Envelope.keyid(other)
      bundle = bundle_with_role([other_keyid], keys: %{other_keyid => other})

      assert AgentCard.verify(envelope, bundle, now: @now) == {:error, :unknown_key_id}
    end

    test "a bundle without a keys map fails :unknown_key_id", %{envelope: envelope} do
      document = %{
        "roles" => %{"delegates" => [%{"name" => "agent_card", "keyids" => [issuer_keyid()]}]}
      }

      assert AgentCard.verify(envelope, %TrustBundle{document: document}, now: @now) ==
               {:error, :unknown_key_id}
    end

    test "a bundle without delegates fails :untrusted_issuer", %{envelope: envelope} do
      document = %{
        "keys" => %{
          issuer_keyid() => %{
            "alg" => "ed25519",
            "public_key" => Base.url_encode64(issuer_public_key(), padding: false)
          }
        },
        "roles" => %{}
      }

      assert AgentCard.verify(envelope, %TrustBundle{document: document}, now: @now) ==
               {:error, :untrusted_issuer}
    end
  end

  describe "issuer key map" do
    test "an unknown keyid fails :unknown_key_id" do
      {:ok, envelope} = AgentCard.sign(valid_card(), IssuerSigner)
      material = %{("sha256:" <> String.duplicate("0", 64)) => issuer_public_key()}
      assert AgentCard.verify(envelope, material, now: @now) == {:error, :unknown_key_id}
    end

    test "a bundle without an agent_card role fails :untrusted_issuer" do
      {:ok, envelope} = AgentCard.sign(valid_card(), IssuerSigner)

      document = %{
        "keys" => %{
          issuer_keyid() => %{
            "alg" => "ed25519",
            "public_key" => Base.url_encode64(issuer_public_key(), padding: false)
          }
        },
        "roles" => %{"delegates" => [%{"name" => "bundle", "keyids" => [issuer_keyid()]}]}
      }

      assert AgentCard.verify(envelope, %TrustBundle{document: document}, now: @now) ==
               {:error, :untrusted_issuer}
    end

    test "non-map trust material fails :missing_trust_bundle" do
      {:ok, envelope} = AgentCard.sign(valid_card(), IssuerSigner)
      assert AgentCard.verify(envelope, :nope, now: @now) == {:error, :missing_trust_bundle}
    end

    test "a bundle key descriptor without a public key is ignored" do
      {:ok, envelope} = AgentCard.sign(valid_card(), IssuerSigner)

      document = %{
        "keys" => %{issuer_keyid() => %{"alg" => "ed25519"}},
        "roles" => %{"delegates" => [%{"name" => "agent_card", "keyids" => [issuer_keyid()]}]}
      }

      assert AgentCard.verify(envelope, %TrustBundle{document: document}, now: @now) ==
               {:error, :untrusted_issuer}
    end

    test "an agent_card role with non-list keyids resolves to no issuers" do
      {:ok, envelope} = AgentCard.sign(valid_card(), IssuerSigner)

      document = %{
        "keys" => %{
          issuer_keyid() => %{
            "alg" => "ed25519",
            "public_key" => Base.url_encode64(issuer_public_key(), padding: false)
          }
        },
        "roles" => %{"delegates" => [%{"name" => "agent_card", "keyids" => "nope"}]}
      }

      assert AgentCard.verify(envelope, %TrustBundle{document: document}, now: @now) ==
               {:error, :untrusted_issuer}
    end

    test "a non-JSON payload fails :invalid_agent_card" do
      {:ok, envelope} = Envelope.sign("not json {", IssuerSigner)

      assert AgentCard.verify(envelope, issuer_material(), now: @now) ==
               {:error, :invalid_agent_card}
    end
  end

  describe "input guards" do
    test "digest and sign reject non-map and bad signers" do
      assert AgentCard.digest("card") == {:error, :invalid_agent_card}
      assert AgentCard.sign("card", IssuerSigner) == {:error, :invalid_agent_card}
      assert AgentCard.sign(valid_card(), "signer") == {:error, :invalid_agent_card}
    end

    test "verify rejects a non-envelope and non-list opts" do
      assert AgentCard.verify("env", issuer_material(), now: @now) == {:error, :invalid_envelope}
      assert AgentCard.verify(%{}, issuer_material(), :bad) == {:error, :invalid_agent_card}
    end

    test "verify rejects an invalid :now and :max_skew_ms" do
      {:ok, envelope} = AgentCard.sign(valid_card(), IssuerSigner)

      assert AgentCard.verify(envelope, issuer_material(), now: :bad) ==
               {:error, :invalid_agent_card}

      assert AgentCard.verify(envelope, issuer_material(), now: @now, max_skew_ms: -1) ==
               {:error, :invalid_agent_card}
    end

    test "rejects a capability with an empty description" do
      card = Map.put(valid_card(), "capabilities", [%{"name" => "a", "description" => ""}])
      assert AgentCard.new(card) == {:error, :invalid_agent_card}
    end
  end

  describe "JWS-to-DSSE parity (M3.22)" do
    test "one keypair signs the JWS and DSSE forms; each verifies under its own verifier" do
      {:ok, card} = AgentCard.new(valid_card())
      {:ok, card_json} = JCS.encode(card)

      # DSSE form.
      {:ok, dsse} = AgentCard.sign(card, IssuerSigner)
      assert {:ok, ^card} = AgentCard.verify(dsse, issuer_material(), now: @now)
      [%{"keyid" => dsse_keyid}] = dsse["signatures"]
      assert dsse_keyid == issuer_keyid()

      # RFC 7515 Ed25519-JWS form, same keypair.
      header = %{"alg" => "EdDSA", "kid" => issuer_keyid()}
      header_b64 = Base.url_encode64(Jason.encode!(header), padding: false)
      payload_b64 = Base.url_encode64(card_json, padding: false)
      signing_input = header_b64 <> "." <> payload_b64
      jws_sig = IssuerSigner.sign(signing_input)

      assert :crypto.verify(:eddsa, :none, signing_input, jws_sig, [issuer_public_key(), :ed25519])

      # The DSSE signature is over PAE, the JWS signature over the JWS signing
      # input: distinct pre-images, same key, per the mapping table.
      [%{"sig" => dsse_sig_b64}] = dsse["signatures"]
      dsse_sig = Base.url_decode64!(dsse_sig_b64, padding: false)
      pae = Envelope.pae(Envelope.payload_type(), card_json)
      assert :crypto.verify(:eddsa, :none, pae, dsse_sig, [issuer_public_key(), :ed25519])
      refute dsse_sig == jws_sig
    end
  end

  defp bundle_with_role(role_keyids, keys: keys) do
    document = %{
      "keys" =>
        Map.new(keys, fn {keyid, public_key} ->
          {keyid,
           %{"alg" => "ed25519", "public_key" => Base.url_encode64(public_key, padding: false)}}
        end),
      "roles" => %{
        "delegates" => [%{"name" => "agent_card", "keyids" => role_keyids}]
      }
    }

    %TrustBundle{document: document}
  end

  defp read_fixture(name), do: File.read!(Path.join([@fixture_root, "research_peer", name]))
  defp read_json(name), do: Jason.decode!(read_fixture(name))

  defp flip_first_byte(payload) do
    <<first, rest::binary>> = Base.url_decode64!(payload, padding: false)
    Base.url_encode64(<<Bitwise.bxor(first, 1), rest::binary>>, padding: false)
  end

  defp sha256_hex(bytes), do: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)
end
