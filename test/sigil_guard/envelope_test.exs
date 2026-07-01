defmodule SigilGuard.RustGoldenVectorSigner do
  @moduledoc false

  @behaviour SigilGuard.Signer

  @seed :binary.copy(<<0x2A>>, 32)

  @impl SigilGuard.Signer
  def sign(message), do: :crypto.sign(:eddsa, :none, message, [@seed, :ed25519])

  @impl SigilGuard.Signer
  def public_key do
    {public_key, _} = :crypto.generate_key(:eddsa, :ed25519, @seed)
    public_key
  end
end

defmodule SigilGuard.EnvelopeTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Envelope
  alias SigilGuard.RustGoldenVectorSigner
  alias SigilGuard.TestSigner

  @rust_vectors_path Path.expand(
                       "../fixtures/envelope_golden_vectors.sigil_protocol_0_1_5.json",
                       __DIR__
                     )

  @external_resource @rust_vectors_path

  describe "canonical_bytes/4" do
    test "produces deterministic JSON with lexicographic key order" do
      bytes =
        Envelope.canonical_bytes(
          "did:sigil:alice",
          :allowed,
          "2024-01-01T00:00:00.000Z",
          "abcd1234"
        )

      assert bytes ==
               ~s({"identity":"did:sigil:alice","nonce":"abcd1234","timestamp":"2024-01-01T00:00:00.000Z","verdict":"allowed"})
    end

    test "keys are in strict lexicographic order" do
      bytes = Envelope.canonical_bytes("x", :blocked, "t", "n")
      decoded = Jason.decode!(bytes)
      keys = Map.keys(decoded)

      assert keys == Enum.sort(keys)
    end

    test "excludes signature and reason fields" do
      bytes = Envelope.canonical_bytes("id", :scanned, "ts", "nc")
      decoded = Jason.decode!(bytes)

      refute Map.has_key?(decoded, "signature")
      refute Map.has_key?(decoded, "reason")
    end

    test "formats verdict atoms as lowercase strings in canonical bytes" do
      for {atom, string} <- [{:allowed, "allowed"}, {:blocked, "blocked"}, {:scanned, "scanned"}] do
        bytes = Envelope.canonical_bytes("id", atom, "ts", "nc")
        decoded = Jason.decode!(bytes)
        assert decoded["verdict"] == string
      end
    end
  end

  describe "sign/3" do
    test "produces a valid envelope map" do
      envelope =
        Envelope.sign("did:sigil:test", :allowed,
          signer: TestSigner,
          timestamp: "2024-01-01T00:00:00.000Z",
          nonce: "deadbeef"
        )

      assert envelope["identity"] == "did:sigil:test"
      assert envelope["verdict"] == "allowed"
      assert envelope["timestamp"] == "2024-01-01T00:00:00.000Z"
      assert envelope["nonce"] == "deadbeef"
      assert is_binary(envelope["signature"])
    end

    test "can emit legacy title-cased verdicts by profile" do
      envelope =
        Envelope.sign("did:sigil:test", :allowed,
          signer: TestSigner,
          profile: :legacy_sigil_guard,
          timestamp: "2024-01-01T00:00:00.000Z",
          nonce: "deadbeef"
        )

      assert envelope["verdict"] == "Allowed"
      assert :ok = Envelope.verify(envelope, TestSigner.public_key_b64u())
    end

    test "includes reason when provided" do
      envelope =
        Envelope.sign("did:sigil:test", :blocked,
          signer: TestSigner,
          reason: "sensitivity hit detected"
        )

      assert envelope["reason"] == "sensitivity hit detected"
    end

    test "requires a reason for blocked envelopes" do
      assert_raise ArgumentError, ~r/blocked envelopes require a reason/, fn ->
        Envelope.sign("did:sigil:test", :blocked, signer: TestSigner)
      end
    end

    test "validates signer-facing arguments" do
      assert_raise ArgumentError, ~r/identity must be a string/, fn ->
        Envelope.sign(:not_a_string, :allowed, signer: TestSigner)
      end

      assert_raise ArgumentError, ~r/invalid envelope verdict/, fn ->
        bad_verdict = String.to_existing_atom("Elixir")
        Envelope.sign("did:sigil:test", bad_verdict, signer: TestSigner)
      end

      assert_raise ArgumentError, ~r/invalid wire_verdict_format :upper/, fn ->
        Envelope.sign("did:sigil:test", :allowed,
          signer: TestSigner,
          wire_verdict_format: :upper
        )
      end
    end

    test "excludes reason when not provided" do
      envelope = Envelope.sign("did:sigil:test", :allowed, signer: TestSigner)

      refute Map.has_key?(envelope, "reason")
    end

    test "signature is base64url-encoded without padding" do
      envelope = Envelope.sign("did:sigil:test", :allowed, signer: TestSigner)
      signature = envelope["signature"]

      refute String.contains?(signature, "=")
      refute String.contains?(signature, "+")
      refute String.contains?(signature, "/")
      assert {:ok, _} = Base.url_decode64(signature, padding: false)
    end

    test "generates timestamp and nonce when not provided" do
      envelope = Envelope.sign("did:sigil:test", :allowed, signer: TestSigner)

      assert String.ends_with?(envelope["timestamp"], "Z")
      assert byte_size(envelope["nonce"]) == 32
    end
  end

  describe "verify/2" do
    test "verifies a valid signature" do
      envelope =
        Envelope.sign("did:sigil:test", :allowed,
          signer: TestSigner,
          timestamp: "2024-06-15T10:30:00.000Z",
          nonce: "aabbccdd11223344"
        )

      assert :ok = Envelope.verify(envelope, TestSigner.public_key_b64u())
    end

    test "rejects tampered identity" do
      envelope =
        Envelope.sign("did:sigil:test", :allowed,
          signer: TestSigner,
          timestamp: "2024-06-15T10:30:00.000Z",
          nonce: "aabbccdd11223344"
        )

      tampered = Map.put(envelope, "identity", "did:sigil:evil")

      assert {:error, :invalid_signature} =
               Envelope.verify(tampered, TestSigner.public_key_b64u())
    end

    test "rejects tampered verdict" do
      envelope =
        Envelope.sign("did:sigil:test", :allowed,
          signer: TestSigner,
          timestamp: "2024-06-15T10:30:00.000Z",
          nonce: "aabbccdd11223344"
        )

      tampered = Map.put(envelope, "verdict", "Blocked")

      assert {:error, :invalid_signature} =
               Envelope.verify(tampered, TestSigner.public_key_b64u())
    end

    test "rejects tampered timestamp" do
      envelope =
        Envelope.sign("did:sigil:test", :allowed,
          signer: TestSigner,
          timestamp: "2024-06-15T10:30:00.000Z",
          nonce: "aabbccdd11223344"
        )

      tampered = Map.put(envelope, "timestamp", "2025-01-01T00:00:00.000Z")

      assert {:error, :invalid_signature} =
               Envelope.verify(tampered, TestSigner.public_key_b64u())
    end

    test "rejects wrong public key" do
      envelope = Envelope.sign("did:sigil:test", :allowed, signer: TestSigner)

      {other_pub, _} = :crypto.generate_key(:eddsa, :ed25519)
      other_b64u = Base.url_encode64(other_pub, padding: false)

      assert {:error, :invalid_signature} = Envelope.verify(envelope, other_b64u)
    end

    test "returns error for invalid base64 key" do
      envelope = Envelope.sign("did:sigil:test", :allowed, signer: TestSigner)

      assert {:error, :invalid_base64} = Envelope.verify(envelope, "not-valid-base64!!!")
    end

    test "returns error for invalid base64 in signature" do
      envelope =
        Envelope.sign("did:sigil:test", :allowed,
          signer: TestSigner,
          timestamp: "2024-06-15T10:30:00.000Z",
          nonce: "aabbccdd11223344"
        )

      bad_sig = Map.put(envelope, "signature", "not!valid!base64")
      assert {:error, :invalid_base64} = Envelope.verify(bad_sig, TestSigner.public_key_b64u())
    end

    test "verifies scanned verdict envelopes" do
      envelope =
        Envelope.sign("did:sigil:scanner", :scanned,
          signer: TestSigner,
          timestamp: "2024-06-15T10:30:00.000Z",
          nonce: "aabbccdd11223344"
        )

      assert envelope["verdict"] == "scanned"
      assert :ok = Envelope.verify(envelope, TestSigner.public_key_b64u())
    end

    test "verifies lowercase wire verdicts by default" do
      envelope =
        Envelope.sign("did:sigil:test", :allowed,
          signer: TestSigner,
          timestamp: "2024-06-15T10:30:00.000Z",
          nonce: "aabbccdd11223344"
        )

      assert envelope["verdict"] == "allowed"
      assert :ok = Envelope.verify(envelope, TestSigner.public_key_b64u())
    end

    test "strict spec profile rejects legacy title-cased verdicts" do
      envelope =
        Envelope.sign("did:sigil:test", :allowed,
          signer: TestSigner,
          profile: :legacy_sigil_guard,
          timestamp: "2024-06-15T10:30:00.000Z",
          nonce: "aabbccdd11223344"
        )

      assert {:error, :invalid_verdict} =
               Envelope.verify(envelope, TestSigner.public_key_b64u(),
                 profile: :sigil_spec_draft_2026_02
               )
    end

    test "strict spec profile rejects blocked envelopes without reason" do
      envelope =
        Envelope.sign("did:sigil:test", :blocked,
          signer: TestSigner,
          reason: "policy blocked",
          timestamp: "2024-06-15T10:30:00.000Z",
          nonce: "aabbccdd11223344"
        )
        |> Map.delete("reason")

      assert {:error, :blocked_reason_required} =
               Envelope.verify(envelope, TestSigner.public_key_b64u(),
                 profile: :sigil_spec_draft_2026_02
               )
    end

    test "blocked reason policy can be required independent of profile" do
      envelope =
        Envelope.sign("did:sigil:test", :blocked,
          signer: TestSigner,
          reason: "policy blocked",
          timestamp: "2024-06-15T10:30:00.000Z",
          nonce: "aabbccdd11223344"
        )
        |> Map.delete("reason")

      assert {:error, :blocked_reason_required} =
               Envelope.verify(envelope, TestSigner.public_key_b64u(), blocked_reason: :require)
    end

    test "enforces timestamp freshness when requested" do
      envelope =
        Envelope.sign("did:sigil:test", :allowed,
          signer: TestSigner,
          timestamp: "2024-06-15T10:30:00.000Z",
          nonce: "aabbccdd11223344"
        )

      assert {:error, :stale_envelope} =
               Envelope.verify(envelope, TestSigner.public_key_b64u(), max_skew_ms: 1)
    end

    test "rejects invalid freshness configuration and timestamps" do
      envelope =
        Envelope.sign("did:sigil:test", :allowed,
          signer: TestSigner,
          timestamp: "not-a-timestamp",
          nonce: "aabbccdd11223344"
        )

      assert {:error, :invalid_timestamp} =
               Envelope.verify(envelope, TestSigner.public_key_b64u(), max_skew_ms: 1_000)

      fresh_envelope = Envelope.sign("did:sigil:test", :allowed, signer: TestSigner)

      assert {:error, :invalid_timestamp} =
               Envelope.verify(fresh_envelope, TestSigner.public_key_b64u(), max_skew_ms: -1)
    end

    test "detects replayed nonces when requested" do
      SigilGuard.ReplayStore.clear()

      envelope =
        Envelope.sign("did:sigil:test", :allowed,
          signer: TestSigner,
          timestamp: Envelope.generate_timestamp(),
          nonce: "aabbccdd11223344aabbccdd11223344"
        )

      opts = [max_skew_ms: 300_000, replay: true]

      assert :ok = Envelope.verify(envelope, TestSigner.public_key_b64u(), opts)

      assert {:error, :replay_detected} =
               Envelope.verify(envelope, TestSigner.public_key_b64u(), opts)
    end
  end

  describe "Rust-generated golden vectors" do
    test "fixture records external generator provenance" do
      fixture = rust_vectors()

      assert fixture["schema"] == "sigil_guard.envelope_golden_vectors.v1"
      assert fixture["generated_by"]["language"] == "rust"
      assert fixture["generated_by"]["crate"] == "sigil-protocol"
      assert fixture["generated_by"]["crate_version"] == "0.1.5"
      assert fixture["public_key_b64u"] == public_key_b64u(RustGoldenVectorSigner)
    end

    test "canonical bytes match the Rust sigil-protocol crate" do
      for vector <- rust_vectors()["vectors"] do
        assert Envelope.canonical_bytes(
                 vector["identity"],
                 verdict_atom(vector["verdict"]),
                 vector["timestamp"],
                 vector["nonce"]
               ) == vector["canonical_json"],
               "canonical bytes mismatch for #{vector["case"]}"
      end
    end

    test "verifies Rust-generated envelopes in compatibility and strict profiles" do
      public_key_b64u = rust_vectors()["public_key_b64u"]

      for vector <- rust_vectors()["vectors"] do
        assert :ok = Envelope.verify(vector["envelope"], public_key_b64u),
               "default verification mismatch for #{vector["case"]}"

        assert :ok =
                 Envelope.verify(vector["envelope"], public_key_b64u,
                   profile: :sigil_spec_draft_2026_02
                 ),
               "strict verification mismatch for #{vector["case"]}"
      end
    end

    test "Elixir signing reproduces Rust-generated signatures" do
      for vector <- rust_vectors()["vectors"] do
        assert Envelope.sign(vector["identity"], verdict_atom(vector["verdict"]),
                 signer: RustGoldenVectorSigner,
                 reason: vector["reason"],
                 timestamp: vector["timestamp"],
                 nonce: vector["nonce"]
               ) == vector["envelope"],
               "signature mismatch for #{vector["case"]}"
      end
    end
  end

  describe "verify/2 with malformed input" do
    test "returns error for each missing required field" do
      envelope = Envelope.sign("did:sigil:test", :allowed, signer: TestSigner)

      for field <- ~w(identity verdict timestamp nonce signature) do
        assert {:error, :missing_field} =
                 envelope
                 |> Map.delete(field)
                 |> Envelope.verify(TestSigner.public_key_b64u()),
               "expected missing_field when #{field} is absent"
      end
    end

    test "returns error for non-string field values" do
      envelope = Envelope.sign("did:sigil:test", :allowed, signer: TestSigner)
      corrupted = Map.put(envelope, "signature", nil)

      assert {:error, :missing_field} =
               Envelope.verify(corrupted, TestSigner.public_key_b64u())
    end

    test "returns error for non-map envelopes" do
      assert {:error, :invalid_envelope} =
               Envelope.verify("not a map", TestSigner.public_key_b64u())

      assert {:error, :invalid_envelope} = Envelope.verify(nil, TestSigner.public_key_b64u())
      assert {:error, :invalid_envelope} = Envelope.verify(%{}, nil)
    end

    test "rejects unknown verdict strings" do
      envelope = Envelope.sign("did:sigil:test", :allowed, signer: TestSigner)

      for bad_verdict <- ["ALLOWED", "garbage", ""] do
        tampered = Map.put(envelope, "verdict", bad_verdict)

        assert {:error, :invalid_verdict} =
                 Envelope.verify(tampered, TestSigner.public_key_b64u()),
               "expected invalid_verdict for #{inspect(bad_verdict)}"
      end
    end

    test "returns error for wrong-size public key" do
      envelope = Envelope.sign("did:sigil:test", :allowed, signer: TestSigner)
      short_key = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)

      assert {:error, :invalid_key} = Envelope.verify(envelope, short_key)
    end

    test "returns error for wrong-size signature" do
      envelope = Envelope.sign("did:sigil:test", :allowed, signer: TestSigner)
      short_sig = Base.url_encode64(:crypto.strong_rand_bytes(10), padding: false)
      tampered = Map.put(envelope, "signature", short_sig)

      assert {:error, :invalid_signature} =
               Envelope.verify(tampered, TestSigner.public_key_b64u())
    end

    test "treats invalid Ed25519 public-key points as signature failures" do
      envelope = Envelope.sign("did:sigil:test", :allowed, signer: TestSigner)
      invalid_curve_point = Base.url_encode64(:binary.copy(<<0>>, 32), padding: false)

      assert {:error, :invalid_signature} = Envelope.verify(envelope, invalid_curve_point)
    end
  end

  describe "generate_timestamp/0" do
    test "returns ISO 8601 format with milliseconds" do
      ts = Envelope.generate_timestamp()

      assert String.ends_with?(ts, "Z")
      assert {:ok, _, _} = DateTime.from_iso8601(ts)
    end
  end

  describe "generate_nonce/0" do
    test "returns 32-character hex string (16 bytes)" do
      nonce = Envelope.generate_nonce()

      assert byte_size(nonce) == 32
      assert Regex.match?(~r/^[0-9a-f]{32}$/, nonce)
    end

    test "generates unique values" do
      nonces = for _ <- 1..100, do: Envelope.generate_nonce()

      assert length(Enum.uniq(nonces)) == 100
    end
  end

  defp rust_vectors do
    @rust_vectors_path
    |> File.read!()
    |> Jason.decode!()
  end

  defp verdict_atom("allowed"), do: :allowed
  defp verdict_atom("blocked"), do: :blocked
  defp verdict_atom("scanned"), do: :scanned

  defp public_key_b64u(signer) do
    signer.public_key()
    |> Base.url_encode64(padding: false)
  end
end
