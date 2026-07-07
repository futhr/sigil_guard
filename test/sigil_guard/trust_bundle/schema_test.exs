defmodule SigilGuard.TrustBundle.SchemaTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Attestation.Envelope
  alias SigilGuard.TrustBundle.Schema

  @issued_at "2026-07-02T12:00:00.000Z"
  @expires_at "2026-08-01T12:00:00.000Z"
  @role_expires_at "2026-10-01T12:00:00.000Z"

  describe "validate/1" do
    test "validates a minimal bundle document" do
      assert Schema.validate(bundle_document()) == {:ok, :bundle, bundle_document()}
    end

    test "validates optional bundle sections and revocations" do
      document =
        bundle_document()
        |> Map.put("tools", [%{"name" => "mix"}])
        |> Map.put("policies", [%{"id" => "default"}])
        |> Map.put("patterns", [%{"id" => "safe-read"}])
        |> Map.put("identity_issuers", [%{"id" => "issuer"}])
        |> Map.put("rotation_chain", [%{"root_version" => "1"}])
        |> Map.put("provenance", %{"source" => "test"})
        |> Map.put("revocations", [
          %{"kind" => "key", "id" => root_keyid(), "revoked_at" => @issued_at}
        ])

      assert Schema.validate(document) == {:ok, :bundle, document}
    end

    test "validates a root rotation document" do
      assert Schema.validate(rotation_document()) == {:ok, :rotation, rotation_document()}
    end

    test "rejects unsupported and invalid profiles" do
      assert bundle_document()
             |> Map.put("profile", "sigil_guard_trust_bundle/v2")
             |> Schema.validate() == {:error, :unsupported_profile_version}

      assert rotation_document()
             |> Map.put("profile", "sigil_guard_root_rotation/v2")
             |> Schema.validate() == {:error, :unsupported_profile_version}

      assert bundle_document()
             |> Map.put("profile", "other/v1")
             |> Schema.validate() == {:error, :invalid_bundle_format}

      assert Map.delete(bundle_document(), "profile")
             |> Schema.validate() == {:error, :invalid_bundle_format}
    end

    test "rejects non-document inputs" do
      assert Schema.validate("not a document") == {:error, :invalid_bundle_format}
      assert Schema.validate_bundle("not a document") == {:error, :invalid_bundle_format}
      assert Schema.validate_rotation("not a document") == {:error, :invalid_bundle_format}
    end

    test "rejects invalid bundle format trigger classes" do
      bad_key = String.duplicate("0", 32)
      bad_keyid = Envelope.keyid(bad_key)
      valid_keyid = root_keyid()

      cases = [
        {"unknown top-level field", Map.put(bundle_document(), "extra", true)},
        {"missing required field", Map.delete(bundle_document(), "bundle_id")},
        {"sequence regex violation", Map.put(bundle_document(), "sequence", "0")},
        {"sequence with trailing newline", Map.put(bundle_document(), "sequence", "1\n")},
        {"rollback floor above sequence", Map.put(bundle_document(), "rollback_floor", "2")},
        {"invalid timestamp precision",
         Map.put(bundle_document(), "issued_at", "2026-07-02T12:00:00Z")},
        {"timestamp with trailing newline",
         Map.put(bundle_document(), "issued_at", @issued_at <> "\n")},
        {"non-binary timestamp", Map.put(bundle_document(), "issued_at", 1)},
        {"inverted lifetime", Map.put(bundle_document(), "expires_at", @issued_at)},
        {"threshold below range", put_in(bundle_document(), ["roles", "root", "threshold"], 0)},
        {
          "threshold above range",
          put_in(bundle_document(), ["roles", "delegates", Access.at(0), "threshold"], 2)
        },
        {
          "duplicate role keyids",
          put_in(bundle_document(), ["roles", "root", "keyids"], [valid_keyid, valid_keyid])
        },
        {
          "role keyid absent from keys",
          put_in(bundle_document(), ["roles", "root", "keyids"], [bad_keyid])
        },
        {
          "role keyid with trailing newline",
          put_in(bundle_document(), ["roles", "root", "keyids"], [valid_keyid <> "\n"])
        },
        {
          "keyid not sha256 of key",
          bundle_document()
          |> put_in(["keys", bad_keyid], %{
            "alg" => "ed25519",
            "public_key" => Base.url_encode64(root_public_key(), padding: false)
          })
          |> put_in(["roles", "root", "keyids"], [bad_keyid])
        },
        {
          "wrong key algorithm",
          put_in(bundle_document(), ["keys", valid_keyid, "alg"], "rsa")
        },
        {
          "non-32-byte key",
          put_in(
            bundle_document(),
            ["keys", valid_keyid, "public_key"],
            Base.url_encode64("short", padding: false)
          )
        },
        {"non-list optional section", Map.put(bundle_document(), "patterns", %{})},
        {"malformed revocation", Map.put(bundle_document(), "revocations", [%{"kind" => "key"}])}
      ]

      for {label, document} <- cases do
        assert Schema.validate(document) == {:error, :invalid_bundle_format}, label
      end
    end

    test "rejects malformed bundle field types" do
      valid_keyid = root_keyid()

      cases = [
        {"atom top-level key", Map.put(bundle_document(), :extra, true)},
        {"empty bundle id", Map.put(bundle_document(), "bundle_id", "")},
        {"numeric sequence", Map.put(bundle_document(), "sequence", 1)},
        {"empty key map", Map.put(bundle_document(), "keys", %{})},
        {"non-map key descriptor",
         put_in(bundle_document(), ["keys", valid_keyid], "descriptor")},
        {"non-binary keyid", Map.put(bundle_document(), "keys", %{1 => key_descriptor()})},
        {"non-base64 public key",
         put_in(bundle_document(), ["keys", valid_keyid, "public_key"], "*")},
        {"missing public key",
         update_in(bundle_document(), ["keys", valid_keyid], &Map.delete(&1, "public_key"))},
        {"non-map roles", Map.put(bundle_document(), "roles", [])},
        {"non-map root role", put_in(bundle_document(), ["roles", "root"], [])},
        {"empty delegates", put_in(bundle_document(), ["roles", "delegates"], [])},
        {"non-map delegate", put_in(bundle_document(), ["roles", "delegates"], ["delegate"])},
        {"empty delegate name",
         put_in(bundle_document(), ["roles", "delegates", Access.at(0), "name"], "")},
        {"duplicate delegate names", duplicate_bundle_delegate_document()},
        {"non-binary delegate keyid",
         put_in(bundle_document(), ["roles", "delegates", Access.at(0), "keyids"], [1])},
        {"string threshold",
         put_in(bundle_document(), ["roles", "delegates", Access.at(0), "threshold"], "1")},
        {"non-map provenance", Map.put(bundle_document(), "provenance", [])},
        {"non-list revocations", Map.put(bundle_document(), "revocations", %{})},
        {"non-map revocation", Map.put(bundle_document(), "revocations", ["revocation"])},
        {"invalid revocation kind",
         Map.put(bundle_document(), "revocations", [
           %{"kind" => "other", "id" => "root", "revoked_at" => @issued_at}
         ])},
        {"invalid revocation timestamp",
         Map.put(bundle_document(), "revocations", [
           %{"kind" => "key", "id" => "root", "revoked_at" => "2026-07-02T12:00:00Z"}
         ])}
      ]

      for {label, document} <- cases do
        assert Schema.validate(document) == {:error, :invalid_bundle_format}, label
      end
    end

    test "returns unknown_role when bundle delegate is absent" do
      document = put_in(bundle_document(), ["roles", "delegates", Access.at(0), "name"], "other")

      assert Schema.validate(document) == {:error, :unknown_role}
    end

    test "rejects malformed rotation documents" do
      cases = [
        {"unknown top-level field", Map.put(rotation_document(), "extra", true)},
        {"non-integer root version",
         put_in(rotation_document(), ["roles", "root", "version"], "latest")},
        {"root version mismatch", put_in(rotation_document(), ["roles", "root", "version"], "3")},
        {"invalid issued_at", Map.put(rotation_document(), "issued_at", "2026-07-02T12:00:00Z")},
        {"missing root role", Map.put(rotation_document(), "roles", %{})}
      ]

      for {label, document} <- cases do
        assert Schema.validate(document) == {:error, :invalid_bundle_format}, label
      end
    end
  end

  defp bundle_document do
    %{
      "profile" => "sigil_guard_trust_bundle/v1",
      "bundle_id" => "example-org-trust",
      "sequence" => "1",
      "issued_at" => @issued_at,
      "expires_at" => @expires_at,
      "roles" => %{
        "root" => %{
          "keyids" => [root_keyid()],
          "threshold" => 1,
          "version" => "1",
          "expires_at" => "2027-07-02T12:00:00.000Z"
        },
        "delegates" => [
          %{
            "name" => "bundle",
            "keyids" => [bundle_keyid()],
            "threshold" => 1,
            "expires_at" => @role_expires_at
          }
        ]
      },
      "keys" => %{
        root_keyid() => %{
          "alg" => "ed25519",
          "public_key" => Base.url_encode64(root_public_key(), padding: false)
        },
        bundle_keyid() => %{
          "alg" => "ed25519",
          "public_key" => Base.url_encode64(bundle_public_key(), padding: false)
        }
      },
      "rollback_floor" => "1"
    }
  end

  defp rotation_document do
    %{
      "profile" => "sigil_guard_root_rotation/v1",
      "bundle_id" => "example-org-trust",
      "root_version" => "2",
      "roles" => %{
        "root" => %{
          "keyids" => [root_keyid()],
          "threshold" => 1,
          "version" => "2",
          "expires_at" => "2028-07-02T12:00:00.000Z"
        }
      },
      "keys" => %{
        root_keyid() => %{
          "alg" => "ed25519",
          "public_key" => Base.url_encode64(root_public_key(), padding: false)
        }
      },
      "rollback_floor" => "2",
      "issued_at" => @issued_at
    }
  end

  defp root_public_key, do: public_key(:crypto.hash(:sha256, "root"))
  defp bundle_public_key, do: public_key(:crypto.hash(:sha256, "bundle"))
  defp root_keyid, do: Envelope.keyid(root_public_key())
  defp bundle_keyid, do: Envelope.keyid(bundle_public_key())

  defp key_descriptor do
    %{
      "alg" => "ed25519",
      "public_key" => Base.url_encode64(root_public_key(), padding: false)
    }
  end

  defp duplicate_bundle_delegate_document do
    bundle_delegate = hd(bundle_document()["roles"]["delegates"])
    put_in(bundle_document(), ["roles", "delegates"], [bundle_delegate, bundle_delegate])
  end

  defp public_key(seed) do
    {public_key, _} = :crypto.generate_key(:eddsa, :ed25519, seed)
    public_key
  end
end
