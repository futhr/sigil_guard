defmodule SigilGuard.BoundaryPolicy.ContractTest do
  use ExUnit.Case, async: true

  use ExUnitProperties

  alias SigilGuard.BoundaryPolicy.Contract

  doctest Contract

  describe "parse/1 success" do
    test "an empty section compiles to an empty map" do
      assert Contract.parse([]) == {:ok, %{}}
    end

    test "parses the full vocabulary for one sink" do
      line =
        "contract sink:external max_size:16384 no_raw_credentials:true " <>
          "digest_only_pii:true classes:text credential_transform:hash"

      assert {:ok, %{"external" => contract}} = Contract.parse([line])

      assert contract == %Contract{
               max_size: 16_384,
               no_raw_credentials: true,
               digest_only_pii: true,
               classes: [:text],
               credential_transform: :hash
             }
    end

    test "applies the documented defaults for omitted fields" do
      assert {:ok, %{"model" => contract}} = Contract.parse(["contract sink:model"])

      assert contract == %Contract{
               max_size: nil,
               no_raw_credentials: false,
               digest_only_pii: false,
               classes: nil,
               credential_transform: :mask
             }
    end

    test "one contract line fans out to every listed sink" do
      assert {:ok, contracts} =
               Contract.parse(["contract sink:external,network max_size:1024"])

      assert contracts["external"] == contracts["network"]
      assert contracts["external"].max_size == 1024
    end

    test "accepts both content classes and deduplicates them" do
      assert {:ok, %{"model" => contract}} =
               Contract.parse(["contract sink:model classes:text,structured,text"])

      assert contract.classes == [:text, :structured]
    end

    test "accepts the mask transform explicitly and the minimum max_size" do
      assert {:ok, %{"log" => contract}} =
               Contract.parse(["contract sink:log max_size:64 credential_transform:mask"])

      assert contract.max_size == 64
      assert contract.credential_transform == :mask
    end
  end

  describe "parse/1 errors" do
    test "a duplicate sink across two contracts fails" do
      assert Contract.parse([
               "contract sink:external max_size:1024",
               "contract sink:external,log max_size:2048"
             ]) == {:error, :invalid_output_contract}
    end

    test "a sink repeated within one line fails" do
      assert Contract.parse(["contract sink:external,external"]) ==
               {:error, :invalid_output_contract}
    end

    test "a missing sink field fails" do
      assert Contract.parse(["contract max_size:1024"]) == {:error, :invalid_output_contract}
    end

    test "an unknown field fails" do
      assert Contract.parse(["contract sink:external retain:true"]) ==
               {:error, :invalid_output_contract}
    end

    test "a duplicate field within one contract fails" do
      assert Contract.parse(["contract sink:external max_size:64 max_size:128"]) ==
               {:error, :invalid_output_contract}
    end

    test "a max_size below 64 fails" do
      assert Contract.parse(["contract sink:external max_size:63"]) ==
               {:error, :invalid_output_contract}
    end

    test "a non-integer or trailing-garbage max_size fails" do
      assert Contract.parse(["contract sink:external max_size:big"]) ==
               {:error, :invalid_output_contract}

      assert Contract.parse(["contract sink:external max_size:64kb"]) ==
               {:error, :invalid_output_contract}
    end

    test "an invalid content class fails" do
      assert Contract.parse(["contract sink:external classes:text,binary"]) ==
               {:error, :invalid_output_contract}
    end

    test "a non-boolean flag value fails" do
      assert Contract.parse(["contract sink:external no_raw_credentials:yes"]) ==
               {:error, :invalid_output_contract}
    end

    test "an empty CSV member fails" do
      assert Contract.parse(["contract sink:external,"]) == {:error, :invalid_output_contract}

      assert Contract.parse(["contract sink:external classes:"]) ==
               {:error, :invalid_output_contract}
    end

    test "a field token without a colon fails" do
      assert Contract.parse(["contract sink:external maxsize"]) ==
               {:error, :invalid_output_contract}
    end

    test "a line that does not start with contract fails" do
      assert Contract.parse(["policy sink:external"]) == {:error, :invalid_output_contract}
      assert Contract.parse(["contract"]) == {:error, :invalid_output_contract}
    end

    test "an unknown credential_transform fails with :unknown_transform" do
      assert Contract.parse(["contract sink:external credential_transform:rot13"]) ==
               {:error, :unknown_transform}
    end
  end

  describe "truncate/2" do
    test "returns content unchanged when it already fits" do
      assert Contract.truncate("under the cap", 64) == "under the cap"
    end

    test "keeps a byte-bounded prefix and appends the marker when over" do
      result = Contract.truncate(String.duplicate("a", 100), 64)
      assert result == String.duplicate("a", 53) <> "[TRUNCATED]"
      assert byte_size(result) == 64
    end

    test "backs off to a codepoint boundary so multibyte content stays valid UTF-8" do
      # "é" is two bytes; a naive 53-byte cut would split the 27th codepoint.
      result = Contract.truncate(String.duplicate("é", 100), 64)

      assert String.valid?(result)
      assert byte_size(result) <= 64
      assert String.ends_with?(result, "[TRUNCATED]")
    end

    property "the result is always valid UTF-8 and never exceeds max_size" do
      check all(
              content <- string(:printable),
              max_size <- integer(64..256)
            ) do
        result = Contract.truncate(content, max_size)
        assert String.valid?(result)
        assert byte_size(result) <= max_size
      end
    end
  end

  describe "hash/1 and mask/1" do
    test "hash is the 71-byte sha256 prefix and is deterministic" do
      digest = Contract.hash("token-value")
      assert digest == Contract.hash("token-value")
      assert byte_size(digest) == 71
      assert String.starts_with?(digest, "sha256:")
    end

    test "mask preserves the codepoint count for multibyte spans" do
      assert Contract.mask("abc") == "***"
      # three codepoints, six bytes -> three stars.
      assert Contract.mask("héy") == "***"
    end
  end

  describe "enforce/4" do
    defp text_contract(fields), do: struct(Contract, fields)

    test "a nil contract passes content through unchanged" do
      assert Contract.enforce(nil, "external", "anything") == {:ok, "anything"}
    end

    test "a block or quarantine verdict skips the contract entirely" do
      contract = text_contract(max_size: 64)
      big = String.duplicate("x", 200)

      assert Contract.enforce(contract, "external", big, verdict: :block) == {:ok, big}
      assert Contract.enforce(contract, "external", big, verdict: :quarantine) == {:ok, big}
    end

    test "a disallowed content class escalates to block with the contract rule id" do
      contract = text_contract(classes: [:text])

      assert Contract.enforce(contract, "external", %{"a" => 1}) ==
               {:block, "contract.external.class"}
    end

    test "an allowed structured payload crosses unchanged" do
      contract = text_contract(classes: [:text, :structured], max_size: 64)
      payload = %{"a" => 1}

      assert Contract.enforce(contract, "model", payload) == {:ok, payload}
    end

    test "no_raw_credentials replaces supplied matches with the contract transform" do
      hashed = text_contract(no_raw_credentials: true, credential_transform: :hash)
      masked = text_contract(no_raw_credentials: true, credential_transform: :mask)
      text = "authorization: s3cr3t-token here"

      assert {:ok, out} = Contract.enforce(hashed, "log", text, credentials: ["s3cr3t-token"])
      refute out =~ "s3cr3t-token"
      assert out =~ Contract.hash("s3cr3t-token")

      assert {:ok, out} = Contract.enforce(masked, "log", text, credentials: ["s3cr3t-token"])
      assert out =~ String.duplicate("*", String.length("s3cr3t-token"))
    end

    test "credential matches are ignored when no_raw_credentials is off" do
      contract = text_contract(no_raw_credentials: false)
      text = "token s3cr3t"

      assert Contract.enforce(contract, "log", text, credentials: ["s3cr3t"]) == {:ok, text}
    end

    test "digest_only_pii hashes supplied PII spans" do
      contract = text_contract(digest_only_pii: true)
      text = "user alice ok"

      assert {:ok, out} = Contract.enforce(contract, "log", text, pii: ["alice"])
      refute out =~ "alice"
      assert out =~ Contract.hash("alice")
    end

    test "runs credential transform, PII, then truncation in order" do
      contract =
        text_contract(
          no_raw_credentials: true,
          credential_transform: :mask,
          digest_only_pii: true,
          max_size: 64
        )

      text = "key=SECRET pii=bob " <> String.duplicate("z", 100)

      assert {:ok, out} =
               Contract.enforce(contract, "external", text, credentials: ["SECRET"], pii: ["bob"])

      refute out =~ "SECRET"
      assert byte_size(out) <= 64
      assert String.ends_with?(out, "[TRUNCATED]")
    end

    test "text transforms do not apply to a structured payload" do
      contract = text_contract(classes: [:structured], no_raw_credentials: true, max_size: 64)
      payload = ["a", "b"]

      assert Contract.enforce(contract, "model", payload, credentials: ["a"]) == {:ok, payload}
    end
  end
end
