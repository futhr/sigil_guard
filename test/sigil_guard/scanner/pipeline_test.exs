defmodule SigilGuard.ScannerPipelineTestStub do
  @moduledoc false

  @spec scan(String.t(), [map()], keyword()) :: [map()]
  def scan(_, _, _) do
    [
      %{
        name: "stub",
        category: "test",
        severity: :low,
        match: "x",
        offset: 0,
        length: 1,
        replacement_hint: nil
      }
    ]
  end
end

defmodule SigilGuard.Scanner.PipelineTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Patterns
  alias SigilGuard.Scanner
  alias SigilGuard.Scanner.Pipeline

  describe "scan/3" do
    test "enriches regex hits with deterministic validation metadata" do
      assert {:hit, [hit]} = Scanner.scan("key=AKIAIOSFODNN7EXAMPLE")

      assert hit.name == "aws_access_key"
      assert hit.validated
      assert hit.stage == :validated
      assert hit.confidence >= 0.9
      assert :known_key_format in hit.signals
      assert :credential_category in hit.signals
    end

    test "keeps legacy regex-only hits when requested" do
      assert {:hit, [hit]} = Scanner.scan("key=AKIAIOSFODNN7EXAMPLE", pipeline: :regex)

      assert hit.name == "aws_access_key"
      refute Map.has_key?(hit, :confidence)
      refute Map.has_key?(hit, :signals)
      refute Map.has_key?(hit, :validated)
    end

    test "rejects weak generic secrets in staged mode" do
      assert {:ok, "secret=aaaaaaaa"} = Scanner.scan("secret=aaaaaaaa")
    end

    test "rejects placeholder generic secrets in staged mode" do
      assert {:ok, "secret=changeme12345"} = Scanner.scan("secret=changeme12345")

      assert {:ok, "api_key=abcabcabcabcabcabcabcabc"} =
               Scanner.scan("api_key=abcabcabcabcabcabcabcabc")
    end

    test "keeps high-entropy generic secrets in staged mode" do
      assert {:hit, [hit]} = Scanner.scan("secret=R7v9K2mQ4xZ8pL6n")

      assert hit.name == "generic_secret"
      assert hit.validated
      assert :high_entropy in hit.signals
      assert :assignment_context in hit.signals
    end

    test "allows local validation thresholds to be tightened" do
      assert {:ok, "secret=R7v9K2mQ4xZ8pL6n"} =
               Scanner.scan("secret=R7v9K2mQ4xZ8pL6n",
                 generic_secret_min_entropy: 4.5
               )
    end

    test "can keep weak regex candidates when validation is disabled" do
      assert {:hit, [hit]} = Scanner.scan("secret=aaaaaaaa", validate: false)

      assert hit.name == "generic_secret"
      refute hit.validated
      assert hit.stage == :enriched
    end

    test "filters hits below the configured confidence floor" do
      patterns =
        Patterns.compile([
          %{name: "custom", category: "test", severity: :low, pattern: "CUSTOM_[0-9]{4}"}
        ])

      assert {:ok, "CUSTOM_1234"} =
               Scanner.scan("CUSTOM_1234", patterns: patterns, min_confidence: 0.7)
    end

    test "accepts custom scanner pipeline modules" do
      patterns = Patterns.compile([%{name: "x", category: "t", severity: :low, pattern: "x"}])

      assert {:hit, [hit]} =
               Scanner.scan("x", patterns: patterns, pipeline: SigilGuard.ScannerPipelineTestStub)

      assert hit.name == "stub"
    end

    test "raises on invalid scanner pipeline modules" do
      assert_raise ArgumentError, ~r/export scan\/3/, fn ->
        Scanner.scan("x", pipeline: String)
      end
    end
  end

  describe "regex_candidates/2" do
    test "exposes the raw regex candidate stage" do
      [pattern] = Patterns.compile([%{name: "x", category: "t", severity: :low, pattern: "x+"}])

      assert [%{match: "xxx", offset: 1, length: 3, pattern: ^pattern}] =
               Pipeline.regex_candidates(" xxx ", [pattern])
    end
  end
end
