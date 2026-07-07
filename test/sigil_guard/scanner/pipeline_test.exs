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

defmodule SigilGuard.ScannerBadReturnTestStub do
  @moduledoc false

  @spec scan(String.t(), [map()], keyword()) :: term()
  def scan(_, _, _), do: :not_hits
end

defmodule SigilGuard.ScannerBadHitTestStub do
  @moduledoc false

  @spec scan(String.t(), [map()], keyword()) :: [map()]
  def scan(text, _, _) do
    [
      %{
        name: "bad",
        category: "test",
        severity: :low,
        match: "x",
        offset: byte_size(text) + 1,
        length: 1,
        replacement_hint: nil
      }
    ]
  end
end

defmodule SigilGuard.Scanner.PipelineTest do
  @moduledoc false

  use ExUnit.Case, async: true

  use ExUnitProperties

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
      assert :token_boundary in hit.signals
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
      assert :assignment_boundary in hit.signals
    end

    test "rejects embedded assignment labels in staged mode" do
      text = "notsecret=R7v9K2mQ4xZ8pL6n"

      assert {:ok, ^text} = Scanner.scan(text)
      assert {:hit, [hit]} = Scanner.scan(text, pipeline: :regex)
      assert hit.name == "generic_secret"
      assert hit.offset == 3
    end

    test "rejects embedded fixed-format token substrings in staged mode" do
      text = "XAKIAIOSFODNN7EXAMPLEY"

      assert {:ok, ^text} = Scanner.scan(text)
      assert {:hit, [hit]} = Scanner.scan(text, pipeline: :regex)
      assert hit.name == "aws_access_key"
      assert hit.offset == 1
    end

    test "rejects embedded bearer token labels in staged mode" do
      text = "notbearer sk-abc123def456ghi789jkl012mno345"

      assert {:ok, ^text} = Scanner.scan(text)
      assert {:hit, [hit]} = Scanner.scan(text, pipeline: :regex)
      assert hit.name == "bearer_token"
      assert hit.offset == 3
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

    test "validates raw high-entropy generic secret candidates without delimiters" do
      patterns =
        Patterns.compile([
          %{
            name: "generic_secret",
            category: "credential",
            severity: :medium,
            pattern: "[A-Za-z0-9]{20,}"
          }
        ])

      assert [hit] = Pipeline.scan("R7v9K2mQ4xZ8pL6nT5y0", patterns)

      assert hit.name == "generic_secret"
      assert hit.match == "R7v9K2mQ4xZ8pL6nT5y0"
      assert :high_entropy in hit.signals
    end

    test "validates bearer-token-shaped values without a Bearer prefix for custom patterns" do
      patterns =
        Patterns.compile([
          %{
            name: "bearer_token",
            category: "credential",
            severity: :high,
            pattern: "sk-[A-Za-z0-9._~+\\/=\\-]{24,}"
          }
        ])

      assert [hit] = Pipeline.scan("sk-aB3dE5gH7jK9mN2pQ4rS6tU8", patterns)

      assert hit.name == "bearer_token"
      assert hit.match == "sk-aB3dE5gH7jK9mN2pQ4rS6tU8"
      assert :token_boundary in hit.signals
    end

    test "extracts quoted assignment values before terminators" do
      patterns =
        Patterns.compile([
          %{
            name: "generic_secret",
            category: "credential",
            severity: :medium,
            pattern: ~S(secret\s*=\s*'[^']+')
          },
          %{
            name: "generic_api_key",
            category: "credential",
            severity: :high,
            pattern: ~S(api_key\s*=\s*"[^"]+")
          }
        ])

      assert [single_quoted] =
               Pipeline.scan("secret='R7v9K2mQ4xZ8pL6n extra'", patterns)

      assert single_quoted.name == "generic_secret"
      assert single_quoted.validated

      assert [double_quoted] =
               Pipeline.scan("api_key=\"R7v9K2mQ4xZ8pL6nT5y0\"", patterns)

      assert double_quoted.name == "generic_api_key"
      assert double_quoted.validated
    end

    test "filters hits below the configured confidence floor" do
      patterns =
        Patterns.compile([
          %{name: "custom", category: "test", severity: :low, pattern: "CUSTOM_[0-9]{4}"}
        ])

      assert {:ok, "CUSTOM_1234"} =
               Scanner.scan("CUSTOM_1234", patterns: patterns, min_confidence: 0.7)
    end

    test "falls back to conservative scanner options when thresholds are malformed" do
      assert {:hit, [hit]} =
               Scanner.scan("secret=R7v9K2mQ4xZ8pL6n",
                 generic_secret_min_length: "long",
                 generic_secret_min_entropy: :strict,
                 min_confidence: "high",
                 token_min_entropy: "strict"
               )

      assert hit.name == "generic_secret"
      assert hit.validated
    end

    test "keeps validation enabled for malformed validation toggles" do
      assert {:ok, "secret=aaaaaaaa"} = Scanner.scan("secret=aaaaaaaa", validate: "false")

      assert {:hit, [hit]} = Scanner.scan("secret=aaaaaaaa", validate: false)
      refute hit.validated
    end

    test "accepts custom scanner pipeline modules" do
      patterns = Patterns.compile([%{name: "x", category: "t", severity: :low, pattern: "x"}])

      assert {:hit, [hit]} =
               Scanner.scan("x", patterns: patterns, pipeline: SigilGuard.ScannerPipelineTestStub)

      assert hit.name == "stub"
    end

    test "rejects custom scanner pipelines with malformed output" do
      assert_raise ArgumentError, ~r/must return a hit list/, fn ->
        Scanner.scan("x", pipeline: SigilGuard.ScannerBadReturnTestStub)
      end

      assert_raise ArgumentError, ~r/must return valid scan hits/, fn ->
        Scanner.scan("x", pipeline: SigilGuard.ScannerBadHitTestStub)
      end
    end

    test "raises on invalid scanner pipeline modules" do
      assert_raise ArgumentError, ~r/export scan\/3/, fn ->
        Scanner.scan("x", pipeline: String)
      end
    end

    test "raises on invalid scanner pipeline option values" do
      assert_raise ArgumentError, ~r/invalid scanner pipeline 123/, fn ->
        Scanner.scan("x", pipeline: 123)
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

  describe "confidence score bounds" do
    # Fixtures that reliably produce an enriched hit under the built-in patterns.
    @scored_secrets [
      "key=AKIAIOSFODNN7EXAMPLE",
      "api_key=R7v9K2mQ4xZ8pL6nT5y0",
      "secret=R7v9K2mQ4xZ8pL6nT5y0"
    ]

    test "a strongly-signalled secret caps confidence at 0.99, never above 1.0" do
      assert {:hit, [hit]} = Scanner.scan("key=AKIAIOSFODNN7EXAMPLE")
      assert hit.confidence <= 0.99
    end

    property "every enriched hit carries a confidence that is a float in 0.0..1.0" do
      check all(
              secret <- member_of(@scored_secrets),
              noise <- string(:alphanumeric, max_length: 10)
            ) do
        text = noise <> " " <> secret <> " " <> noise

        case Scanner.scan(text) do
          {:ok, _} ->
            :ok

          {:hit, hits} ->
            Enum.each(hits, fn hit ->
              assert is_float(hit.confidence)
              assert hit.confidence >= 0.0 and hit.confidence <= 1.0
            end)
        end
      end
    end
  end
end
