defmodule SigilGuard.Patterns do
  @moduledoc """
  Pattern compilation and management for sensitivity scanning.

  Provides built-in patterns for common credential and secret formats, plus
  support for loading patterns from explicit compatibility bundles.

  ## Built-in Patterns

  The following patterns are included by default (no registry dependency):

    * AWS access keys (`AKIA`, `ABIA`, `ACCA`, `ASIA` prefixes)
    * Generic API key assignments
    * Bearer tokens
    * Database connection URIs (PostgreSQL, MySQL, MongoDB)
    * Private key headers (RSA, EC, OpenSSH)
    * Generic secret/password/token assignments

  ## Compatibility Bundle Patterns

  When the legacy remote-bundle cache is enabled, patterns from
  `GET /patterns/bundle` are merged with built-in patterns. Remote bundle
  patterns take precedence on name collision after provenance checks pass.
  """

  @typedoc """
  Pattern-set category (SP.04). The built-in pipeline emits the closed atom set
  `:secret | :injection | :poisoning`; custom/compatibility-bundle patterns may
  carry a free-form string category.
  """
  @type category :: :secret | :injection | :poisoning | String.t()

  @type scan_hit :: %{
          required(:name) => String.t(),
          required(:category) => category(),
          required(:severity) => :low | :medium | :high,
          required(:match) => String.t(),
          required(:offset) => non_neg_integer(),
          required(:length) => non_neg_integer(),
          required(:replacement_hint) => String.t() | nil,
          optional(:confidence) => float(),
          optional(:signals) => [atom()],
          optional(:span) => {non_neg_integer(), non_neg_integer()},
          optional(:stage) => atom(),
          optional(:validated) => boolean()
        }

  @typedoc "Pattern set (SP.04): `secret` feeds the scanner; `injection`/`poisoning` feed quarantine."
  @type pattern_set :: :secret | :injection | :poisoning

  @type compiled_pattern :: %{
          name: String.t(),
          category: category(),
          severity: :low | :medium | :high,
          regex: Regex.t(),
          replacement_hint: String.t() | nil,
          max_match_bytes: pos_integer(),
          set: pattern_set()
        }

  @default_max_match_bytes 256
  @max_match_bytes_limit 4096

  # `max_match_bytes` bounds the longest span each pattern can match, clamping
  # unbounded quantifiers (SP.04 Holdback Invariant). It sizes the streaming
  # holdback window so no secret can straddle a chunk boundary undetected.
  @built_in_patterns [
    %{
      name: "aws_access_key",
      category: :secret,
      severity: :high,
      pattern: "(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}",
      replacement_hint: "[AWS_KEY]",
      max_match_bytes: 20
    },
    %{
      name: "generic_api_key",
      category: :secret,
      severity: :high,
      pattern: "(?i)(api[_\\-]?key|apikey)\\s*[:=]\\s*['\"]?[\\w\\-]{20,}",
      replacement_hint: "[API_KEY]",
      max_match_bytes: 256
    },
    %{
      name: "bearer_token",
      category: :secret,
      severity: :high,
      pattern: "(?i)bearer\\s+[a-zA-Z0-9._~+/=\\-]{20,}",
      replacement_hint: "[BEARER_TOKEN]",
      max_match_bytes: 256
    },
    %{
      name: "database_uri",
      category: :secret,
      severity: :high,
      pattern: "(?i)(postgres|mysql|mongodb)://[^:]+:[^@]+@",
      replacement_hint: "[DATABASE_URI]",
      max_match_bytes: 256
    },
    %{
      name: "private_key",
      category: :secret,
      severity: :high,
      pattern: "-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
      replacement_hint: "[PRIVATE_KEY]",
      max_match_bytes: 40
    },
    %{
      name: "generic_secret",
      category: :secret,
      severity: :medium,
      pattern: "(?i)(secret|password|token|credential)\\s*[:=]\\s*['\"]?[^\\s'\"]{8,}",
      replacement_hint: "[SECRET]",
      max_match_bytes: 256
    }
  ]

  @doc "Return compiled built-in patterns."
  @spec built_in() :: [compiled_pattern()]
  def built_in do
    case :persistent_term.get({__MODULE__, :built_in_patterns}, :undefined) do
      :undefined ->
        patterns = compile_built_in_patterns()
        :persistent_term.put({__MODULE__, :built_in_patterns}, patterns)
        patterns

      patterns ->
        patterns
    end
  end

  @doc "The default `max_match_bytes` used when a pattern does not declare one."
  @spec default_max_match_bytes() :: 256
  def default_max_match_bytes, do: @default_max_match_bytes

  @doc """
  Return the largest `max_match_bytes` among `patterns`.

  Sizes the streaming holdback window (SP.04): the effective window MUST be at
  least this value so no pattern match can straddle a chunk boundary undetected.
  Falls back to the default when the list is empty or a pattern omits the field.
  """
  @spec largest_max_match_bytes([compiled_pattern()]) :: pos_integer()
  def largest_max_match_bytes(patterns) when is_list(patterns) do
    patterns
    |> Enum.map(&Map.get(&1, :max_match_bytes, @default_max_match_bytes))
    |> Enum.max(fn -> @default_max_match_bytes end)
  end

  @doc """
  Compile a list of raw pattern maps into executable patterns.

  Accepts both built-in format (with `:pattern` key) and compatibility bundle
  format (with `"regex"` key).
  """
  @spec compile([map()]) :: [compiled_pattern()]
  def compile(raw_patterns) do
    raw_patterns
    |> Enum.map(&compile_pattern/1)
    |> Enum.reject(&is_nil/1)
  end

  @doc """
  Parse a compatibility bundle response into pattern maps.

  Expected format:
  ```json
  {"generated_at": "...", "count": 5, "patterns": [...]}
  ```
  """
  @spec parse_bundle(map()) :: {:ok, [map()]} | {:error, term()}
  def parse_bundle(%{"patterns" => patterns}) when is_list(patterns) do
    if Enum.all?(patterns, &valid_raw_pattern?/1) do
      {:ok, patterns}
    else
      {:error, :invalid_pattern_format}
    end
  end

  def parse_bundle(_), do: {:error, :invalid_bundle_format}

  @doc """
  Merge two pattern lists, with `override` taking precedence on name collision.
  """
  @spec merge([compiled_pattern()], [compiled_pattern()]) :: [compiled_pattern()]
  def merge(base, override) do
    override_names = MapSet.new(override, & &1.name)

    base
    |> Enum.reject(fn p -> MapSet.member?(override_names, p.name) end)
    |> Enum.concat(override)
  end

  defp compile_pattern(raw) when is_map(raw) do
    with :ok <- validate_pattern_metadata(raw),
         source when is_binary(source) <- extract_regex_source(raw),
         {:ok, regex} <- Regex.compile(source) do
      build_compiled(raw, regex)
    else
      _ -> nil
    end
  end

  defp compile_pattern(_), do: nil

  defp compile_built_in_patterns do
    Enum.map(@built_in_patterns, fn raw ->
      %{
        name: raw.name,
        category: raw.category,
        severity: raw.severity,
        regex: Regex.compile!(raw.pattern),
        replacement_hint: raw.replacement_hint,
        max_match_bytes: raw.max_match_bytes,
        set: :secret
      }
    end)
  end

  defp valid_raw_pattern?(raw) when is_map(raw) do
    is_binary(extract_regex_source(raw)) and validate_pattern_metadata(raw) == :ok
  end

  defp valid_raw_pattern?(_), do: false

  defp build_compiled(raw, regex) do
    %{
      name: to_string(flex_get(raw, :name, "unnamed")),
      category: to_string(flex_get(raw, :category, "unknown")),
      severity: extract_severity(raw),
      regex: regex,
      replacement_hint: flex_get(raw, :replacement_hint),
      max_match_bytes: extract_max_match_bytes(raw),
      set: :secret
    }
  end

  # Bundle patterns MAY declare `max_match_bytes` in 1..4096 (SP.04); an absent,
  # out-of-range, or non-integer value defaults to 256.
  defp extract_max_match_bytes(raw) do
    case flex_fetch(raw, :max_match_bytes) do
      {:ok, value} when is_integer(value) and value >= 1 and value <= @max_match_bytes_limit ->
        value

      _ ->
        @default_max_match_bytes
    end
  end

  defp extract_regex_source(raw) do
    cond do
      Map.has_key?(raw, :pattern) -> raw[:pattern]
      Map.has_key?(raw, "regex") -> raw["regex"]
      true -> raw["pattern"]
    end
  end

  defp extract_severity(raw) do
    case flex_fetch(raw, :severity) do
      {:ok, severity} -> parse_severity(severity)
      :error -> :medium
    end
  end

  defp validate_pattern_metadata(raw) do
    with :ok <- validate_optional_binary(raw, :name),
         :ok <- validate_optional_binary(raw, :category),
         :ok <- validate_replacement_hint(raw) do
      validate_optional_severity(raw)
    end
  end

  defp validate_optional_binary(raw, key) do
    case flex_fetch(raw, key) do
      {:ok, value} when is_binary(value) -> :ok
      {:ok, _} -> :error
      :error -> :ok
    end
  end

  defp validate_replacement_hint(raw) do
    case flex_fetch(raw, :replacement_hint) do
      {:ok, value} when is_binary(value) or is_nil(value) -> :ok
      {:ok, _} -> :error
      :error -> :ok
    end
  end

  defp validate_optional_severity(raw) do
    case flex_fetch(raw, :severity) do
      {:ok, severity} -> if is_nil(parse_severity(severity)), do: :error, else: :ok
      :error -> :ok
    end
  end

  # Get a value from a map with atom or string keys.
  defp flex_get(raw, key, default \\ nil) do
    case flex_fetch(raw, key) do
      {:ok, value} -> value
      :error -> default
    end
  end

  defp flex_fetch(raw, key) do
    case Map.fetch(raw, key) do
      {:ok, value} -> {:ok, value}
      :error -> Map.fetch(raw, Atom.to_string(key))
    end
  end

  defp parse_severity(severity) when severity in [:low, :medium, :high], do: severity
  defp parse_severity("low"), do: :low
  defp parse_severity("medium"), do: :medium
  defp parse_severity("high"), do: :high
  defp parse_severity(_), do: nil
end
