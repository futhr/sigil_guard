defmodule SigilGuard.Patterns do
  @moduledoc """
  Pattern compilation and management for sensitivity scanning.

  Provides built-in patterns for common credential and secret formats,
  plus support for loading patterns from SIGIL registry bundles.

  ## Built-in Patterns

  The following patterns are included by default (no registry dependency):

    * AWS access keys (`AKIA`, `ABIA`, `ACCA`, `ASIA` prefixes)
    * Generic API key assignments
    * Bearer tokens
    * Database connection URIs (PostgreSQL, MySQL, MongoDB)
    * Private key headers (RSA, EC, OpenSSH)
    * Generic secret/password/token assignments

  ## Registry Patterns

  When the SIGIL registry is enabled, patterns from `GET /patterns/bundle`
  are merged with built-in patterns. Registry patterns take precedence
  on name collision.
  """

  @type scan_hit :: %{
          name: String.t(),
          category: String.t(),
          severity: :low | :medium | :high | :critical,
          match: String.t(),
          offset: non_neg_integer(),
          length: non_neg_integer(),
          replacement_hint: String.t() | nil
        }

  @type compiled_pattern :: %{
          name: String.t(),
          category: String.t(),
          severity: :low | :medium | :high | :critical,
          regex: Regex.t(),
          replacement_hint: String.t() | nil
        }

  @built_in_patterns [
    %{
      name: "aws_access_key",
      category: "credential",
      severity: :critical,
      pattern: "(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}",
      replacement_hint: "[AWS_KEY]"
    },
    %{
      name: "generic_api_key",
      category: "credential",
      severity: :high,
      pattern: "(?i)(api[_\\-]?key|apikey)\\s*[:=]\\s*['\"]?[\\w\\-]{20,}",
      replacement_hint: "[API_KEY]"
    },
    %{
      name: "bearer_token",
      category: "credential",
      severity: :high,
      pattern: "(?i)bearer\\s+[a-zA-Z0-9._~+/=\\-]{20,}",
      replacement_hint: "[BEARER_TOKEN]"
    },
    %{
      name: "database_uri",
      category: "credential",
      severity: :critical,
      pattern: "(?i)(postgres|mysql|mongodb)://[^:]+:[^@]+@",
      replacement_hint: "[DATABASE_URI]"
    },
    %{
      name: "private_key",
      category: "credential",
      severity: :critical,
      pattern: "-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
      replacement_hint: "[PRIVATE_KEY]"
    },
    %{
      name: "generic_secret",
      category: "credential",
      severity: :medium,
      pattern: "(?i)(secret|password|token|credential)\\s*[:=]\\s*['\"]?[^\\s'\"]{8,}",
      replacement_hint: "[SECRET]"
    }
  ]

  @doc "Return compiled built-in patterns."
  @spec built_in() :: [compiled_pattern()]
  def built_in do
    Enum.map(@built_in_patterns, &compile_pattern/1)
  end

  @doc """
  Compile a list of raw pattern maps into executable patterns.

  Accepts both built-in format (with `:pattern` key) and registry bundle
  format (with `"regex"` key).
  """
  @spec compile([map()]) :: [compiled_pattern()]
  def compile(raw_patterns) do
    raw_patterns
    |> Enum.map(&compile_pattern/1)
    |> Enum.reject(&is_nil/1)
  end

  @doc """
  Parse a SIGIL registry bundle response into pattern maps.

  Expected format:
  ```json
  {"generated_at": "...", "count": 5, "patterns": [...]}
  ```
  """
  @spec parse_bundle(map()) :: {:ok, [map()]} | {:error, term()}
  def parse_bundle(%{"patterns" => patterns}) when is_list(patterns) do
    {:ok, patterns}
  end

  def parse_bundle(_other), do: {:error, :invalid_bundle_format}

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

  defp compile_pattern(raw) do
    case Regex.compile(extract_regex_source(raw)) do
      {:ok, regex} -> build_compiled(raw, regex)
      {:error, _reason} -> nil
    end
  end

  defp build_compiled(raw, regex) do
    %{
      name: to_string(flex_get(raw, :name, "unnamed")),
      category: to_string(flex_get(raw, :category, "unknown")),
      severity: extract_severity(raw),
      regex: regex,
      replacement_hint: flex_get(raw, :replacement_hint)
    }
  end

  defp extract_regex_source(raw) do
    raw[:pattern] || raw["regex"] || raw["pattern"]
  end

  defp extract_severity(raw) do
    raw[:severity] || parse_severity(raw["severity"]) || :medium
  end

  # Get a value from a map with atom or string keys.
  defp flex_get(raw, key, default \\ nil) do
    raw[key] || raw[Atom.to_string(key)] || default
  end

  defp parse_severity("low"), do: :low
  defp parse_severity("medium"), do: :medium
  defp parse_severity("high"), do: :high
  defp parse_severity("critical"), do: :critical
  defp parse_severity(_other), do: nil
end
