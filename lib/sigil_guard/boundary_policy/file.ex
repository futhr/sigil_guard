defmodule SigilGuard.BoundaryPolicy.File do
  @moduledoc """
  Boundary-policy file grammar parser.

  Parses the 1.0 line-oriented policy file into a compiled `%File{}`: an ordered
  list of `[rules]`, an optional `default` verdict, the `[contracts]` section
  compiled by `SigilGuard.BoundaryPolicy.Contract` into a `%{sink => contract}`
  map, and the `[repo]` section compiled through `SigilGuard.RepoPolicy`.

  The mandatory first non-comment line is `version 3`. `#` starts a comment,
  blank lines are ignored, and inside `[rules]`/`[contracts]` a line beginning
  with whitespace continues the previous logical line (joined with one space).
  The `[repo]` body is passed to the repo-policy parser verbatim, with no folding.
  Files over 256 KiB fail `:policy_too_large`; any grammar violation fails
  `:invalid_policy_file`.
  """

  alias SigilGuard.BoundaryPolicy.Contract
  alias SigilGuard.RepoPolicy
  alias SigilGuard.Verdict

  @max_bytes 256 * 1024
  @version_line "version 3"

  @default_candidates [
    "SIGILGUARD_POLICY",
    ".sigilguard-policy",
    ".sigilguard/policy",
    ".github/sigilguard-policy"
  ]

  @legacy_replacements [
    {"SIGIL_POLICY", "SIGILGUARD_POLICY"},
    {".sigil-policy", ".sigilguard-policy"},
    {".sigil/policy", ".sigilguard/policy"},
    {".github/sigil-policy", ".github/sigilguard-policy"}
  ]
  @sections ~w([rules] [repo] [contracts])
  @section_regex ~r/^\[[a-z_]+\]$/
  @decisions ~w(allow redact confirm quarantine block)

  @string_matchers ~w(source tool actor)
  @none_sole_matchers ~w(hits indicator)

  @matcher_values %{
    "phase" =>
      ~w(session_start tool_request permission_requested permission_resolved tool_result file_changed model_ingress model_egress session_end),
    "origin" => ~w(unknown user model tool resource repo),
    "sink" => ~w(internal model user tool external network log repo),
    "zone" => ~w(trusted semi_trusted untrusted),
    "trust" => ~w(low medium high),
    "sensitivity" => ~w(public internal private),
    "isolation" => ~w(absent none container vm remote_attested),
    "effect" => ~w(read write execute network),
    "hits" => ~w(none any secret injection poisoning),
    "indicator" => ~w(none any injection poisoning)
  }

  @typedoc "A compiled `[rules]` rule: id, decision verdict, and AND-ed matchers."
  @type rule :: %{
          id: String.t(),
          decision: Verdict.t(),
          matchers: %{String.t() => [String.t()]}
        }

  @type parse_error ::
          :invalid_policy_file
          | :policy_too_large
          | :invalid_output_contract
          | :unknown_transform

  @type t :: %__MODULE__{
          rules: [rule()],
          default: Verdict.t() | nil,
          contracts: %{optional(String.t()) => Contract.t()},
          repo: RepoPolicy.t() | nil,
          digest: String.t() | nil
        }

  defstruct rules: [], default: nil, contracts: %{}, repo: nil, digest: nil

  @doc """
  Parse policy-file bytes into a compiled `%File{}`.
  """
  @spec parse(binary()) :: {:ok, t()} | {:error, parse_error()}
  def parse(bytes) when is_binary(bytes) do
    if byte_size(bytes) > @max_bytes do
      {:error, :policy_too_large}
    else
      parse_within_limit(bytes)
    end
  end

  def parse(_), do: {:error, :invalid_policy_file}

  defp parse_within_limit(bytes) do
    result =
      bytes
      |> String.split("\n")
      |> Enum.with_index(1)
      |> parse_lines()

    case result do
      {:ok, compiled} -> {:ok, %{compiled | digest: digest(bytes)}}
      error -> error
    end
  end

  @doc """
  Return the lowercase-hex SHA-256 over the raw policy-file bytes as read.

  The evidence digest is over raw bytes with no normalization, so it exists even
  for files that fail to parse and matches what `sha256sum` and git produce.
  """
  @spec digest(binary()) :: String.t()
  def digest(bytes) when is_binary(bytes) do
    Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)
  end

  @doc """
  Load and parse the repository's boundary-policy file.

  Candidate paths are checked in order: `SIGILGUARD_POLICY`,
  `.sigilguard-policy`, `.sigilguard/policy`, `.github/sigilguard-policy`. A
  legacy filename (`SIGIL_POLICY`, `.sigil-policy`, `.sigil/policy`,
  `.github/sigil-policy`) present under the repo root fails closed with
  `{:error, {:legacy_policy_filename, found, use}}` - even when a new-name file
  also exists. There is no silent fallback or coexistence; candidate paths
  resolve inside the repo root only.
  """
  @spec load(Path.t(), keyword()) ::
          {:ok, t()}
          | {:error,
             parse_error()
             | :not_found
             | {:legacy_policy_filename, Path.t(), Path.t()}}
  def load(repo_root, opts \\ []) when is_binary(repo_root) do
    root = Path.expand(repo_root)

    with :ok <- reject_legacy(root, opts) do
      candidates = Keyword.get(opts, :candidates, @default_candidates)

      case first_existing(root, candidates) do
        nil -> {:error, :not_found}
        path -> read_and_parse(path, opts)
      end
    end
  end

  defp reject_legacy(root, opts) do
    legacy = Keyword.get(opts, :legacy_replacements, @legacy_replacements)

    Enum.reduce_while(legacy, :ok, fn {found_name, use_name}, :ok ->
      path = Path.expand(found_name, root)

      if inside_root?(root, path) and safe_regular_candidate?(root, path) do
        {:halt, {:error, {:legacy_policy_filename, path, use_name}}}
      else
        {:cont, :ok}
      end
    end)
  end

  defp first_existing(root, candidates) do
    Enum.find_value(candidates, fn relative ->
      path = Path.expand(relative, root)
      if inside_root?(root, path) and safe_regular_candidate?(root, path), do: path
    end)
  end

  # sobelow_skip ["Traversal.FileModule"]
  defp read_and_parse(path, opts) do
    max_bytes = Keyword.get(opts, :max_bytes, @max_bytes)

    with {:ok, %{type: :regular, size: size}} <- File.stat(path),
         :ok <- within_size(size, max_bytes),
         {:ok, bytes} <- File.read(path) do
      parse(bytes)
    else
      {:error, :policy_too_large} -> {:error, :policy_too_large}
      _ -> {:error, :not_found}
    end
  end

  defp within_size(size, max_bytes) when size <= max_bytes, do: :ok
  defp within_size(_, _), do: {:error, :policy_too_large}

  defp inside_root?(root, path) do
    path == root or String.starts_with?(path, root <> "/")
  end

  defp safe_regular_candidate?(root, path) do
    path
    |> Path.relative_to(root)
    |> Path.split()
    |> Enum.reduce_while(root, fn segment, current ->
      candidate = Path.join(current, segment)

      case File.lstat(candidate) do
        {:ok, %{type: :symlink}} -> {:halt, false}
        {:ok, _} -> {:cont, candidate}
        {:error, _} -> {:halt, false}
      end
    end)
    |> then(&(&1 == path and File.regular?(path)))
  end

  defp parse_lines(numbered) do
    with {:ok, rest} <- expect_version(numbered),
         {:ok, acc} <- walk_sections(rest, new_acc()) do
      finalize(acc)
    end
  end

  defp expect_version(numbered) do
    case skip_ignored(numbered) do
      [{line, _} | rest] ->
        if strip(line) == @version_line, do: {:ok, rest}, else: {:error, :invalid_policy_file}

      [] ->
        {:error, :invalid_policy_file}
    end
  end

  defp walk_sections([], acc), do: {:ok, acc}

  defp walk_sections(numbered, acc) do
    case skip_ignored(numbered) do
      [] ->
        {:ok, acc}

      [{line, _} | rest] ->
        header = strip(line)

        cond do
          header == "[repo]" -> take_repo(rest, acc)
          header in @sections -> take_folded_section(header, rest, acc)
          section_header?(header) -> {:error, :invalid_policy_file}
          true -> {:error, :invalid_policy_file}
        end
    end
  end

  defp take_repo(_, %{repo: repo}) when repo != nil, do: {:error, :invalid_policy_file}

  defp take_repo(numbered, acc) do
    {body, rest} =
      Enum.split_while(numbered, fn {line, _} -> not section_header?(strip(line)) end)

    text = Enum.map_join(body, "\n", fn {line, _} -> line end)

    case RepoPolicy.parse(text) do
      {:ok, repo} -> walk_sections(rest, %{acc | repo: repo})
      {:error, _} -> {:error, :invalid_policy_file}
    end
  end

  defp take_folded_section(header, numbered, acc) do
    if section_seen?(acc, header) do
      {:error, :invalid_policy_file}
    else
      {body, rest} =
        Enum.split_while(numbered, fn {line, _} -> not section_header?(strip(line)) end)

      logical = fold(body)

      with {:ok, acc} <- ingest_section(header, logical, mark_seen(acc, header)) do
        walk_sections(rest, acc)
      end
    end
  end

  defp ingest_section("[rules]", logical, acc) do
    Enum.reduce_while(logical, {:ok, acc}, fn {text, n}, {:ok, acc} ->
      case rules_line(text, n, acc) do
        {:ok, acc} -> {:cont, {:ok, acc}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp ingest_section("[contracts]", logical, acc) do
    case Contract.parse(Enum.map(logical, fn {text, _} -> text end)) do
      {:ok, contracts} -> {:ok, %{acc | contracts: contracts}}
      {:error, reason} -> {:error, reason}
    end
  end

  defp rules_line("default " <> rest, _, acc) do
    cond do
      acc.default != nil -> {:error, :invalid_policy_file}
      strip(rest) in @decisions -> {:ok, %{acc | default: String.to_existing_atom(strip(rest))}}
      true -> {:error, :invalid_policy_file}
    end
  end

  defp rules_line(text, n, acc) do
    [decision | matcher_tokens] = String.split(text, " ", trim: true)

    with true <- decision in @decisions,
         {:ok, matchers} <- parse_matchers(matcher_tokens) do
      rule = %{id: "line_#{n}", decision: String.to_existing_atom(decision), matchers: matchers}
      {:ok, %{acc | rules: [rule | acc.rules]}}
    else
      _ -> {:error, :invalid_policy_file}
    end
  end

  defp parse_matchers(tokens) do
    Enum.reduce_while(tokens, {:ok, %{}}, fn token, {:ok, matchers} ->
      case parse_matcher(token, matchers) do
        {:ok, matchers} -> {:cont, {:ok, matchers}}
        :error -> {:halt, :error}
      end
    end)
  end

  defp parse_matcher(token, matchers) do
    case String.split(token, ":", parts: 2) do
      [key, raw_values] -> parse_matcher(key, raw_values, matchers)
      _ -> :error
    end
  end

  defp parse_matcher(key, raw_values, matchers) do
    values = String.split(raw_values, ",", trim: false)

    with false <- Map.has_key?(matchers, key),
         true <- valid_values?(key, values) do
      {:ok, Map.put(matchers, key, values)}
    else
      _ -> :error
    end
  end

  defp valid_values?(_, []), do: false
  defp valid_values?(_, values) when values == [""], do: false

  defp valid_values?(key, values) do
    Enum.all?(values, &(&1 != "")) and
      not none_violation?(key, values) and
      Enum.all?(values, &valid_value?(key, &1))
  end

  defp none_violation?(key, values) do
    key in @none_sole_matchers and "none" in values and length(values) > 1
  end

  defp valid_value?(key, _) when key in @string_matchers, do: true

  defp valid_value?(key, value) do
    case Map.fetch(@matcher_values, key) do
      {:ok, allowed} -> value in allowed
      :error -> false
    end
  end

  defp fold(numbered) do
    numbered
    |> Enum.reduce([], fn {raw, n}, acc ->
      content = strip_comment(raw)

      cond do
        strip(content) == "" -> acc
        continuation?(raw) and acc != [] -> fold_append(acc, strip(content))
        true -> [{strip(content), n} | acc]
      end
    end)
    |> Enum.reverse()
  end

  defp fold_append([{text, n} | rest], addition), do: [{text <> " " <> addition, n} | rest]

  defp continuation?(raw), do: raw != "" and String.first(raw) in [" ", "\t"]

  defp skip_ignored(numbered) do
    Enum.drop_while(numbered, fn {line, _} -> strip(strip_comment(line)) == "" end)
  end

  defp strip_comment(line) do
    hd(String.split(line, "#", parts: 2))
  end

  defp strip(line), do: String.trim(line)

  defp section_header?(line), do: Regex.match?(@section_regex, line)

  defp new_acc, do: %{rules: [], default: nil, contracts: %{}, repo: nil, seen: MapSet.new()}

  defp section_seen?(acc, header), do: MapSet.member?(acc.seen, header)
  defp mark_seen(acc, header), do: %{acc | seen: MapSet.put(acc.seen, header)}

  defp finalize(acc) do
    {:ok,
     %__MODULE__{
       rules: Enum.reverse(acc.rules),
       default: acc.default,
       contracts: acc.contracts,
       repo: acc.repo
     }}
  end
end
