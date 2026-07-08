defmodule SigilGuard.RepoPolicy do
  @moduledoc """
  Deterministic repo-level policy kernel for agent-authored changes.

  This module adds a repo-level policy layer to SigilGuard: it evaluates an
  agent identity, action, and changed file paths against ordered path rules and
  returns one of three governance decisions:

    * `:allow`
    * `:require_approval`
    * `:block`

  Policies are data, not code. A policy can be compiled from maps, keyword
  lists, or a small line-oriented format:

      default require_approval
      allow agent:did:web:codex action:modify README.md docs/**
      require_approval agent:* config/** .github/**
      block agent:* priv/secrets/**

  Matching is intentionally deterministic and conservative:

    * changed paths must be safe relative paths; absolute paths and `..` are
      blocked before rule matching
    * rules only match exact agents/actions or `*`
    * path globs support `*`, `?`, and `**`
    * `:block` beats `:require_approval`, which beats `:allow`
    * if any path is unmatched, the policy default applies

  This is not a replacement for human code review. It is a deterministic
  preflight boundary that makes repo modification authority explicit.
  """

  alias SigilGuard.RepoPolicy.Decision

  @version 1
  @default_decision :require_approval
  @default_policy_paths [
    "SIGILGUARD_POLICY",
    ".sigilguard-policy",
    ".sigilguard/policy",
    ".github/sigilguard-policy"
  ]

  @legacy_policy_replacements [
    {"SIGIL_POLICY", "SIGILGUARD_POLICY"},
    {".sigil-policy", ".sigilguard-policy"},
    {".sigil/policy", ".sigilguard/policy"},
    {".github/sigil-policy", ".github/sigilguard-policy"}
  ]
  @default_max_policy_bytes 262_144
  @decisions [:allow, :require_approval, :block]
  @decision_rank %{allow: 0, require_approval: 1, block: 2}
  @atom_fields %{
    "action" => :action,
    "actions" => :actions,
    "actor" => :actor,
    "agent" => :agent,
    "agents" => :agents,
    "changed_files" => :changed_files,
    "changed_paths" => :changed_paths,
    "decision" => :decision,
    "default" => :default,
    "files" => :files,
    "id" => :id,
    "identity" => :identity,
    "message" => :message,
    "path" => :path,
    "paths" => :paths,
    "rules" => :rules
  }

  @type verdict :: Decision.verdict()

  @type rule :: %{
          id: String.t(),
          decision: verdict(),
          agents: [String.t()],
          actions: [String.t()],
          paths: [String.t()],
          path_matchers: [term()],
          message: String.t() | nil,
          index: non_neg_integer()
        }

  @type t :: %__MODULE__{
          version: pos_integer(),
          default: verdict(),
          rules: [rule()]
        }

  defstruct version: @version, default: @default_decision, rules: []

  @doc """
  Compile a raw repo policy map or keyword list.

  Rule fields accept atom or string keys:

    * `:id` - stable rule identifier. Defaults to `"rule_<index>"`.
    * `:decision` - `:allow`, `:require_approval`, or `:block`.
    * `:agents` - exact agent identifiers or `"*"`.
    * `:actions` - exact action names or `"*"`.
    * `:paths` - safe relative path globs.
    * `:message` - optional operator-facing reason.
  """
  @spec compile(t() | map() | keyword()) :: {:ok, t()} | {:error, atom() | {atom(), term()}}
  def compile(%__MODULE__{} = policy) do
    with {:ok, rules} <- ensure_compiled_rules(policy.rules) do
      {:ok, %{policy | rules: rules}}
    end
  end

  def compile(raw) when is_list(raw) do
    try do
      raw
      |> Map.new()
      |> compile()
    rescue
      ArgumentError -> {:error, :invalid_policy}
    end
  end

  def compile(raw) when is_map(raw) do
    with {:ok, default} <-
           normalize_decision(field_or_default(raw, "default", @default_decision)),
         {:ok, rules} <- compile_rules(field_or_default(raw, "rules", [])) do
      {:ok, %__MODULE__{default: default, rules: rules}}
    end
  end

  def compile(_), do: {:error, :invalid_policy}

  @doc """
  Parse a line-oriented policy document and compile it.

  Supported lines:

      default require_approval
      allow agent:did:web:codex action:modify docs/**
      block agent:* priv/secrets/**

  Lines starting with `#` and blank lines are ignored.
  """
  @spec parse(String.t()) :: {:ok, t()} | {:error, atom() | {atom(), term()}}
  def parse(text) when is_binary(text) do
    result =
      text
      |> String.split("\n")
      |> Enum.with_index(1)
      |> Enum.reduce_while({:ok, %{default: @default_decision, rules: []}}, &parse_line/2)

    case result do
      {:ok, policy} -> compile(%{policy | rules: Enum.reverse(policy.rules)})
      error -> error
    end
  end

  @doc """
  Load the first policy file found under a repo root.

  By default the loader checks these repo-relative paths in order:

    * `SIGILGUARD_POLICY`
    * `.sigilguard-policy`
    * `.sigilguard/policy`
    * `.github/sigilguard-policy`

  Legacy policy filenames fail closed with
  `{:error, {:legacy_policy_filename, found, use}}`. Legacy files are never
  parsed and never silently used as fallbacks, including when a 1.0 policy file
  is also present.

  Options:

    * `:candidates` - override the repo-relative candidate paths.
    * `:max_bytes` - maximum policy file size. Defaults to 256 KiB.
  """
  @spec load(Path.t(), keyword()) :: {:ok, t()} | {:error, term()}
  def load(repo_root, opts \\ []) when is_binary(repo_root) do
    with {:ok, path} <- find_file(repo_root, opts) do
      load_file(path, opts)
    end
  end

  @doc """
  Return the first policy file path found under a repo root.

  Candidate paths must be safe relative paths. Absolute paths and traversal are
  rejected before any filesystem lookup.
  """
  @spec find_file(Path.t(), keyword()) :: {:ok, Path.t()} | {:error, term()}
  def find_file(repo_root, opts \\ []) when is_binary(repo_root) do
    root = Path.expand(repo_root)

    with :ok <- reject_legacy_policy_paths(root),
         {:ok, candidates} <-
           normalize_policy_paths(Keyword.get(opts, :candidates, @default_policy_paths)) do
      case first_existing_policy_path(root, candidates) do
        nil -> {:error, :not_found}
        path -> {:ok, path}
      end
    end
  end

  @doc """
  Load a policy from a specific file path.

  The file must be regular and no larger than `:max_bytes`.
  """
  @spec load_file(Path.t(), keyword()) :: {:ok, t()} | {:error, term()}
  # sobelow_skip ["Traversal.FileModule"]
  def load_file(path, opts \\ []) when is_binary(path) do
    path = Path.expand(path)

    with {:ok, max_bytes} <-
           normalize_max_bytes(Keyword.get(opts, :max_bytes, @default_max_policy_bytes)),
         :ok <- ensure_policy_file(path, max_bytes),
         {:ok, text} <- File.read(path) do
      parse(text)
    end
  end

  @doc """
  Evaluate a compiled policy against a repo-change context.

  Context fields accept atom or string keys:

    * `:agent`, `:identity`, or `:actor`
    * `:action`
    * `:changed_paths`, `:changed_files`, `:files`, or `:paths`
  """
  @spec evaluate(t(), map() | keyword()) :: Decision.t()
  def evaluate(%__MODULE__{} = policy, context) do
    context = context_map(context)

    case context_string(context, ~w(agent identity actor), :invalid_agent) do
      {:ok, agent} ->
        evaluate_with_agent(policy, context, agent)

      {:error, reason} ->
        invalid_context_decision(nil, "invalid", reason)
    end
  end

  @doc """
  Return canonical bytes for a compiled policy.
  """
  @spec canonical_bytes(t()) :: binary()
  def canonical_bytes(%__MODULE__{} = policy) do
    policy
    |> canonical_map()
    |> canonical_iodata()
    |> IO.iodata_to_binary()
  end

  @doc """
  Return a lowercase SHA-256 digest of a compiled policy.
  """
  @spec digest(t()) :: String.t()
  def digest(%__MODULE__{} = policy) do
    policy
    |> canonical_bytes()
    |> sha256_hex()
  end

  @doc """
  Build the SP.11 policy-facts map from a compiled policy and a decision.

  This is the exact shape the repo kernel contributes to
  `SigilGuard.BoundaryPolicy` and to `repo_change` audit evidence: the repo
  `verdict`, one `matched_rules` entry per applied rule (its `rule_id` and the
  rule `message`, else the decision `reason`), the `unmatched_paths` governed
  by the default, the compiled-policy `policy_file_digest`, and the
  `default_decision`.
  """
  @spec policy_facts(t(), Decision.t()) :: %{
          verdict: Decision.verdict(),
          matched_rules: [%{rule_id: String.t(), explanation: String.t()}],
          unmatched_paths: [String.t()],
          policy_file_digest: String.t(),
          default_decision: Decision.verdict()
        }
  def policy_facts(%__MODULE__{} = policy, %Decision{} = decision) do
    %{
      verdict: decision.verdict,
      matched_rules: matched_rule_facts(policy, decision),
      unmatched_paths: decision.unmatched_paths,
      policy_file_digest: digest(policy),
      default_decision: policy.default
    }
  end

  defp matched_rule_facts(policy, decision) do
    by_id = Map.new(policy.rules, &{&1.id, &1})

    Enum.map(decision.matched_rule_ids, fn id ->
      %{rule_id: id, explanation: rule_explanation(Map.get(by_id, id), decision)}
    end)
  end

  defp rule_explanation(%{message: message}, _) when is_binary(message), do: message
  defp rule_explanation(_, decision), do: decision.reason

  defp compile_rules(rules) when is_list(rules) do
    result =
      rules
      |> Enum.with_index()
      |> Enum.reduce_while({:ok, []}, fn {rule, index}, {:ok, acc} ->
        case compile_rule(rule, index) do
          {:ok, compiled} -> {:cont, {:ok, [compiled | acc]}}
          {:error, reason} -> {:halt, {:error, {reason, index}}}
        end
      end)

    case result do
      {:ok, compiled} -> {:ok, Enum.reverse(compiled)}
      error -> error
    end
  end

  defp compile_rules(_), do: {:error, :invalid_rules}

  defp ensure_compiled_rules(rules) when is_list(rules) do
    result =
      rules
      |> Enum.with_index()
      |> Enum.reduce_while({:ok, []}, fn {rule, index}, {:ok, acc} ->
        case ensure_compiled_rule(rule, index) do
          {:ok, compiled} -> {:cont, {:ok, [compiled | acc]}}
          {:error, reason} -> {:halt, {:error, reason}}
        end
      end)

    case result do
      {:ok, compiled} -> {:ok, Enum.reverse(compiled)}
      error -> error
    end
  end

  defp ensure_compiled_rules(_), do: {:error, :invalid_rules}

  defp ensure_compiled_rule(%{path_matchers: path_matchers} = rule, _)
       when is_list(path_matchers),
       do: {:ok, rule}

  defp ensure_compiled_rule(%{paths: paths} = rule, _) do
    with {:ok, path_matchers} <- compile_path_matchers(paths) do
      {:ok, Map.put(rule, :path_matchers, path_matchers)}
    end
  end

  defp ensure_compiled_rule(_, index), do: compile_rule(nil, index)

  defp compile_rule(raw, index) when is_list(raw) do
    raw
    |> Map.new()
    |> compile_rule(index)
  end

  defp compile_rule(raw, index) when is_map(raw) do
    with {:ok, decision} <- normalize_decision(field(raw, "decision")),
         {:ok, agents} <-
           normalize_matchers(field_or_default(raw, ["agents", "agent"], ["*"])),
         {:ok, actions} <-
           normalize_matchers(field_or_default(raw, ["actions", "action"], ["*"])),
         {:ok, paths} <- normalize_patterns(field_or_default(raw, ["paths", "path"], nil)),
         {:ok, path_matchers} <- compile_path_matchers(paths),
         {:ok, id} <- normalize_id(field(raw, "id"), index) do
      {:ok,
       %{
         id: id,
         decision: decision,
         agents: agents,
         actions: actions,
         paths: paths,
         path_matchers: path_matchers,
         message: optional_string(field(raw, "message")),
         index: index
       }}
    end
  end

  defp compile_rule(_, _), do: {:error, :invalid_rule}

  defp parse_line({line, line_no}, {:ok, policy}) do
    line =
      line
      |> strip_comment()
      |> String.trim()

    cond do
      line == "" ->
        {:cont, {:ok, policy}}

      String.starts_with?(line, "default ") ->
        parse_default(line, policy)

      true ->
        parse_rule(line, line_no, policy)
    end
  end

  defp parse_line(_, error), do: {:halt, error}

  defp parse_default(line, policy) do
    [_, decision | _] = String.split(line)

    case normalize_decision(decision) do
      {:ok, normalized} -> {:cont, {:ok, %{policy | default: normalized}}}
      {:error, reason} -> {:halt, {:error, reason}}
    end
  end

  defp parse_rule(line, line_no, policy) do
    [decision | tokens] = String.split(line)

    {fields, paths} =
      Enum.reduce(tokens, {%{}, []}, fn token, {fields, paths} ->
        cond do
          String.starts_with?(token, "agent:") ->
            {Map.put(fields, :agents, split_csv(String.replace_prefix(token, "agent:", ""))),
             paths}

          String.starts_with?(token, "action:") ->
            {Map.put(fields, :actions, split_csv(String.replace_prefix(token, "action:", ""))),
             paths}

          true ->
            {fields, [token | paths]}
        end
      end)

    rule =
      fields
      |> Map.put(:decision, decision)
      |> Map.put(:paths, Enum.reverse(paths))
      |> Map.put(:id, "line_#{line_no}")

    {:cont, {:ok, %{policy | rules: [rule | policy.rules]}}}
  end

  defp strip_comment(line) do
    line
    |> String.split("#", parts: 2)
    |> hd()
  end

  defp split_csv(value) do
    value
    |> String.split(",", trim: true)
    |> Enum.map(&String.trim/1)
  end

  defp evaluate_paths(policy, agent, action, paths) do
    matches = matching_rules(policy.rules, agent, action, paths)
    unmatched = unmatched_paths(paths, matches)
    strongest = strongest_decision(matches)
    verdict = final_verdict(strongest, unmatched, policy.default)

    build_decision(%{
      verdict: verdict,
      reason: reason(verdict, matches, unmatched, policy.default),
      agent: agent,
      action: action,
      changed_paths: paths,
      matched_rule_ids: matched_rule_ids(matches),
      unmatched_paths: unmatched
    })
  end

  defp matching_rules(rules, agent, action, paths) do
    for rule <- rules,
        path <- paths,
        rule_matches?(rule, agent, action, path),
        do: {rule, path}
  end

  defp unmatched_paths(paths, matches) do
    matched_paths =
      matches
      |> Enum.map(&elem(&1, 1))
      |> MapSet.new()

    Enum.reject(paths, &MapSet.member?(matched_paths, &1))
  end

  defp strongest_decision([]), do: nil

  defp strongest_decision(matches) do
    matches
    |> Enum.map(fn {rule, _} -> rule.decision end)
    |> Enum.max_by(&Map.fetch!(@decision_rank, &1))
  end

  defp final_verdict(:block, _, _), do: :block
  defp final_verdict(:require_approval, _, _), do: :require_approval
  defp final_verdict(_, [_ | _], default), do: default
  defp final_verdict(:allow, [], _), do: :allow
  defp final_verdict(nil, [], default), do: default

  defp reason(:block, matches, _, _) do
    "Repo policy blocked by #{rule_summary(matches)}"
  end

  defp reason(:require_approval, _, unmatched, _) when unmatched != [] do
    "Repo policy requires approval for unmatched paths"
  end

  defp reason(:require_approval, matches, _, _) do
    "Repo policy requires approval by #{rule_summary(matches)}"
  end

  defp reason(:allow, _, [], _), do: "Repo policy allowed all changed paths"

  defp reason(:allow, _, unmatched, :allow) when unmatched != [] do
    "Repo policy default allowed unmatched paths"
  end

  defp rule_summary(matches) do
    matches
    |> matched_rule_ids()
    |> Enum.join(", ")
  end

  defp matched_rule_ids(matches) do
    matches
    |> Enum.map(fn {rule, _} -> {rule.index, rule.id} end)
    |> Enum.uniq()
    |> Enum.sort_by(&elem(&1, 0))
    |> Enum.map(&elem(&1, 1))
  end

  defp rule_matches?(rule, agent, action, path) do
    matcher_matches?(rule.agents, agent) and
      matcher_matches?(rule.actions, action) and
      Enum.any?(rule.path_matchers, &path_matches?(&1, path))
  end

  defp matcher_matches?(matchers, nil), do: "*" in matchers
  defp matcher_matches?(matchers, value), do: "*" in matchers or value in matchers

  defp path_matches?(matcher, path) do
    match_segments?(matcher, String.split(path, "/", trim: true))
  end

  defp match_segments?([], []), do: true
  defp match_segments?([], _), do: false
  defp match_segments?([:globstar], _), do: true

  defp match_segments?([:globstar | pattern_rest] = pattern, path) do
    match_segments?(pattern_rest, path) or
      case path do
        [] -> false
        [_ | path_rest] -> match_segments?(pattern, path_rest)
      end
  end

  defp match_segments?([matcher_segment | pattern_rest], [path_segment | path_rest]) do
    segment_matches?(matcher_segment, path_segment) and match_segments?(pattern_rest, path_rest)
  end

  defp match_segments?(_, _), do: false

  defp segment_matches?({:literal, expected}, segment), do: segment == expected
  defp segment_matches?({:regex, regex}, segment), do: Regex.match?(regex, segment)

  defp normalize_decision(value) when value in @decisions, do: {:ok, value}
  defp normalize_decision(:allowed), do: {:ok, :allow}
  defp normalize_decision(:blocked), do: {:ok, :block}
  defp normalize_decision(:confirm), do: {:ok, :require_approval}

  defp normalize_decision(value) when is_binary(value) do
    case String.downcase(value) do
      "allow" -> {:ok, :allow}
      "allowed" -> {:ok, :allow}
      "block" -> {:ok, :block}
      "blocked" -> {:ok, :block}
      "require_approval" -> {:ok, :require_approval}
      "require-approval" -> {:ok, :require_approval}
      "confirm" -> {:ok, :require_approval}
      _ -> {:error, :invalid_decision}
    end
  end

  defp normalize_decision(_), do: {:error, :invalid_decision}

  defp normalize_matchers(value) when is_binary(value), do: normalize_matchers([value])

  defp normalize_matchers(value) when is_atom(value) and not is_boolean(value),
    do: normalize_matchers([value])

  defp normalize_matchers(values) when is_list(values) do
    result =
      Enum.reduce_while(values, {:ok, []}, fn value, {:ok, acc} ->
        case normalize_matcher(value) do
          {:ok, matcher} -> {:cont, {:ok, [matcher | acc]}}
          {:error, reason} -> {:halt, {:error, reason}}
        end
      end)

    case result do
      {:ok, []} ->
        {:error, :invalid_matchers}

      {:ok, normalized} ->
        normalized =
          normalized
          |> Enum.reverse()
          |> Enum.uniq()

        {:ok, normalized}

      error ->
        error
    end
  end

  defp normalize_matchers(_), do: {:error, :invalid_matchers}

  defp normalize_matcher(value) when is_atom(value) and not is_boolean(value),
    do: {:ok, Atom.to_string(value)}

  defp normalize_matcher(value) when is_binary(value) do
    case String.trim(value) do
      "" -> {:error, :invalid_matchers}
      matcher -> {:ok, matcher}
    end
  end

  defp normalize_matcher(_), do: {:error, :invalid_matchers}

  defp normalize_patterns(value) when is_binary(value), do: normalize_patterns([value])

  defp normalize_patterns(values) when is_list(values) do
    result =
      Enum.reduce_while(values, {:ok, []}, fn pattern, {:ok, acc} ->
        case normalize_pattern(pattern) do
          {:ok, normalized} -> {:cont, {:ok, [normalized | acc]}}
          {:error, reason} -> {:halt, {:error, reason}}
        end
      end)

    case result do
      {:ok, []} -> {:error, :missing_paths}
      {:ok, patterns} -> {:ok, Enum.reverse(patterns)}
      error -> error
    end
  end

  defp normalize_patterns(_), do: {:error, :missing_paths}

  defp compile_path_matchers(paths) when is_list(paths) do
    result =
      Enum.reduce_while(paths, {:ok, []}, fn path, {:ok, acc} ->
        case compile_path_matcher(path) do
          {:ok, matcher} -> {:cont, {:ok, [matcher | acc]}}
          {:error, reason} -> {:halt, {:error, reason}}
        end
      end)

    case result do
      {:ok, matchers} -> {:ok, Enum.reverse(matchers)}
      error -> error
    end
  end

  defp compile_path_matchers(_), do: {:error, :missing_paths}

  defp compile_path_matcher(pattern) when is_binary(pattern) do
    {:ok,
     pattern
     |> String.split("/", trim: true)
     |> Enum.map(&compile_segment_matcher/1)}
  end

  defp compile_path_matcher(_), do: {:error, :invalid_path_pattern}

  defp compile_segment_matcher("**"), do: :globstar

  defp compile_segment_matcher(segment) do
    if String.contains?(segment, ["*", "?"]) do
      regex =
        segment
        |> Regex.escape()
        |> String.replace("\\*", ".*")
        |> String.replace("\\?", ".")
        |> then(&"^#{&1}$")
        |> Regex.compile!()

      {:regex, regex}
    else
      {:literal, segment}
    end
  end

  defp normalize_policy_paths(paths) when is_binary(paths), do: normalize_policy_paths([paths])

  defp normalize_policy_paths(paths) when is_list(paths) do
    result =
      Enum.reduce_while(paths, {:ok, []}, fn path, {:ok, acc} ->
        case normalize_policy_path(path) do
          {:ok, normalized} -> {:cont, {:ok, [normalized | acc]}}
          {:error, reason} -> {:halt, {:error, reason}}
        end
      end)

    case result do
      {:ok, []} -> {:error, :missing_policy_paths}
      {:ok, normalized} -> {:ok, Enum.reverse(normalized)}
      error -> error
    end
  end

  defp normalize_policy_paths(_), do: {:error, :invalid_policy_paths}

  defp normalize_policy_path(path) when is_binary(path) do
    path = normalize_separators(String.trim(path))

    cond do
      path == "" -> {:error, :invalid_policy_path}
      absolute_path?(path) -> {:error, :absolute_policy_path}
      traversal_path?(path) -> {:error, :policy_path_traversal}
      true -> {:ok, collapse_relative(path)}
    end
  end

  defp normalize_policy_path(_), do: {:error, :invalid_policy_path}

  defp reject_legacy_policy_paths(root) do
    Enum.reduce_while(@legacy_policy_replacements, :ok, fn {legacy, replacement}, :ok ->
      path = Path.expand(legacy, root)

      if inside_root?(root, path) and File.regular?(path) do
        {:halt, {:error, {:legacy_policy_filename, path, replacement}}}
      else
        {:cont, :ok}
      end
    end)
  end

  defp normalize_pattern(pattern) when is_binary(pattern) do
    pattern = String.trim(pattern)

    cond do
      pattern == "" -> {:error, :invalid_path_pattern}
      absolute_path?(pattern) -> {:error, :absolute_path_pattern}
      traversal_path?(pattern) -> {:error, :path_traversal_pattern}
      String.ends_with?(pattern, "/") -> {:ok, normalize_separators(pattern) <> "**"}
      true -> {:ok, normalize_separators(pattern)}
    end
  end

  defp normalize_pattern(_), do: {:error, :invalid_path_pattern}

  defp normalize_changed_paths(path) when is_binary(path), do: normalize_changed_paths([path])

  defp normalize_changed_paths(paths) when is_list(paths) do
    result =
      Enum.reduce_while(paths, {:ok, []}, fn path, {:ok, acc} ->
        case normalize_changed_path(path) do
          {:ok, normalized} -> {:cont, {:ok, [normalized | acc]}}
          {:error, reason} -> {:halt, {:error, reason}}
        end
      end)

    case result do
      {:ok, normalized} ->
        normalized =
          normalized
          |> Enum.reverse()
          |> Enum.uniq()

        {:ok, normalized}

      error ->
        error
    end
  end

  defp normalize_changed_paths(_), do: {:error, :invalid_changed_paths}

  defp normalize_changed_path(path) when is_binary(path) do
    path = normalize_separators(String.trim(path))

    cond do
      path == "" -> {:error, :invalid_changed_path}
      absolute_path?(path) -> {:error, :absolute_changed_path}
      traversal_path?(path) -> {:error, :path_traversal}
      true -> {:ok, collapse_relative(path)}
    end
  end

  defp normalize_changed_path(_), do: {:error, :invalid_changed_path}

  defp normalize_separators(path), do: String.replace(path, "\\", "/")

  defp absolute_path?(path), do: String.starts_with?(path, "/")

  defp traversal_path?(path) do
    path
    |> String.split("/", trim: true)
    |> Enum.any?(&(&1 == ".."))
  end

  defp collapse_relative(path) do
    segments =
      path
      |> String.split("/", trim: true)
      |> Enum.reject(&(&1 == "."))

    case segments do
      [] -> "."
      segments -> Enum.join(segments, "/")
    end
  end

  defp first_existing_policy_path(root, candidates) do
    Enum.find_value(candidates, fn relative ->
      path = Path.expand(relative, root)

      if inside_root?(root, path) and File.regular?(path) do
        path
      end
    end)
  end

  defp inside_root?(root, path) do
    root = Path.expand(root)
    path = Path.expand(path)
    root_prefix = root <> "/"

    path == root or String.starts_with?(path, root_prefix)
  end

  defp ensure_policy_file(path, max_bytes) do
    case File.stat(path) do
      {:ok, %{type: :regular, size: size}} when size <= max_bytes -> :ok
      {:ok, %{type: :regular}} -> {:error, :policy_too_large}
      {:ok, %{type: type}} -> {:error, {:invalid_policy_file, type}}
      {:error, reason} -> {:error, reason}
    end
  end

  defp normalize_max_bytes(value) when is_integer(value) and value >= 0, do: {:ok, value}
  defp normalize_max_bytes(_), do: {:error, :invalid_max_bytes}

  defp normalize_id(nil, index), do: {:ok, "rule_#{index}"}

  defp normalize_id(value, _) when is_atom(value) and not is_boolean(value),
    do: {:ok, Atom.to_string(value)}

  defp normalize_id(value, _) when is_binary(value) and value != "", do: {:ok, value}
  defp normalize_id(_, _), do: {:error, :invalid_rule_id}

  defp optional_string(nil), do: nil
  defp optional_string(value) when is_atom(value), do: Atom.to_string(value)
  defp optional_string(value) when is_binary(value), do: value
  defp optional_string(_), do: nil

  defp changed_paths(context) do
    field_or_default(context, ~w(changed_paths changed_files files paths), [])
  end

  defp context_map(context) when is_list(context), do: Map.new(context)
  defp context_map(context) when is_map(context), do: context
  defp context_map(_), do: %{}

  defp evaluate_with_agent(policy, context, agent) do
    case context_string(context, ~w(action), :invalid_action) do
      {:ok, action} ->
        action = action || "modify"

        case normalize_changed_paths(changed_paths(context)) do
          {:ok, paths} -> evaluate_paths(policy, agent, action, paths)
          {:error, reason} -> invalid_path_decision(agent, action, reason)
        end

      {:error, reason} ->
        invalid_context_decision(agent, "invalid", reason)
    end
  end

  defp context_string(map, keys, invalid_reason) do
    result =
      Enum.reduce_while(keys, :missing, fn key, :missing ->
        case fetch_field(map, key) do
          {:ok, value} ->
            context_string_value(value, invalid_reason)

          :error ->
            {:cont, :missing}
        end
      end)

    case result do
      :missing -> {:ok, nil}
      result -> result
    end
  end

  defp context_string_value(nil, _), do: {:cont, :missing}

  defp context_string_value(value, _) when is_binary(value) and value != "",
    do: {:halt, {:ok, value}}

  defp context_string_value(value, _) when is_atom(value) and not is_boolean(value),
    do: {:halt, {:ok, Atom.to_string(value)}}

  defp context_string_value(_, invalid_reason), do: {:halt, {:error, invalid_reason}}

  defp field(map, key) when is_map(map) do
    case fetch_field(map, key) do
      {:ok, value} -> value
      :error -> nil
    end
  end

  defp field_or_default(map, keys, default) when is_list(keys) do
    case fetch_any_field(map, keys) do
      {:ok, value} -> value
      :error -> default
    end
  end

  defp field_or_default(map, key, default) do
    case fetch_field(map, key) do
      {:ok, value} -> value
      :error -> default
    end
  end

  defp fetch_any_field(map, keys) do
    Enum.reduce_while(keys, :error, fn key, :error ->
      case fetch_field(map, key) do
        {:ok, value} -> {:halt, {:ok, value}}
        :error -> {:cont, :error}
      end
    end)
  end

  defp fetch_field(map, key) when is_map(map) do
    case Map.fetch(map, key) do
      {:ok, value} -> {:ok, value}
      :error -> Map.fetch(map, Map.fetch!(@atom_fields, key))
    end
  end

  defp invalid_path_decision(agent, action, reason) do
    build_decision(%{
      verdict: :block,
      reason: "Repo policy blocked invalid changed path: #{reason}",
      agent: agent,
      action: action,
      changed_paths: [],
      matched_rule_ids: [],
      unmatched_paths: []
    })
  end

  defp invalid_context_decision(agent, action, reason) do
    build_decision(%{
      verdict: :block,
      reason: "Repo policy blocked invalid context: #{reason}",
      agent: agent,
      action: action,
      changed_paths: [],
      matched_rule_ids: [],
      unmatched_paths: []
    })
  end

  defp build_decision(attrs) do
    %Decision{
      verdict: attrs.verdict,
      reason: attrs.reason,
      agent: attrs.agent,
      action: attrs.action,
      changed_paths: attrs.changed_paths,
      matched_rule_ids: attrs.matched_rule_ids,
      unmatched_paths: attrs.unmatched_paths,
      digest: decision_digest(attrs)
    }
  end

  defp decision_digest(attrs) do
    %{
      "verdict" => attrs.verdict,
      "reason" => attrs.reason,
      "agent" => attrs.agent,
      "action" => attrs.action,
      "changed_paths" => attrs.changed_paths,
      "matched_rule_ids" => attrs.matched_rule_ids,
      "unmatched_paths" => attrs.unmatched_paths
    }
    |> canonical_iodata()
    |> IO.iodata_to_binary()
    |> sha256_hex()
  end

  defp canonical_map(%__MODULE__{} = policy) do
    %{
      "version" => policy.version,
      "default" => policy.default,
      "rules" =>
        Enum.map(policy.rules, fn rule ->
          %{
            "id" => rule.id,
            "decision" => rule.decision,
            "agents" => rule.agents,
            "actions" => rule.actions,
            "paths" => rule.paths,
            "message" => rule.message,
            "index" => rule.index
          }
        end)
    }
  end

  defp canonical_iodata(value) when is_map(value) do
    parts =
      value
      |> Enum.map(fn {key, item} -> {canonical_key(key), item} end)
      |> Enum.sort_by(&elem(&1, 0))
      |> Enum.map(fn {key, item} -> [Jason.encode!(key), ?:, canonical_iodata(item)] end)
      |> Enum.intersperse(",")

    [?{, parts, ?}]
  end

  defp canonical_iodata(value) when is_list(value) do
    parts =
      value
      |> Enum.map(&canonical_iodata/1)
      |> Enum.intersperse(",")

    [?[, parts, ?]]
  end

  defp canonical_iodata(value)
       when is_atom(value) and not is_boolean(value) and not is_nil(value) do
    value
    |> Atom.to_string()
    |> Jason.encode!()
  end

  defp canonical_iodata(value), do: Jason.encode!(value)

  defp canonical_key(key) when is_atom(key), do: Atom.to_string(key)
  defp canonical_key(key) when is_binary(key), do: key
  defp canonical_key(key), do: to_string(key)

  defp sha256_hex(data), do: Base.encode16(:crypto.hash(:sha256, data), case: :lower)
end
