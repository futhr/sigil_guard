defmodule Mix.Tasks.Sigil.MigrationGate do
  @shortdoc "Validate 1.0 migration coverage"

  @moduledoc """
  Validates that deleted legacy surfaces have explicit `MIGRATING-1.0.md` coverage.

      mix sigil.migration_gate

  The gate is intentionally static: M6 owns the deletion list, and future
  deletion work must extend this required mapping list in the same commit as the
  deletion and migration docs.
  """

  use Mix.Task

  @type finding :: %{
          required(:check) => atom(),
          required(:path) => String.t(),
          required(:line) => pos_integer() | nil,
          required(:message) => String.t()
        }

  @type gate_opts :: [root: Path.t(), required_mappings: [{atom(), String.t()}]]

  @required_mappings [
    module: "SigilGuard.Registry",
    module: "SigilGuard.Registry.Bundle",
    module: "SigilGuard.Registry.Cache",
    module: "SigilGuard.Envelope",
    module: "SigilGuard.Profile",
    function: "SigilGuard.Registry.fetch_bundle/1",
    function: "SigilGuard.Registry.resolve_did/2",
    function: "SigilGuard.Registry.resolve_key/2",
    function: "SigilGuard.Registry.fetch_policies/1",
    function: "SigilGuard.Registry.Bundle.sign/2",
    function: "Envelope.sign(identity, verdict, opts)",
    function: "Envelope.verify(envelope, public_key_b64u, opts)",
    function: "SigilGuard.Profile.profiles/0",
    function: "SigilGuard.Profile.normalize!/1",
    function: "SigilGuard.Profile.wire_verdict_format/1",
    function: "SigilGuard.Profile.verdict_acceptance/1",
    function: "SigilGuard.Profile.require_blocked_reason_on_verify?/1",
    function: "SigilGuard.Profile.registry_identity_endpoints/1",
    config: ":backend",
    config: ":protocol_profile",
    config: ":registry_url",
    config: ":registry_ttl_ms",
    config: ":registry_timeout_ms",
    config: ":registry_retry_ms",
    config: ":registry_enabled",
    config: ":registry_require_signed_bundles",
    config: ":registry_bundle_public_keys",
    config: ":registry_bundle_max_age_seconds",
    config: ":registry_bundle_clock_skew_seconds",
    config: "scanner_patterns: :registry",
    filename: "SIGIL_POLICY",
    filename: ".sigil-policy",
    filename: ".sigil/policy",
    filename: ".github/sigil-policy"
  ]

  @doc """
  Run the migration gate and raise on failures.
  """
  @spec run([String.t()]) :: :ok
  def run(args) do
    if args != [] do
      Mix.raise("sigil.migration_gate does not accept options")
    end

    case validate() do
      :ok ->
        Mix.shell().info("Migration gate passed")

      {:error, findings} ->
        findings
        |> format_findings()
        |> Mix.raise()
    end
  end

  @doc """
  Validate migration coverage and local markdown links.
  """
  @spec validate(gate_opts()) :: :ok | {:error, [finding()]}
  def validate(opts \\ []) do
    root =
      opts
      |> Keyword.get(:root, File.cwd!())
      |> Path.expand()

    path = Path.join(root, "MIGRATING-1.0.md")
    body = read(path)
    required_mappings = Keyword.get(opts, :required_mappings, @required_mappings)

    findings =
      mapping_findings(root, path, body, required_mappings) ++
        link_findings(root, path, body)

    case findings do
      [] -> :ok
      [_ | _] -> {:error, Enum.sort_by(findings, &{&1.path, &1.line || 0, &1.check})}
    end
  end

  defp mapping_findings(root, path, body, required_mappings) do
    Enum.flat_map(required_mappings, fn {kind, token} ->
      if String.contains?(body, token) do
        []
      else
        [
          finding(
            :missing_mapping,
            relative_path(root, path),
            nil,
            "#{kind} #{token} is not mapped"
          )
        ]
      end
    end)
  end

  defp link_findings(root, path, body) do
    anchors = heading_anchors(body)

    body
    |> lines()
    |> Enum.flat_map(fn {line, line_no} ->
      line
      |> markdown_links()
      |> Enum.flat_map(&link_finding(root, path, line_no, &1, anchors))
    end)
  end

  defp link_finding(root, path, line_no, target, anchors) do
    {file_part, anchor} = split_anchor(target)
    target_path = Path.expand(file_part, Path.dirname(path))

    link_finding_for(%{
      root: root,
      path: path,
      line_no: line_no,
      target: target,
      anchor: anchor,
      anchors: anchors,
      target_path: target_path
    })
  end

  defp link_finding_for(%{target: ""}), do: []

  defp link_finding_for(args) do
    cond do
      external_link?(args.target) ->
        []

      local_anchor?(args.target) ->
        local_anchor_finding(args)

      not inside_root?(args.root, args.target_path) ->
        invalid_link(args, "link escapes repo: #{args.target}")

      not File.exists?(args.target_path) ->
        invalid_link(args, "missing link target: #{args.target}")

      missing_same_file_anchor?(args) ->
        invalid_link(args, "missing anchor: #{args.target}")

      true ->
        []
    end
  end

  defp external_link?(target), do: String.starts_with?(target, ["http://", "https://", "mailto:"])
  defp local_anchor?(target), do: String.starts_with?(target, "#")

  defp local_anchor_finding(args) do
    anchor = String.trim_leading(args.target, "#")

    if MapSet.member?(args.anchors, anchor) do
      []
    else
      invalid_link(args, "missing anchor: #{args.target}")
    end
  end

  defp missing_same_file_anchor?(%{
         path: path,
         target_path: target_path,
         anchor: anchor,
         anchors: anchors
       }) do
    Path.expand(target_path) == Path.expand(path) and is_binary(anchor) and
      not MapSet.member?(anchors, anchor)
  end

  defp invalid_link(args, message) do
    [finding(:invalid_link, relative_path(args.root, args.path), args.line_no, message)]
  end

  defp split_anchor(target) do
    case String.split(target, "#", parts: 2) do
      [file] -> {file, nil}
      [file, anchor] -> {file, anchor}
    end
  end

  defp markdown_links(line) do
    ~r/\[[^\]]+\]\(([^)]+)\)/
    |> Regex.scan(line)
    |> Enum.map(fn [_, target] -> target end)
  end

  defp heading_anchors(body) do
    body
    |> lines()
    |> Enum.flat_map(fn {line, _} ->
      case Regex.run(~r/^#+\s+(.+)$/, line) do
        [_, heading] -> [anchor_for(heading)]
        nil -> []
      end
    end)
    |> MapSet.new()
  end

  defp anchor_for(heading) do
    heading
    |> String.downcase()
    |> String.replace(~r/`/, "")
    |> String.replace(~r/[^a-z0-9\s-]/, "")
    |> String.trim()
    |> String.replace(~r/\s+/, "-")
  end

  defp lines(body) do
    body
    |> String.split("\n")
    |> Enum.with_index(1)
  end

  defp read(path) do
    case File.read(path) do
      {:ok, body} -> body
      {:error, _} -> ""
    end
  end

  defp inside_root?(root, path) do
    root = Path.expand(root)
    path = Path.expand(path)
    path == root or String.starts_with?(path, root <> "/")
  end

  defp finding(check, path, line, message) do
    %{check: check, path: path, line: line, message: message}
  end

  defp relative_path(root, path), do: Path.relative_to(path, root)

  defp format_findings(findings) do
    lines =
      Enum.map(findings, fn finding ->
        location =
          case finding.line do
            nil -> finding.path
            line -> "#{finding.path}:#{line}"
          end

        "#{location}: #{finding.check}: #{finding.message}"
      end)

    "migration gate failed:\n" <> Enum.join(lines, "\n")
  end
end
