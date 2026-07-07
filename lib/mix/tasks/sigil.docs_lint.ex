defmodule Mix.Tasks.Sigil.DocsLint do
  @shortdoc "Validate SigilGuard docs catalogue rules"

  @moduledoc """
  Consolidates the documentation checks required before v3 implementation work.

      mix sigil.docs_lint

  The task checks spec/task drift, forbidden terminology, known-dead public
  URLs, stale three-digit research/spec identifiers, local filesystem links,
  and old public wire/config vocabulary in public documentation.
  """

  use Mix.Task

  @type finding :: %{
          required(:check) => atom(),
          required(:path) => String.t(),
          required(:line) => pos_integer() | nil,
          required(:message) => String.t()
        }

  @type lint_opts :: [
          root: Path.t(),
          forbidden_terms: [String.t()],
          dead_urls: [String.t()],
          old_vocabulary: [String.t()]
        ]

  @doc """
  Run the docs lint checks and raise on any finding.
  """
  @spec run([String.t()]) :: :ok
  def run(args) do
    if args != [] do
      Mix.raise("sigil.docs_lint does not accept options")
    end

    case lint() do
      :ok ->
        Mix.shell().info("Docs lint passed")

      {:error, findings} ->
        findings
        |> format_findings()
        |> Mix.raise()
    end
  end

  @doc """
  Run the docs lint checks.
  """
  @spec lint(lint_opts()) :: :ok | {:error, [finding()]}
  def lint(opts \\ []) do
    root =
      opts
      |> Keyword.get(:root, File.cwd!())
      |> Path.expand()

    files = markdown_files(root)
    task_file = Path.join(root, "docs/tasks/sigil-tasks.md")
    spec_files = Path.wildcard(Path.join(root, "docs/specs/SP.*.md"))

    findings =
      [
        spec_drift_findings(root, task_file, spec_files),
        pattern_findings(root, files, :forbidden_term, forbidden_terms(opts)),
        pattern_findings(root, files, :dead_url, dead_urls(opts)),
        stale_id_findings(root, files),
        local_filesystem_link_findings(root, files),
        old_vocabulary_findings(root, public_doc_files(root), old_vocabulary(opts))
      ]
      |> List.flatten()

    case findings do
      [] -> :ok
      [_ | _] -> {:error, Enum.sort_by(findings, &{&1.path, &1.line || 0, &1.check})}
    end
  end

  defp spec_drift_findings(root, task_file, spec_files) do
    spec_ids =
      spec_files
      |> Enum.map(&Path.basename/1)
      |> Enum.flat_map(&scan_ids(&1, ~r/^SP\.(\d{2})-/))
      |> MapSet.new()

    task_ids =
      task_file
      |> task_body()
      |> scan_ids(~r/\bSP\.(\d{2})\b/)
      |> MapSet.new()

    missing_task_findings =
      spec_ids
      |> MapSet.difference(task_ids)
      |> Enum.map(fn id ->
        finding(
          :spec_drift,
          relative_path(root, task_file),
          nil,
          "SP.#{id} has no task reference"
        )
      end)

    unknown_spec_findings =
      task_ids
      |> MapSet.difference(spec_ids)
      |> Enum.map(fn id ->
        finding(:spec_drift, relative_path(root, task_file), nil, "SP.#{id} has no spec file")
      end)

    missing_task_findings ++ unknown_spec_findings
  end

  defp pattern_findings(root, files, check, patterns) do
    for file <- files,
        {line, line_no} <- lines(file),
        pattern <- patterns,
        String.contains?(line, pattern) do
      finding(check, relative_path(root, file), line_no, message_for(check))
    end
  end

  defp stale_id_findings(root, files) do
    for file <- files,
        {line, line_no} <- lines(file),
        [id] <- Regex.scan(~r/\b(?:SP|R)\.\d{3,}\b/, line) do
      finding(:stale_id, relative_path(root, file), line_no, "stale three-digit id #{id}")
    end
  end

  defp local_filesystem_link_findings(root, files) do
    for file <- files,
        {line, line_no} <- lines(file),
        Regex.match?(~r/(?:file:\/\/|\/Users\/|\/home\/|[A-Za-z]:\\)/, line) do
      finding(:local_filesystem_link, relative_path(root, file), line_no, "local filesystem link")
    end
  end

  defp old_vocabulary_findings(root, files, patterns) do
    files
    |> Enum.reject(&old_vocabulary_exempt?/1)
    |> then(&pattern_findings(root, &1, :old_vocabulary, patterns))
  end

  defp old_vocabulary_exempt?(path) do
    path =~ "/test/fixtures/historical/" or
      Path.basename(path) in ["MIGRATING-1.0.md", "CHANGELOG.md"]
  end

  defp markdown_files(root) do
    root
    |> Path.join("**/*.md")
    |> Path.wildcard()
    |> Enum.reject(&String.contains?(&1, "/deps/"))
  end

  defp public_doc_files(root) do
    [
      Path.join(root, "README.md"),
      Path.join(root, "CONTRIBUTING.md"),
      Path.join(root, "docs/README.md"),
      Path.join(root, "docs/specs/README.md")
      | Path.wildcard(Path.join(root, "docs/templates/*.md"))
    ]
    |> Enum.filter(&File.regular?/1)
  end

  defp scan_ids(text, regex) do
    regex
    |> Regex.scan(text)
    |> Enum.map(fn [_, id] -> id end)
  end

  defp lines(path) do
    case read_file(path) do
      {:ok, body} ->
        body
        |> String.split("\n")
        |> Enum.with_index(1)

      {:error, _} ->
        []
    end
  end

  defp read_file(path), do: File.read(path)

  defp task_body(path) do
    case read_file(path) do
      {:ok, body} -> body
      {:error, _} -> ""
    end
  end

  defp finding(check, path, line, message) do
    %{check: check, path: path, line: line, message: message}
  end

  defp relative_path(root, path), do: Path.relative_to(path, root)

  defp message_for(:forbidden_term), do: "forbidden inspiration-project term"
  defp message_for(:dead_url), do: "dead public protocol/registry URL"
  defp message_for(:old_vocabulary), do: "old public wire/config vocabulary"

  defp forbidden_terms(opts), do: Keyword.get(opts, :forbidden_terms, private_forbidden_terms())
  defp dead_urls(opts), do: Keyword.get(opts, :dead_urls, private_dead_urls())

  defp old_vocabulary(opts) do
    Keyword.get(opts, :old_vocabulary, [
      "_sigil",
      "_sigil_confirmation",
      "protocol_profile",
      "registry_url",
      "registry_enabled",
      "registry_*",
      "scanner_patterns: :registry"
    ])
  end

  defp private_forbidden_terms do
    []
  end

  defp private_dead_urls do
    []
  end

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

    "docs lint failed:\n" <> Enum.join(lines, "\n")
  end
end
