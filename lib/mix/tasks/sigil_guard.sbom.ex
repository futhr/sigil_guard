defmodule Mix.Tasks.SigilGuard.Sbom do
  @shortdoc "Generate an SPDX JSON SBOM"

  @moduledoc """
  Generate an SPDX 2.3 JSON SBOM from the Mix project and lockfile.

  The generated document is intentionally dependency-light: it uses Mix project
  metadata, production dependencies, `mix.lock`, and Jason to produce a
  package-level SBOM suitable for release artifact attestation.

      mix sigil_guard.sbom --output dist/sigil_guard.spdx.json
  """

  use Mix.Task

  @switches [output: :string]
  @default_output "dist/sigil_guard.spdx.json"
  @spdx_version "SPDX-2.3"
  @data_license "CC0-1.0"

  @type spdx_document :: %{required(String.t()) => term()}

  @doc """
  Generate and write the SBOM file.
  """
  @spec run([String.t()]) :: :ok
  def run(args) do
    {opts, _, invalid} = OptionParser.parse(args, strict: @switches)

    if invalid != [] do
      Mix.raise("invalid options: #{inspect(invalid)}")
    end

    output = Keyword.get(opts, :output, @default_output)
    sbom = generate()

    output
    |> Path.dirname()
    |> File.mkdir_p!()

    File.write!(output, Jason.encode_to_iodata!(sbom, pretty: true))
    Mix.shell().info("Generated SBOM at #{output}")
  end

  @doc """
  Build an SPDX document map for the current Mix project.
  """
  @spec generate(keyword()) :: spdx_document()
  def generate(opts \\ []) do
    project = Mix.Project.config()
    created_at = Keyword.get_lazy(opts, :created_at, &timestamp/0)
    git_revision = Keyword.get_lazy(opts, :git_revision, &git_revision/0)
    root = root_package(project)
    locks = lock_entries()
    root_dependencies = runtime_root_dependencies(project)
    dependency_names = dependency_closure(root_dependencies, locks)
    dependencies = dependency_packages(locks, dependency_names)
    dependency_edges = dependency_edges(root_dependencies, dependency_names, locks)

    %{
      "spdxVersion" => @spdx_version,
      "dataLicense" => @data_license,
      "SPDXID" => "SPDXRef-DOCUMENT",
      "name" => "#{project[:app]}-#{project[:version]}",
      "documentNamespace" => document_namespace(project, git_revision, created_at),
      "creationInfo" => %{
        "created" => created_at,
        "creators" => [
          "Tool: mix sigil_guard.sbom",
          "Organization: SigilGuard"
        ]
      },
      "packages" => [root | dependencies],
      "relationships" => relationships(root, dependency_edges)
    }
  end

  defp root_package(project) do
    package = Keyword.get(project, :package, [])
    licenses = Keyword.get(package, :licenses, ["NOASSERTION"])
    declared_license = Enum.join(licenses, " OR ")
    name = package[:name] || Atom.to_string(project[:app])
    source_url = project[:source_url] || project[:homepage_url] || "NOASSERTION"

    %{
      "name" => name,
      "SPDXID" => package_id(name),
      "versionInfo" => project[:version],
      "downloadLocation" => source_url,
      "filesAnalyzed" => false,
      "licenseConcluded" => declared_license,
      "licenseDeclared" => declared_license,
      "supplier" => "Organization: SigilGuard",
      "externalRefs" => [
        %{
          "referenceCategory" => "PACKAGE-MANAGER",
          "referenceType" => "purl",
          "referenceLocator" => "pkg:hex/#{name}@#{project[:version]}"
        }
      ]
    }
  end

  defp runtime_root_dependencies(project) do
    project
    |> Keyword.get(:deps, [])
    |> Enum.flat_map(&runtime_root_dependency/1)
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp runtime_root_dependency({name, _}), do: [name]

  defp runtime_root_dependency({name, _, opts}) when is_list(opts) do
    if runtime_dependency?(opts), do: [name], else: []
  end

  defp runtime_root_dependency(_), do: []

  defp runtime_dependency?(opts) do
    Keyword.get(opts, :runtime, true) != false and
      production_dependency?(Keyword.get(opts, :only, :all))
  end

  defp production_dependency?(:all), do: true
  defp production_dependency?(:prod), do: true
  defp production_dependency?(env) when is_atom(env), do: false
  defp production_dependency?(envs) when is_list(envs), do: :prod in envs
  defp production_dependency?(_), do: false

  defp dependency_closure(root_dependencies, locks) do
    root_dependencies
    |> Enum.reduce(MapSet.new(), &include_dependency(&1, locks, &2))
    |> MapSet.to_list()
    |> Enum.sort()
  end

  defp include_dependency(name, locks, seen) do
    cond do
      MapSet.member?(seen, name) -> seen
      not Map.has_key?(locks, name) -> seen
      true -> include_lock_dependency(name, locks, seen)
    end
  end

  defp include_lock_dependency(name, locks, seen) do
    locks
    |> Map.fetch!(name)
    |> lock_dependency_names()
    |> Enum.reduce(MapSet.put(seen, name), &include_dependency(&1, locks, &2))
  end

  defp dependency_packages(locks, dependency_names) do
    dependency_names
    |> Enum.flat_map(fn name ->
      case Map.fetch(locks, name) do
        {:ok, lock} -> dependency_package(lock)
        :error -> []
      end
    end)
  end

  defp dependency_package({:hex, package, version, checksum, _, _, repo, outer}) do
    name = Atom.to_string(package)

    [
      %{
        "name" => name,
        "SPDXID" => package_id(name),
        "versionInfo" => version,
        "downloadLocation" => "https://hex.pm/packages/#{name}",
        "filesAnalyzed" => false,
        "licenseConcluded" => "NOASSERTION",
        "licenseDeclared" => "NOASSERTION",
        "supplier" => "NOASSERTION",
        "checksums" => [
          %{"algorithm" => "SHA256", "checksumValue" => outer || checksum}
        ],
        "externalRefs" => [
          %{
            "referenceCategory" => "PACKAGE-MANAGER",
            "referenceType" => "purl",
            "referenceLocator" => "pkg:hex/#{name}@#{version}?repository_url=#{repo}"
          }
        ]
      }
    ]
  end

  defp dependency_package(_), do: []

  defp dependency_edges(root_dependencies, dependency_names, locks) do
    dependency_set = MapSet.new(dependency_names)

    root_edges =
      for name <- root_dependencies,
          MapSet.member?(dependency_set, name),
          do: {:root, name}

    transitive_edges =
      for name <- dependency_names,
          child <- lock_dependency_names(Map.fetch!(locks, name)),
          MapSet.member?(dependency_set, child),
          do: {name, child}

    root_edges
    |> Kernel.++(transitive_edges)
    |> MapSet.new()
    |> Enum.sort()
  end

  defp lock_dependency_names({:hex, _, _, _, _, dependencies, _, _}) do
    dependencies
    |> Enum.reject(&optional_lock_dependency?/1)
    |> Enum.map(&lock_dependency_name/1)
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp lock_dependency_names(_), do: []

  defp optional_lock_dependency?({_, _, opts}), do: Keyword.get(opts, :optional, false)
  defp optional_lock_dependency?(_), do: true

  defp lock_dependency_name({name, _, opts}), do: Keyword.get(opts, :hex, name)

  defp relationships(root, dependency_edges) do
    describes = [
      %{
        "spdxElementId" => "SPDXRef-DOCUMENT",
        "relationshipType" => "DESCRIBES",
        "relatedSpdxElement" => root["SPDXID"]
      }
    ]

    dependency_relationships =
      Enum.map(dependency_edges, fn {parent, child} ->
        %{
          "spdxElementId" => relationship_package_id(root, parent),
          "relationshipType" => "DEPENDS_ON",
          "relatedSpdxElement" => package_id(Atom.to_string(child))
        }
      end)

    describes ++ dependency_relationships
  end

  defp lock_entries do
    Mix.Dep.Lock.read()
    |> Map.new()
  end

  defp relationship_package_id(root, :root), do: root["SPDXID"]
  defp relationship_package_id(_, name), do: package_id(Atom.to_string(name))

  defp document_namespace(project, git_revision, created_at) do
    hash =
      "#{project[:app]}:#{project[:version]}:#{git_revision}:#{created_at}"
      |> sha256_hex()

    source = project[:source_url] || project[:homepage_url] || "https://example.invalid"
    "#{source}/sbom/#{project[:app]}-#{project[:version]}-#{hash}"
  end

  defp package_id(name) do
    normalized =
      name
      |> String.replace(~r/[^A-Za-z0-9.-]/, "-")
      |> String.trim("-")

    "SPDXRef-Package-#{normalized}"
  end

  defp git_revision do
    case System.cmd("git", ["rev-parse", "HEAD"],
           env: [{"GIT_TERMINAL_PROMPT", "0"}],
           stderr_to_stdout: true
         ) do
      {revision, 0} -> String.trim(revision)
      _ -> "NOASSERTION"
    end
  rescue
    ErlangError -> "NOASSERTION"
  end

  defp timestamp do
    DateTime.utc_now(:second)
    |> DateTime.to_iso8601()
  end

  defp sha256_hex(data), do: Base.encode16(:crypto.hash(:sha256, data), case: :lower)
end
