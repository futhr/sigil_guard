defmodule SigilGuard.MixProject do
  use Mix.Project

  @version "0.2.0"
  @source_url "https://github.com/futhr/sigil_guard"

  def project do
    [
      app: :sigil_guard,
      version: @version,
      elixir: "~> 1.17",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      elixirc_paths: elixirc_paths(Mix.env()),
      description: description(),
      package: package(),
      source_url: @source_url,
      homepage_url: @source_url,
      docs: docs(),
      dialyzer: dialyzer(),
      test_coverage: [tool: ExCoveralls],
      aliases: aliases(),
      name: "SigilGuard"
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto],
      mod: {SigilGuard.Application, []}
    ]
  end

  def cli do
    [
      preferred_envs: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.html": :test,
        "coveralls.lcov": :test,
        cover: :test,
        "cover.html": :test
      ]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      # Core
      {:finch, "~> 0.19"},
      {:jason, "~> 1.4"},
      {:telemetry, "~> 1.0"},

      # Code quality
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:sobelow, "~> 0.13", only: [:dev, :test], runtime: false},
      {:mix_audit, "~> 2.1", only: [:dev, :test], runtime: false},
      {:ex_check, "~> 0.16", only: [:dev, :test], runtime: false},

      # Documentation
      {:ex_doc, "~> 0.35", only: [:dev, :test], runtime: false},
      {:doctor, "~> 0.22", only: [:dev, :test], runtime: false},
      {:doctest_formatter, "~> 0.4", only: [:dev, :test], runtime: false},

      # Testing
      {:excoveralls, "~> 0.18", only: :test},
      {:bypass, "~> 2.1", only: :test},
      {:mox, "~> 1.1", only: :test},

      # Benchmarks
      {:benchee, "~> 1.3", only: :dev, runtime: false},
      {:benchee_markdown, "~> 0.3", only: :dev, runtime: false},

      # Release
      {:git_ops, "~> 2.6", only: :dev, runtime: false}
    ]
  end

  defp description do
    "SIGIL Protocol integration for Elixir — sensitivity scanning, envelope signing, " <>
      "policy enforcement, tamper-evident auditing, and registry client with a native Elixir runtime."
  end

  defp package do
    [
      name: "sigil_guard",
      licenses: ["MIT"],
      links: %{
        "GitHub" => @source_url,
        "SIGIL Protocol" => "https://sigil-protocol.org/"
      },
      files: ~w[
        lib
        .formatter.exs
        mix.exs
        README.md
        LICENSE
        CHANGELOG.md
      ],
      maintainers: ["Tobias Bohwalli <hi@futhr.io>"]
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: [
        "README.md": [title: "Overview"],
        "bench/output/benchmarks.md": [title: "Benchmarks"],
        "CHANGELOG.md": [title: "Changelog"],
        "CONTRIBUTING.md": [title: "Contributing"],
        "AGENTS.md": [title: "AI Agents"],
        LICENSE: [title: "License"]
      ],
      groups_for_extras: [
        "Getting Started": ~r/README/,
        Performance: ~r/benchmarks/,
        Reference: ~r/CHANGELOG|CONTRIBUTING|AGENTS|LICENSE/
      ],
      groups_for_modules: [
        "Core API": [
          SigilGuard,
          SigilGuard.Scanner,
          SigilGuard.Scanner.Pipeline,
          SigilGuard.Envelope,
          SigilGuard.Policy,
          SigilGuard.Confirmation,
          SigilGuard.Context,
          SigilGuard.Decision,
          SigilGuard.Identity,
          SigilGuard.Identity.Binding,
          SigilGuard.Patterns,
          SigilGuard.Profile,
          SigilGuard.Quarantine,
          SigilGuard.RepoPolicy,
          SigilGuard.RepoPolicy.Decision
        ],
        "Runtime Gate": [
          SigilGuard.Runtime.Gate,
          SigilGuard.Runtime.Stream
        ],
        "MCP Gateway": [
          SigilGuard.MCP.Gateway
        ],
        Audit: [
          SigilGuard.Audit,
          SigilGuard.Audit.Action,
          SigilGuard.Audit.Anchor,
          SigilGuard.Audit.Anchor.Store,
          SigilGuard.Audit.Anchor.Store.HTTP,
          SigilGuard.Audit.Anchor.Store.LocalFile,
          SigilGuard.Audit.Actor,
          SigilGuard.Audit.Checkpoint,
          SigilGuard.Audit.EventType,
          SigilGuard.Audit.ExecutionResult,
          SigilGuard.Audit.Export,
          SigilGuard.Audit.Logger
        ],
        "Signing & Vault": [
          SigilGuard.Signer,
          SigilGuard.Signer.Ed25519,
          SigilGuard.Vault,
          SigilGuard.Vault.Entry,
          SigilGuard.Vault.InMemory
        ],
        Registry: [
          SigilGuard.Registry,
          SigilGuard.Registry.Bundle,
          SigilGuard.Registry.Cache
        ],
        Backend: [
          SigilGuard.Backend,
          SigilGuard.Backend.Elixir
        ],
        Runtime: [
          SigilGuard.Application,
          SigilGuard.Config,
          SigilGuard.ReplayStore,
          SigilGuard.Telemetry
        ]
      ],
      source_ref: "v#{@version}",
      source_url: @source_url,
      formatters: ["html"]
    ]
  end

  defp dialyzer do
    [
      plt_file: {:no_warn, "priv/plts/dialyxir.plt"},
      plt_add_apps: [:mix, :ex_unit, :xmerl],
      flags: [:error_handling, :missing_return, :underspecs]
    ]
  end

  defp aliases do
    [
      setup: ["deps.get", "deps.compile"],
      lint: ["format --check-formatted", "credo --strict", "dialyzer"],
      "test.cover": ["coveralls"],
      bench: ["run bench/run.exs"],
      ci: ["setup", "lint", "test.cover"],

      # Release
      release: ["git_ops.release"]
    ]
  end
end
