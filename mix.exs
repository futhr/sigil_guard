defmodule SigilGuard.MixProject do
  use Mix.Project

  @version "0.2.0"
  @source_url "https://github.com/futhr/sigil_guard"

  def project do
    [
      app: :sigil_guard,
      version: @version,
      elixir: "~> 1.18",
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
      {:nimble_options, "~> 1.1"},
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
      {:stream_data, "~> 1.3", only: :test},

      # Benchmarks
      {:benchee, "~> 1.3", only: :dev, runtime: false},
      {:benchee_markdown, "~> 0.3", only: :dev, runtime: false},

      # Release
      {:git_ops, "~> 2.6", only: :dev, runtime: false}
    ]
  end

  defp description do
    "Native Elixir security runtime for MCP and agent tool boundaries: scanning, " <>
      "envelope contracts, policy, audit evidence, and signed trust bundles."
  end

  defp package do
    [
      name: "sigil_guard",
      licenses: ["MIT"],
      links: %{
        "GitHub" => @source_url,
        "Historical upstream SIGIL repository" => "https://github.com/sigil-eu/sigil"
      },
      files: ~w[
        lib
        docs
        .formatter.exs
        mix.exs
        README.md
        LICENSE
        CHANGELOG.md
        MIGRATING-3.0.md
      ],
      maintainers: ["Tobias Bohwalli <hi@futhr.io>"]
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: [
        "README.md": [title: "Overview"],
        "guides/release-and-anchoring.md": [title: "Release and Anchoring"],
        "bench/output/benchmarks.md": [title: "Benchmarks"],
        "MIGRATING-3.0.md": [title: "Migrating to 3.0"],
        "CHANGELOG.md": [title: "Changelog"],
        "CONTRIBUTING.md": [title: "Contributing"],
        "AGENTS.md": [title: "AI Agents"],
        LICENSE: [title: "License"]
      ],
      groups_for_extras: [
        "Getting Started": ~r/README/,
        Guides: ~r/guides/,
        Performance: ~r/benchmarks/,
        Reference: ~r/MIGRATING|CHANGELOG|CONTRIBUTING|AGENTS|LICENSE/
      ],
      groups_for_modules: [
        "Core API": [
          SigilGuard,
          SigilGuard.Scanner,
          SigilGuard.Scanner.Pipeline,
          SigilGuard.Envelope,
          SigilGuard.Policy,
          SigilGuard.Confirmation,
          SigilGuard.Attestation,
          SigilGuard.Attestation.AgentPredicate,
          SigilGuard.Attestation.Digest,
          SigilGuard.Attestation.Envelope,
          SigilGuard.Attestation.Statement,
          SigilGuard.Canonical.JCS,
          SigilGuard.Context,
          SigilGuard.Decision,
          SigilGuard.Identity,
          SigilGuard.Identity.Binding,
          SigilGuard.Patterns,
          SigilGuard.Profile,
          SigilGuard.Quarantine,
          SigilGuard.RepoPolicy,
          SigilGuard.RepoPolicy.Decision,
          SigilGuard.TrustProfile
        ],
        "Runtime Gate": [
          SigilGuard.Runtime.Gate,
          SigilGuard.Runtime.Stream
        ],
        "MCP Gateway": [
          SigilGuard.MCP.Gateway,
          SigilGuard.TransportExamples
        ],
        Audit: [
          SigilGuard.Audit,
          SigilGuard.Audit.Action,
          SigilGuard.Audit.Anchor,
          SigilGuard.Audit.Anchor.Receipt,
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
          SigilGuard.ConfigError,
          SigilGuard.ReplayStore,
          SigilGuard.Telemetry
        ],
        "Trust Bundles": [
          SigilGuard.TrustBundle,
          SigilGuard.TrustBundle.Cache,
          SigilGuard.TrustBundle.Quarantine,
          SigilGuard.TrustBundle.Schema,
          SigilGuard.TrustBundle.Verify
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
