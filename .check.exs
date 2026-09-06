[
  parallel: false,
  skipped: false,
  tools: [
    # Dependencies
    {:deps_get, command: "mix deps.get"},

    # Elixir compilation (--force is default for ex_check compiler)
    {:compiler, command: "mix compile --warnings-as-errors"},
    {:prod_package, command: "./bin/check-prod-package"},

    # Formatting
    {:formatter, command: "mix format --check-formatted"},

    # Static analysis
    {:credo, command: "mix credo --strict"},
    {:sobelow, command: "mix sobelow --config --compact"},

    # Security and dependencies
    {:secret_scan, command: "./bin/check-secrets"},
    {:mix_audit, command: "mix deps.audit"},
    {:hex_audit, command: "mix hex.audit"},

    # Type checking
    {:dialyzer, command: "mix dialyzer"},

    # Documentation
    {:docs_lint, command: "mix sigil.docs_lint"},
    {:migration_gate, command: "mix sigil.migration_gate"},
    {:livebooks, command: "mix sigil.livebook_check"},
    {:doctor, command: "mix doctor"},
    {:ex_doc, command: "mix docs --warnings-as-errors"},

    # Tests
    {:ex_unit, command: "mix test --cover"},
    {:mutation, command: "./bin/check-verdict-mutations"}
  ]
]
