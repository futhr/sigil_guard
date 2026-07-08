[
  parallel: false,
  skipped: false,
  tools: [
    # Dependencies
    {:deps_get, command: "mix deps.get"},

    # Elixir compilation (--force is default for ex_check compiler)
    {:compiler, command: "mix compile --warnings-as-errors"},

    # Formatting
    {:formatter, command: "mix format --check-formatted"},

    # Static analysis
    {:credo, command: "mix credo --strict"},
    {:sobelow, command: "mix sobelow --config --compact"},

    # Security and dependencies
    {:mix_audit, command: "mix deps.audit"},

    # Type checking
    {:dialyzer, command: "mix dialyzer"},

    # Documentation
    {:docs_lint, command: "mix sigil.docs_lint"},
    {:doctor, command: "mix doctor"},
    {:ex_doc, command: "mix docs"},

    # Tests
    {:ex_unit, command: "mix test --cover"}
  ]
]
