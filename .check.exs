[
  parallel: true,
  skipped: true,

  tools: [
    # Dependencies
    {:deps_get, command: "mix deps.get"},

    # Elixir compilation (--force is default for ex_check compiler)
    {:compiler, command: "mix compile --warnings-as-errors"},

    # Formatting
    {:formatter, command: "mix format --check-formatted"},

    # Rust format check (only if native Rust code exists and cargo installed)
    {:rust_fmt,
     command: "cargo fmt --check",
     cd: "native/sigil_guard_nif",
     enabled: File.dir?("native/sigil_guard_nif") and System.find_executable("cargo") != nil},

    # Static analysis
    {:credo, command: "mix credo --strict"},
    {:sobelow, command: "mix sobelow --config --compact"},

    # Rust clippy linting (only if native Rust code exists and cargo installed)
    {:rust_clippy,
     command: "cargo clippy --lib -- -D warnings",
     cd: "native/sigil_guard_nif",
     enabled: File.dir?("native/sigil_guard_nif") and System.find_executable("cargo") != nil},

    # Security and dependencies
    {:mix_audit, command: "mix deps.audit"},

    # Type checking
    {:dialyzer, command: "mix dialyzer"},

    # Documentation
    {:doctor, command: "mix doctor"},
    {:ex_doc, command: "mix docs"},

    # Tests
    {:ex_unit, command: "mix test --cover"},

    # NIF integration tests (only if NIF is compiled)
    {:test_nif,
     command: "mix test --include nif",
     enabled: File.exists?("priv/native/libsigil_guard_nif.so") or
              File.exists?("priv/native/libsigil_guard_nif.dylib"),
     deps: [:ex_unit]}
  ]
]
