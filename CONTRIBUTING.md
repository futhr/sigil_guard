# Contributing to SigilGuard

Thank you for your interest in contributing to SigilGuard!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/sigil_guard.git`
3. Install dependencies: `mix setup`
4. Create a feature branch: `git checkout -b feature/amazing-feature`

## Development

```bash
mix setup          # Install dependencies
mix test           # Run tests
mix lint           # Run linters (format, credo, dialyzer)
mix check          # Run all quality checks
mix docs           # Generate documentation
mix bench          # Run benchmarks
```

## Running NIF Tests

NIF tests require a Rust toolchain:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
mix test --include nif       # Run all tests including NIF
```

## Code Quality

Before submitting a PR, ensure:

- [ ] All tests pass: `mix test`
- [ ] Code is formatted: `mix format`
- [ ] Credo passes: `mix credo --strict`
- [ ] Dialyzer passes: `mix dialyzer`
- [ ] Documentation is updated

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` new features
- `fix:` bug fixes
- `docs:` documentation changes
- `refactor:` code refactoring
- `test:` test additions or changes
- `chore:` maintenance tasks

## Pull Request Process

1. Ensure your code follows the project style
2. Update documentation as needed
3. Add tests for new functionality
4. Update CHANGELOG.md with your changes
5. Submit a PR with a clear description

## Questions?

Open an issue for questions or discussions.
