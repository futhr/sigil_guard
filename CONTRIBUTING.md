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

## Releasing

Releases are managed by maintainers using git_ops:

1. Ensure all tests pass: `mix check`
2. Run `mix release` (alias for `mix git_ops.release`) — updates changelog, bumps version, commits, and tags
3. Push with tags: `git push --follow-tags`
4. CI will publish to Hex.pm on the `v*` tag

The publish workflow builds a release tarball preview, generates an SPDX SBOM
with `mix sigil_guard.sbom`, uploads both as workflow artifacts, and creates
GitHub artifact attestations for package provenance and SBOM linkage before
publishing.

## Pull Request Process

1. Ensure your code follows the project style
2. Update documentation as needed
3. Add tests for new functionality
4. Submit a PR with a clear description

## Questions?

Open an issue for questions or discussions.
