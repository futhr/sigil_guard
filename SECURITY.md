# Security Policy

## Supported Versions

SigilGuard provides security fixes for the latest `1.x` release line.

After `1.0.0` is published, the final `0.2.x` release line receives security
fixes for six months.

## Reporting A Vulnerability

Report suspected vulnerabilities through GitHub private vulnerability
reporting for this repository. Do not open a public issue for an unpatched
vulnerability.

Please include:

- Affected version or commit.
- Reproduction steps or a proof of concept.
- Expected impact and affected surface.
- Any known mitigations.

## Response Targets

- Acknowledgement within 72 hours.
- Triage verdict within 7 days.
- Fix, coordinated disclosure plan, or public advisory within 90 days.

These are response targets, not guarantees. Complex reports may require
coordination with downstream applications or upstream protocol owners.

## Scope

In scope:

- SigilGuard runtime decisions, scanners, policies, audit proofs, vault
  primitives, trust bundles, attestation, and release provenance.
- Build, dependency, and release artifacts shipped by this repository.

Out of scope:

- Host application authentication, transport security, sandbox provisioning,
  deployment policy, or remote network services.
- Vulnerabilities caused by unsafe host integration outside SigilGuard's public
  contracts.

## Signer Compromise

Treat signing-key compromise as an incident. For trust-bundle signer compromise,
follow the emergency rotation ceremony defined in the trust-bundle
specification, found under `docs/specs/` in the source repository.

## Repository Secret Scanning

`./bin/check-secrets` scans the complete Git history with a pinned Gitleaks
release and verifies the downloaded archive checksum before execution. The
canonical `./bin/check` gate runs it in CI and locally.

SigilGuard's scanner tests deliberately contain synthetic credential-shaped
strings. `.gitleaksignore` acknowledges only the exact reviewed historical
fingerprints for those fixtures. Do not add path-wide exclusions: any changed
or new credential-shaped fixture must be reviewed as a fresh finding.
