# SigilGuard Naming Standard

## Canonical Terms

| Term | Use |
|------|-----|
| SigilGuard | Project and package name. |
| sigil | Project idiom and compatibility heritage, not a live dependency. |
| Trust Profile | SigilGuard-owned security profile for embedded runtime decisions. |
| Trust Bundle | Signed local trust material: keys, tools, policies, patterns, revocations. |
| Attestation | Signed typed statement about request/result/decision evidence. |
| Tool Manifest | Signed/hashable MCP tool definition and schema metadata. |
| Compatibility Contract | Existing public API or wire shape current consumers rely on. |
| Legacy Remote Bundle | Explicit optional HTTP-loaded bundle for compatibility. |

## Avoid

- Do not describe SigilGuard as a hosted registry client.
- Do not use public registry language as the default path.
- Do not use old protocol names as the strategic architecture.
- Do not introduce direct integration with outside inspiration projects.
