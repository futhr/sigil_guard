# Library maintenance

The Hex package contains runtime modules, integration guides and notebooks.
Repository development instructions are maintained with the source checkout:
read [CLAUDE.md](https://github.com/refpath/sigil_guard/blob/main/CLAUDE.md)
and the [repository workflows](https://github.com/refpath/sigil_guard/tree/main/.claude).
Clone that repository before running its tests or development scripts; those
instructions do not assume that a Hex installation includes the development tree.

The core runtime dependencies are Jason, NimbleOptions and Telemetry. HTTP
transports, authentication and durable cross-boot trust state belong to the host.
