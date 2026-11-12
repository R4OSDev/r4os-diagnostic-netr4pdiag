# NETR4P.R4X

`NETR4P.R4X` is an independent R4OS diagnostic program implemented in Zig.

## Package

- Version: `0.1.11`
- Image target: `/R4OS/SOFTWARE/TERMINAL/DIAG/NETR4P.R4X`
- Image scope: `test`
- Canonical project manifest: `module.R4MF`

The manifest is the single source of truth for the artifact, imports, image
target, and package metadata.

## Build

On Windows:

    Build.bat

On Linux or macOS:

    ./Build.sh

The build starters resolve the current local R4OS dependency checkouts through
`Settings.R4S`. The URL and hash entries in `build.zig.zon` record the
last verified standalone dependency identities; workspace builds use the
mapped local checkouts.

## Documentation

Detailed German technical notes from the migration are preserved in
`DOCUMENTATION.de.txt`. Source-transfer provenance is recorded in
`PROVENANCE.txt`.

## License

Original R4OS material is licensed under Apache License 2.0. See `LICENSE`
and `NOTICE`. Any repository-specific external material is documented in
`THIRD_PARTY_NOTICES.md`.

Since0.84.34 the current diagnostic counts exactly eight active network roles.
SerialLink is retired and its old aliases are removed. The fixed ninth ABI
snapshot position is reserved; it is not an active or required protocol.
Unknown command options fail explicitly. Existing /SELFTEST and remaining
/EXPECT-MISSING=<network role> checks preserve their network assertions.

## Generation 2

The normal Start2/Query2 diagnostic uses the shared UTF8 argument cursor while preserving its server, TLS, benchmark and missing-role options. `/SELFTEST` first builds and independently checks real DNS R4P query bytes to activate the lazy module; the original eight-role assertions stay strict. Benchmark PUT uses full metadata and the shared borrowed path reader under one source deadline, exact offsets and metadata/revision checks; the existing 64 MB limit remains. Source bytes stay live until the web stream closes. R4P wire operations remain owned by their protocols.
