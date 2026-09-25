# Contents

- `client-ts/` is the typed TypeScript client over `wire/` + `crypto/`:
  enrollment, device sessions, projection publish/subscribe, and the
  command lifecycle.

# Guidelines

- All wire I/O passes through `wire/` validators; the client never trusts
  server payloads.
- Data on stdout, diagnostics on stderr, closed exit codes; every output
  bound is declared in `wire/`.
