# Changelog

All notable changes to KeyFence are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-09-19

### Added

- Find a token carried inside a dotted, JWT-shaped value, and swap the whole
  value for the real credential. A client that will not carry an opaque string
  can now be brokered: codex reads its credential from a file, decodes it as a
  JWT, checks the expiry itself, and goes off to fetch a real credential of its
  own for anything it cannot parse. Issued as `header.payload.kf_...` it is
  satisfied and sends the whole thing as a bearer, while what reaches the
  upstream is the credential alone. A token carried this way inside Basic
  authentication is not recognised; the plain `kf_` form still is.

## [0.2.0] - 2026-09-18

### Added

- Add credential containment for mTLS client certificates and SSH private keys,
  including credential rotation without token reissuance.
- Add named credentials resolved from systemd credentials, local files, the OS
  keyring, or environment variables, plus `credential add`, `list`, and `rm`
  commands that never print secret values.
- Add destination path scoping, request budgets, Lua response rules, webhook
  delivery, Server-Sent Events, recent audit history, and OpenTelemetry traces.
- Add peer-authenticated Unix control sockets and systemd user socket activation.
- Add passthrough host and wildcard-domain rules for traffic that needs no
  credential.
- Add explicit and transparently redirected HTTP handling, connection reuse,
  WebSocket upgrades, and Basic authentication challenges.
- Add attenuated child tokens with inherited authority, lineage-aware quotas,
  and cascading revocation.
- Add standard command help (`-h`, `--help`, and `help`) and version reporting
  (`-V`, `--version`, and `version`) with build and project metadata.
- Add RPM packaging, release automation, worked examples, and an interactive
  container demo.

### Changed

- Bind all listeners to loopback by default.
- Require authentication for the TCP control API unless `--insecure-api` is
  explicitly selected.
- Require token destinations; an empty destination list now grants no access,
  while `"*"` explicitly requests unrestricted destinations.
- Authenticate upstream SSH hosts with `known_hosts` by default.
- Keep credentials only while a valid token references them, and resolve named
  credentials on each request so rotation takes effect automatically.
- Refuse a proxied request whose path is not already in normal form, rather than
  resolving it. A path carrying a `.`, `..`, or empty segment is rejected with
  `path_not_normal`; this includes the URL-in-path shape `/fetch/https://host`,
  which some clients use and which no longer reaches an upstream.

### Fixed

- Forward responses intact when they exceed the Lua inspection limit.
- Enforce request body limits for chunked requests without a declared length.
- Remove credential material from audit records and use stable derived token IDs.
- Avoid upstream HTTP/2 negotiation where it interferes with proxy response
  handling.
- Secure file-backed credential replacement with atomic mode-0600 writes that do
  not follow destination symlinks.
- Clear policy counters when token lineages are revoked or expire.

### Security

- Enforce destination path scoping and policy path rules against the path that
  is actually forwarded. A path decision was made on the request path as it
  arrived and the request was then forwarded with that path untouched, so a
  token scoped to `api.github.com/repos/*` accepted `/repos/../user/keys` and a
  normalising origin served `/user/keys` with the real credential injected. The
  same gap let `//admin/keys` and `/./admin/keys` past a `denied_paths` rule.
  Variants using a `;` parameter, a `\` separator, or double percent-encoding
  are refused as well.

## [0.1.0] - 2026-03-12

### Added

- Initial KeyFence release with HTTPS interception, opaque short-lived tokens,
  destination restrictions, policy enforcement, and structured audit logging.
