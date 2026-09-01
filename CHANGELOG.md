# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Note that `REDACTOR_VERSION` is versioned separately from the package. It pins
the output contract: any change to the redacted output of an input that
previously succeeded requires a `REDACTOR_VERSION` bump, regardless of what
happens to the package version.

## [0.1.0] - unreleased

### Added

- Initial extraction. `redact_message()`, `RedactionResult`, `RedactionKind`,
  `RedactionDropReason`, `REDACTOR_VERSION`.
- Credential detection via 22 detect-secrets plugins.
- PII redaction: email, phone, public IP, MAC, FQDN, hostname, path, URL.
- Obfuscation defence: NFKC normalisation, default-ignorable stripping,
  percent / JSON-escape / surrogate-pair decoding over up to three rounds.
- JSON-aware redaction by key name.
- PEM and PuTTY private key handling.
- Bounded execution under work, structure, obfuscation, and input-size limits.
- Post-redaction self-check that drops any message with surviving sensitive
  content.

`REDACTOR_VERSION` is `"1"`.
