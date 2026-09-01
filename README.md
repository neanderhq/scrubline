# scrubline

Deterministic, bounded redaction of secrets and PII from log lines.

`scrubline` wraps [detect-secrets](https://github.com/Yelp/detect-secrets) for
credential detection and adds the layers it does not cover: personal data,
obfuscation defence, structure-aware redaction, and a bounded work envelope.

```python
from scrubline import redact_message

result = redact_message(
    "user alice@example.com token ghp_16C7e42F292c6912E7710c838347Ae178B4a"
)

result.message  # 'user [REDACTED:EMAIL] token [REDACTED:API_KEY]'
result.fingerprint  # stable sha256 over the redacted message
result.changed  # True
result.drop_reason  # None
```

## Why not just detect-secrets

detect-secrets is excellent at what it does, and `scrubline` uses 22 of its
detector plugins directly. But it is a secret scanner for source trees, and a
log line is a different problem:

| | detect-secrets | scrubline |
|---|---|---|
| Cloud keys, API tokens, private keys | yes | yes (via detect-secrets) |
| Email, phone, public IP, MAC, hostname | no | yes |
| Percent-encoded or unicode-obfuscated input | no | yes |
| JSON-aware redaction by key name | no | yes |
| Bounded work per message | no | yes |
| Stable placeholders + output fingerprint | no | yes |

## Design guarantees

**Deterministic.** The same input always produces the same placeholders and the
same fingerprint. There is no model, no sampling, no ambient state. This is the
property that lets a second, independently written verifier re-check this
library's output without sharing any code with it — which is how it is used in
production.

**Pure.** The module imports no filesystem, network, or process-state APIs. A
test asserts this against the module's own AST, so it cannot regress silently.

**Bounded.** Every message runs under explicit work, structure, and obfuscation
limits, and a 256 KiB input cap. Adversarial input gets dropped with a reason,
never hangs the caller. Failure is always a typed `drop_reason`, never a partial
redaction.

**Fails closed.** After redacting, the result is re-scanned. If anything
sensitive survived, the message is dropped rather than emitted.

## Obfuscation handling

A secret does not stop being a secret because it was percent-encoded on the way
into the log. Before matching, `scrubline` normalises the message (NFKC), strips
default-ignorable and zero-width characters, and decodes percent escapes, JSON
`\uXXXX` escapes, and surrogate pairs — up to three rounds, so layered encodings
unwrap. Input that keeps changing after that is treated as hostile and dropped.

## Redaction kinds

`api_key`, `token`, `credential`, `cookie`, `private_key`, `dsn`, `secret`,
`environment`, `email`, `phone`, `ip_address`, `mac_address`, `username`,
`hostname`, `path`, `url`.

Private IPs and loopback addresses are left alone — they carry no identity and
redacting them destroys the debuggability that log collection exists for.

## Output contract

`REDACTOR_VERSION` pins the placeholder vocabulary and matching behaviour.
Consumers that persist redacted output should record it alongside. Any change
that alters the output for an input that previously succeeded is a version bump,
not a patch release.

## Install

```bash
pip install scrubline
```

## License

Apache-2.0. See [LICENSE](LICENSE).
