"""Deterministic, bounded redaction for log lines.

Wraps Yelp's detect-secrets for credential detection and adds the layers it
does not cover: PII, obfuscation defence, structure-aware redaction, and a
bounded work envelope.

The output contract is stable within a major version of ``REDACTOR_VERSION``:
the same input always produces the same placeholders and the same fingerprint.
That determinism is deliberate. It lets a second, independently written
verifier re-check the output of this library without sharing any code with it.
"""

from __future__ import annotations

from scrubline.redactor import (
    REDACTOR_VERSION,
    RedactionDropReason,
    RedactionKind,
    RedactionResult,
    redact_message,
)

__all__ = [
    "REDACTOR_VERSION",
    "RedactionDropReason",
    "RedactionKind",
    "RedactionResult",
    "redact_message",
]

__version__ = "0.1.0"
