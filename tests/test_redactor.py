from __future__ import annotations

import ast
import json
import random
from pathlib import Path
from urllib.parse import quote

import pytest
from pydantic import ValidationError

import scrubline.redactor as redactor_module
from scrubline.redactor import (
    REDACTOR_VERSION,
    RedactionDropReason,
    RedactionKind,
    RedactionResult,
    redact_message,
)

_FIXTURE_DIR = Path(__file__).parent / "fixtures"


def _load_fixture(name: str) -> object:
    return json.loads((_FIXTURE_DIR / name).read_text(encoding="ascii"))


def _positive_inputs(kind: str) -> list[tuple[str, str, str]]:
    parts = _load_fixture("planted_secret_parts.json")
    cases = _load_fixture("redaction_cases.json")
    assert isinstance(parts, dict)
    assert isinstance(cases, dict)
    values = ["".join(value_parts) for value_parts in parts[kind]]
    case = cases["positive_cases"][kind]
    return [
        (
            f"{kind}-{index + 1}",
            case["templates"][index].format(needle=values[index]),
            case["expected"][index],
        )
        for index in range(2)
    ]


def _assert_message(case_id: str, actual: str | None, expected: str) -> None:
    if actual != expected:
        pytest.fail(f"{case_id}: sanitized message mismatch", pytrace=False)


def _assert_drop(
    case_id: str, result: RedactionResult, reason: RedactionDropReason
) -> None:
    if result.drop_reason is not reason or result.message is not None:
        pytest.fail(f"{case_id}: wrong fail-closed result", pytrace=False)


def test_fixture_never_stores_an_assembled_planted_value() -> None:
    """Catch a complete synthetic credential being persisted in fixture text."""
    fixture_path = _FIXTURE_DIR / "planted_secret_parts.json"
    fixture_text = fixture_path.read_text(encoding="ascii")
    parts = json.loads(fixture_text)
    for kind, variants in parts.items():
        for index, fragments in enumerate(variants):
            if "".join(fragments) in fixture_text:
                pytest.fail(
                    f"fixture-{kind}-{index}: assembled value stored", pytrace=False
                )


def test_public_contract_is_strict_and_content_free_in_repr() -> None:
    """Catch mutable results, leaking reprs, or an incompatible v1 surface."""
    result = RedactionResult(
        message="synthetic-private-content",
        fingerprint=(
            "1a3fa4407db36e3235ff98b8480767b517861c76fbba1adabb66f43714c26ebb"
        ),
        drop_reason=None,
        changed=False,
        truncated=False,
    )

    assert REDACTOR_VERSION == "1"
    assert result.message == "synthetic-private-content"
    assert result.fingerprint == (
        "1a3fa4407db36e3235ff98b8480767b517861c76fbba1adabb66f43714c26ebb"
    )
    assert repr(result) == (
        "RedactionResult(drop_reason=None, changed=False, truncated=False)"
    )
    assert tuple(reason.value for reason in RedactionDropReason) == (
        "invalid_input",
        "input_too_large",
        "obfuscation_limit",
        "structure_limit",
        "malformed_structure",
        "work_limit",
        "internal_error",
    )
    with pytest.raises(ValidationError):
        result.changed = True


@pytest.mark.parametrize(
    "overrides",
    [
        {"message": "content", "fingerprint": None, "drop_reason": None},
        {"message": None, "fingerprint": "hash", "drop_reason": None},
        {
            "message": "content",
            "fingerprint": "hash",
            "drop_reason": RedactionDropReason.INTERNAL_ERROR,
        },
        {
            "message": None,
            "fingerprint": None,
            "drop_reason": RedactionDropReason.INTERNAL_ERROR,
            "changed": True,
        },
        {
            "message": None,
            "fingerprint": None,
            "drop_reason": RedactionDropReason.INTERNAL_ERROR,
            "truncated": True,
        },
        {"changed": 0},
        {"unexpected": "value"},
    ],
)
def test_result_cross_field_invariant_rejects_ambiguous_states(
    overrides: dict[str, object],
) -> None:
    """Catch partial content or changed/truncated failure metadata."""
    values: dict[str, object] = {
        "message": None,
        "fingerprint": None,
        "drop_reason": RedactionDropReason.INTERNAL_ERROR,
        "changed": False,
        "truncated": False,
    }
    values.update(overrides)

    with pytest.raises(ValidationError):
        RedactionResult(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "overrides",
    [
        {"fingerprint": "0" * 63},
        {"fingerprint": "A" * 64},
        {"fingerprint": "g" * 64},
        {
            "fingerprint": "4d409dee6e99db77a12e032b7f3a4e3d7a21ab7127ae3d142a3a26bc0a20e7d5"
        },
        {"changed": False, "truncated": True},
    ],
)
def test_success_result_fingerprint_and_truncation_invariants_are_exact(
    overrides: dict[str, object],
) -> None:
    """Catch caller-constructed success metadata that cannot describe its message."""
    values: dict[str, object] = {
        "message": "synthetic-private-content",
        "fingerprint": (
            "1a3fa4407db36e3235ff98b8480767b517861c76fbba1adabb66f43714c26ebb"
        ),
        "drop_reason": None,
        "changed": True,
        "truncated": False,
    }
    values.update(overrides)
    with pytest.raises(ValidationError):
        RedactionResult(**values)  # type: ignore[arg-type]


def test_public_validation_errors_never_render_caller_input() -> None:
    """Catch Pydantic text or repr echoing invalid result content."""
    parts = _load_fixture("planted_secret_parts.json")
    assert isinstance(parts, dict)
    planted = "".join(parts["secret"][0])
    cases = (
        (
            "validation-fingerprint",
            {
                "message": planted,
                "fingerprint": "synthetic-invalid-fingerprint",
                "drop_reason": None,
                "changed": True,
                "truncated": False,
            },
            (planted, "synthetic-invalid-fingerprint"),
        ),
        (
            "validation-unencodable",
            {
                "message": "\ud800",
                "fingerprint": "synthetic-unencodable-fingerprint",
                "drop_reason": None,
                "changed": True,
                "truncated": False,
            },
            ("\ud800", "synthetic-unencodable-fingerprint"),
        ),
        (
            "validation-extra",
            {
                "message": None,
                "fingerprint": None,
                "drop_reason": RedactionDropReason.INTERNAL_ERROR,
                "changed": False,
                "truncated": False,
                "unexpected": "synthetic-extra-input",
            },
            ("synthetic-extra-input",),
        ),
    )
    for case_id, values, needles in cases:
        try:
            RedactionResult(**values)  # type: ignore[arg-type]
        except ValidationError as error:
            rendered = str(error) + repr(error)
        except Exception:  # noqa: BLE001 - public boundary must normalize errors
            pytest.fail(f"{case_id}: non-validation exception escaped", pytrace=False)
        else:
            pytest.fail(f"{case_id}: invalid result accepted", pytrace=False)
        if any(needle in rendered for needle in needles):
            pytest.fail(f"{case_id}: input reached validation rendering", pytrace=False)


def test_redaction_kind_vocabulary_is_exact() -> None:
    """Catch a placeholder kind being added, removed, or renamed in v1."""
    assert tuple(kind.value for kind in RedactionKind) == (
        "api_key",
        "token",
        "credential",
        "cookie",
        "private_key",
        "dsn",
        "secret",
        "environment",
        "email",
        "phone",
        "ip_address",
        "mac_address",
        "username",
        "hostname",
        "path",
        "url",
    )


def test_safe_message_has_known_fingerprint_and_no_content_change() -> None:
    """Catch fingerprint domain drift or mutation of an already-safe message."""
    assert redact_message("build finished") == RedactionResult(
        message="build finished",
        fingerprint="dd5ecb40468f1c005c7f07963fff6a4fe1bfd4080c8dc3c75885c8bb89ff3477",
        drop_reason=None,
        changed=False,
        truncated=False,
    )


@pytest.mark.parametrize(
    "message", [None, b"text", 7, type("S", (str,), {})("text"), "\ud800"]
)
def test_invalid_input_fails_closed_without_content(message: object) -> None:
    """Catch coercion or exception leakage at the worker's string boundary."""
    assert redact_message(message) == RedactionResult(  # type: ignore[arg-type]
        message=None,
        fingerprint=None,
        drop_reason=RedactionDropReason.INVALID_INPUT,
        changed=False,
        truncated=False,
    )


def test_utf8_input_limit_accepts_boundary_and_rejects_next_byte() -> None:
    """Catch character-count limits or partial output above 256 KiB."""
    at_limit = "a" * (256 * 1024)
    over_limit = at_limit + "a"

    assert redact_message(at_limit).drop_reason is None
    assert redact_message(over_limit) == RedactionResult(
        message=None,
        fingerprint=None,
        drop_reason=RedactionDropReason.INPUT_TOO_LARGE,
        changed=False,
        truncated=False,
    )


def test_normalization_joins_obfuscation_and_canonicalizes_lines() -> None:
    """Catch invisible/control characters surviving or separating later matches."""
    result = redact_message("ｂｕ\u200bｉｌｄ\tok\r\nnext\x00line\u202e")

    assert result.message == "build ok\nnextline"
    assert result.changed is True
    assert result.drop_reason is None


def test_all_bounded_default_ignorables_are_removed_before_matching() -> None:
    """Catch non-Cf default-ignorables shielding a sensitive label."""
    codepoints = (
        0x034F,
        0x180B,
        0x180F,
        0x200B,
        0x2060,
        0x3164,
        0xFE0F,
        0xFFA0,
        0x1BCA0,
        0x1D173,
        0xE0001,
        0xE0100,
    )
    for codepoint in codepoints:
        message = f"to{chr(codepoint)}ken=x"
        _assert_message(
            f"default-ignorable-{codepoint:x}",
            redact_message(message).message,
            "token=[REDACTED:TOKEN]",
        )


@pytest.mark.parametrize(
    ("encoded", "expected"),
    [
        ("status%20ok", "status ok"),
        ("status%2520ok", "status ok"),
        ("status%252520ok", "status ok"),
        (r"\u0062uild", "build"),
        (r"\U00000062uild", "build"),
        (r"\x62uild", "build"),
        (r"launch=\uD83D\uDE80", "launch=🚀"),
    ],
)
def test_valid_obfuscation_decodes_through_three_rounds(
    encoded: str, expected: str
) -> None:
    """Catch missed valid escape forms or a decoder that stops too early."""
    result = redact_message(encoded)

    assert result.message == expected
    assert result.changed is True
    assert result.drop_reason is None


@pytest.mark.parametrize("message", ["status%25252520ok", r"value=\uD800"])
def test_excess_or_malformed_obfuscation_fails_closed(message: str) -> None:
    """Catch a fourth encoding layer or malformed surrogate reaching output."""
    assert redact_message(message) == RedactionResult(
        message=None,
        fingerprint=None,
        drop_reason=RedactionDropReason.OBFUSCATION_LIMIT,
        changed=False,
        truncated=False,
    )


def test_percent_decoding_cannot_be_shielded_by_invalid_utf8_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch invalid percent bytes shielding a provider key or error misclassification."""
    parts = _load_fixture("planted_secret_parts.json")
    assert isinstance(parts, dict)
    planted = "".join(parts["api_key"][0])
    octets = [f"%{byte:02X}" for byte in planted.encode("utf-8")]
    encoded = "".join(octets)
    invalid_cases = (
        "%FF" + encoded,
        "".join(octets[: len(octets) // 2])
        + "%FF"
        + "".join(octets[len(octets) // 2 :]),
        encoded + "%FF",
    )
    for index, message in enumerate(invalid_cases):
        _assert_drop(
            f"percent-invalid-{index}",
            redact_message(message),
            RedactionDropReason.OBFUSCATION_LIMIT,
        )

    partial = "%73%6B" + planted[2:]
    _assert_message(
        "percent-partial",
        redact_message(partial).message,
        "[REDACTED:API_KEY]",
    )
    layered = encoded
    for layer in range(1, 4):
        _assert_message(
            f"percent-layer-{layer}",
            redact_message(layered).message,
            "[REDACTED:API_KEY]",
        )
        layered = quote(layered, safe="")
    _assert_drop(
        "percent-layer-4",
        redact_message(layered),
        RedactionDropReason.OBFUSCATION_LIMIT,
    )

    def unexpected_value_error(_message: str) -> str:
        raise ValueError("fixed-test-error")

    monkeypatch.setattr(redactor_module, "_normalize", unexpected_value_error)
    _assert_drop(
        "percent-unexpected-value-error",
        redact_message("safe text"),
        RedactionDropReason.INTERNAL_ERROR,
    )


def test_malformed_percent_escapes_cannot_split_encoded_credentials() -> None:
    """Catch partial or non-hex escapes shielding an encoded provider value."""
    parts = _load_fixture("planted_secret_parts.json")
    assert isinstance(parts, dict)
    planted = "".join(parts["api_key"][0])
    octets = [f"%{byte:02X}" for byte in planted.encode("utf-8")]
    midpoint = len(octets) // 2
    cases = (
        ("percent-malformed-leading", "%GG" + "".join(octets)),
        (
            "percent-partial-middle",
            "".join(octets[:midpoint]) + "%A" + "".join(octets[midpoint:]),
        ),
        ("percent-malformed-trailing", "".join(octets) + "%GG"),
        (
            "percent-mixed-invalid",
            "%73%6B%GG" + "".join(octets[2:]),
        ),
    )
    for case_id, message in cases:
        _assert_drop(
            case_id,
            redact_message(message),
            RedactionDropReason.OBFUSCATION_LIMIT,
        )
    _assert_message(
        "percent-ordinary-prose",
        redact_message("progress 100% complete").message,
        "progress 100% complete",
    )


def test_provider_shaped_api_keys_use_exact_typed_placeholder() -> None:
    """Catch provider prefixes or key material surviving API-key redaction."""
    for case_id, message, expected in _positive_inputs("api_key"):
        result = redact_message(message)
        _assert_message(case_id, result.message, expected)


def test_bearer_jwt_and_token_assignment_precedence_is_exact() -> None:
    """Catch authorization syntax or JWT segments surviving as generic text."""
    for case_id, message, expected in _positive_inputs("token"):
        result = redact_message(message.swapcase() if case_id == "token-1" else message)
        if case_id == "token-1":
            expected = "[REDACTED:TOKEN]"
        _assert_message(case_id, result.message, expected)


def test_basic_authorization_redacts_the_complete_credential() -> None:
    """Catch a Basic payload or its scheme prefix surviving redaction."""
    for case_id, message, expected in _positive_inputs("credential"):
        if case_id == "credential-1":
            message = "bAsIc " + message.removeprefix("Basic ")
        result = redact_message(message)
        _assert_message(case_id, result.message, expected)


def test_cookie_headers_redact_the_full_header_value() -> None:
    """Catch cookie names, values, or attributes surviving a header match."""
    for case_id, message, expected in _positive_inputs("cookie"):
        result = redact_message(message.swapcase())
        expected = expected.replace("Cookie", "cOOKIE").replace(
            "set-cookie", "SET-COOKIE"
        )
        _assert_message(case_id, result.message, expected)


def test_multiline_private_keys_are_one_typed_replacement() -> None:
    """Catch private-key headers, bodies, or footers surviving independently."""
    for case_id, message, expected in _positive_inputs("private_key"):
        result = redact_message(message)
        _assert_message(case_id, result.message, expected)


def test_private_key_marker_scanner_is_bounded_and_fails_closed() -> None:
    """Catch oversized, incomplete, mismatched, or variant private-key leakage."""

    def pem(label: str, body: str, end_label: str | None = None) -> str:
        closing = label if end_label is None else end_label
        return f"-----BEGIN {label}-----\n{body}\n-----END {closing}-----"

    for case_id, label in (
        ("private-pem", "PRIVATE KEY"),
        ("private-openssh", "OPENSSH PRIVATE KEY"),
        ("private-pgp", "PGP PRIVATE KEY BLOCK"),
    ):
        result = redact_message(f"before {pem(label, 'QQ==')} after")
        _assert_message(
            case_id,
            result.message,
            "before [REDACTED:PRIVATE_KEY] after",
        )

    putty = (
        "PuTTY-User-Key-File-2: ssh-rsa\n"
        "Encryption: none\nComment: synthetic\nPublic-Lines: 1\nQQ==\n"
        "Private-Lines: 1\nQg==\nPrivate-MAC: 00aa"
    )
    _assert_message(
        "private-putty",
        redact_message(f"before {putty} after").message,
        "before [REDACTED:PRIVATE_KEY] after",
    )

    for body_size in (65535, 65536):
        _assert_message(
            f"private-body-{body_size}",
            redact_message(pem("PRIVATE KEY", "Q" * body_size)).message,
            "[REDACTED:PRIVATE_KEY]",
        )
    _assert_drop(
        "private-body-65537",
        redact_message(pem("PRIVATE KEY", "Q" * 65537)),
        RedactionDropReason.WORK_LIMIT,
    )
    _assert_drop(
        "private-incomplete",
        redact_message("-----BEGIN PRIVATE KEY-----\nQQ=="),
        RedactionDropReason.MALFORMED_STRUCTURE,
    )
    _assert_drop(
        "private-mismatched",
        redact_message(pem("PRIVATE KEY", "QQ==", "OPENSSH PRIVATE KEY")),
        RedactionDropReason.MALFORMED_STRUCTURE,
    )

    opening = "-----BEGIN PRIVATE KEY-----\n"
    exact_input = opening + "Q" * (256 * 1024 - len(opening))
    _assert_drop(
        "private-input-at-limit",
        redact_message(exact_input),
        RedactionDropReason.WORK_LIMIT,
    )
    _assert_drop(
        "private-input-over-limit",
        redact_message(exact_input + "Q"),
        RedactionDropReason.INPUT_TOO_LARGE,
    )


def test_unmatched_private_key_closing_and_tail_markers_fail_closed() -> None:
    """Catch records that begin partway through private-key material."""
    cases = (
        ("private-tail-pem", "QQ==\n-----END PRIVATE KEY-----"),
        ("private-tail-openssh", "QQ==\n-----END OPENSSH PRIVATE KEY-----"),
        ("private-tail-pgp", "QQ==\n-----END PGP PRIVATE KEY BLOCK-----"),
        ("private-tail-lines", "Private-Lines: 1\nQQ=="),
        ("private-tail-mac", "Private-MAC: 00aa"),
    )
    for case_id, message in cases:
        _assert_drop(
            case_id,
            redact_message(message),
            RedactionDropReason.MALFORMED_STRUCTURE,
        )


def test_dsn_precedence_replaces_the_entire_connection_string() -> None:
    """Catch DSN credentials, hosts, queries, or URL classification surviving."""
    for case_id, message, expected in _positive_inputs("dsn"):
        result = redact_message(message)
        _assert_message(case_id, result.message, expected)


def test_absolute_and_scheme_relative_urls_are_whole_replacements() -> None:
    """Catch URL credentials, queries, fragments, or IPv6 hosts surviving."""
    for case_id, message, expected in _positive_inputs("url"):
        if case_id == "url-1":
            message = message.replace("https://", "https%3A%2F%2F")
        result = redact_message(message)
        _assert_message(case_id, result.message, expected)

    ipv6_result = redact_message("request http://[2606:4700:4700::1111]/a?q=x#f")
    _assert_message("url-ipv6", ipv6_result.message, "request [REDACTED:URL]")


def test_generic_sensitive_assignments_redact_only_the_value() -> None:
    """Catch secret-bearing labels leaking values or becoming untyped tokens."""
    for case_id, message, expected in _positive_inputs("secret"):
        result = redact_message(message)
        _assert_message(case_id, result.message, expected)


def test_sensitive_context_redacts_any_nonempty_value_with_exact_precedence() -> None:
    """Catch short, quoted, mixed-case, proxy, or overlapping contextual leaks."""
    parts = _load_fixture("planted_secret_parts.json")
    assert isinstance(parts, dict)
    provider_value = "".join(parts["api_key"][0])
    cases = (
        (
            "context-basic-short",
            "Authorization: Basic x",
            "Authorization: [REDACTED:CREDENTIAL]",
        ),
        (
            "context-proxy-basic",
            "Proxy-Authorization = basic 'x'",
            "Proxy-Authorization = [REDACTED:CREDENTIAL]",
        ),
        (
            "context-bearer-short",
            "authorization: bearer x",
            "authorization: [REDACTED:TOKEN]",
        ),
        (
            "context-proxy-bearer",
            'Proxy-Authorization: Bearer "x"',
            "Proxy-Authorization: [REDACTED:TOKEN]",
        ),
        (
            "context-jwt-short",
            "Authorization: JWT x",
            "Authorization: [REDACTED:TOKEN]",
        ),
        ("context-token-one", "token=x", "token=[REDACTED:TOKEN]"),
        ("context-token-quoted", "token : 'x y'", "token : [REDACTED:TOKEN]"),
        ("context-api-key", 'api-key = "x"', "api-key = [REDACTED:API_KEY]"),
        ("context-secret", "secret: x", "secret: [REDACTED:SECRET]"),
        ("context-password", 'password = "x y"', "password = [REDACTED:SECRET]"),
        ("context-credential", "credential=x", "credential=[REDACTED:CREDENTIAL]"),
        (
            "context-private-key",
            "private-key: x",
            "private-key: [REDACTED:PRIVATE_KEY]",
        ),
        (
            "context-env-mixed",
            "Database_Token=x",
            "Database_Token=[REDACTED:ENVIRONMENT]",
        ),
        ("context-empty", "token=", "token="),
        ("context-empty-quoted", 'token=""', 'token=""'),
        ("context-overlap", f"secret={provider_value}", "secret=[REDACTED:SECRET]"),
        (
            "context-url-precedence",
            "secret=https://synthetic.invalid/a?q=x",
            "secret=[REDACTED:URL]",
        ),
        (
            "context-auth-env-overlap",
            "env Authorization=Basic x",
            "env Authorization=[REDACTED:CREDENTIAL]",
        ),
    )
    for case_id, message, expected in cases:
        _assert_message(case_id, redact_message(message).message, expected)


def test_authorization_contexts_and_escaped_quotes_consume_the_full_value() -> None:
    """Catch unknown auth schemes or escaped suffixes leaking credential fragments."""
    cases = (
        (
            "auth-digest",
            'Authorization: Digest username="synthetic", nonce="fixed"',
            "Authorization: [REDACTED:CREDENTIAL]",
        ),
        (
            "auth-bare",
            "Authorization=opaque",
            "Authorization=[REDACTED:CREDENTIAL]",
        ),
        (
            "auth-proxy-custom",
            'Proxy-Authorization: Custom "synthetic value"',
            "Proxy-Authorization: [REDACTED:CREDENTIAL]",
        ),
        (
            "auth-known-bearer",
            "Authorization: Bearer x",
            "Authorization: [REDACTED:TOKEN]",
        ),
        ("auth-generic-short", "auth=x", "auth=[REDACTED:CREDENTIAL]"),
        (
            "authentication-quoted",
            "authentication='synthetic value'",
            "authentication=[REDACTED:CREDENTIAL]",
        ),
        (
            "auth-escaped-double",
            'password="synthetic\\" suffix" end',
            "password=[REDACTED:SECRET] end",
        ),
        (
            "auth-escaped-single",
            "token='synthetic\\' suffix' end",
            "token=[REDACTED:TOKEN] end",
        ),
        ("auth-empty", "Authorization:", "Authorization:"),
    )
    for case_id, message, expected in cases:
        _assert_message(case_id, redact_message(message).message, expected)


def test_generic_secret_fallback_catches_secret_shaped_bare_values() -> None:
    """Catch an unlabelled secret-shaped value after higher-precedence rules."""
    parts = _load_fixture("planted_secret_parts.json")
    assert isinstance(parts, dict)
    planted = "".join(parts["secret"][0])

    result = redact_message(f"opaque {planted}")

    _assert_message("secret-fallback", result.message, "opaque [REDACTED:SECRET]")


def test_environment_secret_assignments_use_environment_precedence() -> None:
    """Catch environment values being preserved or downgraded to generic secret."""
    for case_id, message, expected in _positive_inputs("environment"):
        result = redact_message(message)
        _assert_message(case_id, result.message, expected)

    multiline = redact_message('env AUTH_TOKEN="first line\nsecond line"')
    _assert_message(
        "environment-multiline",
        multiline.message,
        "env AUTH_TOKEN=[REDACTED:ENVIRONMENT]",
    )


def test_stable_detect_secrets_provider_finding_is_redacted() -> None:
    """Catch removal or ambient misconfiguration of deterministic detectors."""
    parts = _load_fixture("planted_secret_parts.json")
    assert isinstance(parts, dict)
    detector_only_value = "".join(parts["api_key"][2])

    result = redact_message(f"aws access id {detector_only_value}")

    _assert_message(
        "api-key-detector",
        result.message,
        "aws access id [REDACTED:API_KEY]",
    )


def test_detector_filters_cannot_log_or_preserve_provider_values(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Catch detector filtering leaking a rejected finding through output or logs."""
    parts = _load_fixture("planted_secret_parts.json")
    assert isinstance(parts, dict)
    planted = "".join(parts["api_key"][3])

    with caplog.at_level("INFO"):
        result = redact_message(f"aws access id {planted}")

    _assert_message(
        "api-key-detector-filter",
        result.message,
        "aws access id [REDACTED:API_KEY]",
    )
    if planted in caplog.text:
        pytest.fail(
            "api-key-detector-filter: planted value reached logs", pytrace=False
        )


def test_deterministic_detector_matrix_is_complete_and_stably_mapped() -> None:
    """Catch provider drift, wrong detector selection, or unstable kind mapping."""
    expected_classes = {
        "AWSKeyDetector",
        "ArtifactoryDetector",
        "AzureStorageKeyDetector",
        "BasicAuthDetector",
        "CloudantDetector",
        "DiscordBotTokenDetector",
        "GitHubTokenDetector",
        "GitLabTokenDetector",
        "IbmCloudIamDetector",
        "IbmCosHmacDetector",
        "JwtTokenDetector",
        "KeywordDetector",
        "MailchimpDetector",
        "NpmDetector",
        "OpenAIDetector",
        "PrivateKeyDetector",
        "PypiTokenDetector",
        "SendGridDetector",
        "SlackDetector",
        "SoftlayerDetector",
        "SquareOAuthDetector",
        "StripeDetector",
        "TelegramBotTokenDetector",
        "TwilioKeyDetector",
    }
    detectors = {
        type(detector).__name__: detector for detector in redactor_module._DETECTORS
    }
    if set(detectors) != expected_classes:
        pytest.fail("detector-matrix: class set drifted", pytrace=False)

    parts = _load_fixture("planted_secret_parts.json")
    assert isinstance(parts, dict)
    samples = parts["detector_samples"]
    table = (
        ("ArtifactoryDetector", 0, "{needle}", "[REDACTED:API_KEY]"),
        ("AWSKeyDetector", 1, "{needle}", "[REDACTED:API_KEY]"),
        ("AzureStorageKeyDetector", 2, "{needle}", "[REDACTED:API_KEY]"),
        (
            "BasicAuthDetector",
            3,
            "https://synthetic:{needle}@host.invalid",
            "[REDACTED:CREDENTIAL]",
        ),
        ("CloudantDetector", 4, "cloudant_apikey={needle}", "[REDACTED:API_KEY]"),
        ("DiscordBotTokenDetector", 5, "{needle}", "[REDACTED:API_KEY]"),
        ("GitHubTokenDetector", 6, "{needle}", "[REDACTED:API_KEY]"),
        ("GitLabTokenDetector", 7, "{needle}", "[REDACTED:API_KEY]"),
        (
            "IbmCosHmacDetector",
            8,
            "cos_hmac_secret_access_key={needle}",
            "[REDACTED:API_KEY]",
        ),
        (
            "IbmCloudIamDetector",
            9,
            "ibm_cloud_iam_api_key={needle}",
            "[REDACTED:API_KEY]",
        ),
        ("JwtTokenDetector", 10, "{needle}", "[REDACTED:TOKEN]"),
        ("KeywordDetector", 11, 'secret = "{needle}"', "[REDACTED:SECRET]"),
        ("MailchimpDetector", 12, "{needle}", "[REDACTED:API_KEY]"),
        (
            "NpmDetector",
            13,
            "//registry.invalid/:_authToken={needle}",
            "[REDACTED:API_KEY]",
        ),
        ("OpenAIDetector", 14, "{needle}", "[REDACTED:API_KEY]"),
        (
            "PrivateKeyDetector",
            15,
            "-----{needle}-----\nQQ==\n-----END PRIVATE KEY-----",
            "[REDACTED:PRIVATE_KEY]",
        ),
        ("PypiTokenDetector", 16, "{needle}", "[REDACTED:API_KEY]"),
        ("SendGridDetector", 17, "{needle}", "[REDACTED:API_KEY]"),
        ("SlackDetector", 18, "{needle}", "[REDACTED:API_KEY]"),
        ("SoftlayerDetector", 19, "softlayer_api_key={needle}", "[REDACTED:API_KEY]"),
        ("SquareOAuthDetector", 20, "{needle}", "[REDACTED:API_KEY]"),
        ("StripeDetector", 21, "{needle}", "[REDACTED:API_KEY]"),
        ("TelegramBotTokenDetector", 22, "{needle}", "[REDACTED:API_KEY]"),
        ("TwilioKeyDetector", 23, "{needle}", "[REDACTED:API_KEY]"),
    )
    for class_name, index, template, placeholder in table:
        needle = "".join(samples[index])
        message = template.format(needle=needle)
        matches = (
            redactor_module._detector_values(detectors[class_name], message)
            if class_name in detectors
            else ()
        )
        if needle not in matches:
            pytest.fail(
                f"detector-{class_name}: intended sample not recognized", pytrace=False
            )
        stage = redactor_module._redact_detected(message)
        if needle in stage or placeholder not in stage:
            pytest.fail(
                f"detector-{class_name}: unstable placeholder mapping", pytrace=False
            )
        result = redact_message(message)
        if result.message is None or needle in result.message:
            pytest.fail(
                f"detector-{class_name}: public redaction leaked", pytrace=False
            )


def test_email_addresses_use_exact_typed_placeholder() -> None:
    """Catch local or domain portions surviving email redaction."""
    for case_id, message, expected in _positive_inputs("email"):
        result = redact_message(message)
        _assert_message(case_id, result.message, expected)


def test_absolute_paths_redact_but_relative_frames_survive() -> None:
    """Catch absolute path leakage or over-redaction of relative stack frames."""
    for case_id, message, expected in _positive_inputs("path"):
        result = redact_message(message)
        _assert_message(case_id, result.message, expected)

    _assert_message(
        "path-linux",
        redact_message("opened /home/synthetic/app.log").message,
        "opened [REDACTED:PATH]",
    )
    _assert_message(
        "path-unc",
        redact_message(r"opened \\synthetic-server\share\app.log").message,
        "opened [REDACTED:PATH]",
    )
    assert redact_message("src/main.py:42").message == "src/main.py:42"


def test_extended_url_path_and_pii_candidates_are_complete_and_validated() -> None:
    """Catch supported global addresses and quoted PII leaking partial values."""
    cases = (
        ("extended-ws", "connect ws://host.invalid/a?q=x", "connect [REDACTED:URL]"),
        ("extended-wss", "connect wss://host.invalid/a", "connect [REDACTED:URL]"),
        (
            "extended-posix-space",
            "opened '/Users/Synthetic Person/Library Logs/app.log'",
            "opened '[REDACTED:PATH]'",
        ),
        (
            "extended-drive-slash",
            'opened "C:/Users/Synthetic Person/App Data/app.log"',
            'opened "[REDACTED:PATH]"',
        ),
        (
            "extended-drive-backslash",
            'opened "C:\\Users\\Synthetic Person\\App Data\\app.log"',
            'opened "[REDACTED:PATH]"',
        ),
        (
            "extended-unc-space",
            'opened "\\\\synthetic-server\\share name\\app.log"',
            'opened "[REDACTED:PATH]"',
        ),
        (
            "extended-ipv4-port",
            "remote 8.8.8.8:443",
            "remote [REDACTED:IP_ADDRESS]:443",
        ),
        (
            "extended-ipv6-bracket",
            "remote [2606:4700:4700::1111]:443",
            "remote [REDACTED:IP_ADDRESS]:443",
        ),
        (
            "extended-ipv6-compressed",
            "remote 2001:4860:4860::8888",
            "remote [REDACTED:IP_ADDRESS]",
        ),
        (
            "extended-ipv6-scoped",
            "remote 2606:4700:4700::1111%en0",
            "remote [REDACTED:IP_ADDRESS]",
        ),
        (
            "extended-ipv6-embedded",
            "remote 64:ff9b::808:808",
            "remote [REDACTED:IP_ADDRESS]",
        ),
        (
            "extended-ipv6-mapped",
            "remote ::ffff:8.8.8.8",
            "remote [REDACTED:IP_ADDRESS]",
        ),
        (
            "extended-uk-phone",
            "call +44 (0)20 7946 0958",
            "call [REDACTED:PHONE]",
        ),
        (
            "extended-long-user",
            "user='" + "synthetic user " * 8 + "' end",
            "user=[REDACTED:USERNAME] end",
        ),
        (
            "extended-long-host",
            'host="' + "node-" * 70 + '.example.invalid" end',
            "host=[REDACTED:HOSTNAME] end",
        ),
        (
            "extended-unicode-email",
            "contact δοκιμή@παράδειγμα.δοκιμή",
            "contact [REDACTED:EMAIL]",
        ),
        (
            "extended-idn-host",
            "remote δοκιμή.παράδειγμα",
            "remote [REDACTED:HOSTNAME]",
        ),
        (
            "extended-eui64-colon",
            "mac=02:42:ac:ff:fe:11:00:02",
            "mac=[REDACTED:MAC_ADDRESS]",
        ),
        (
            "extended-eui64-hyphen",
            "mac=02-42-ac-ff-fe-11-00-02",
            "mac=[REDACTED:MAC_ADDRESS]",
        ),
        ("extended-eui48-dotted", "mac=0242.ac11.0002", "mac=[REDACTED:MAC_ADDRESS]"),
        (
            "extended-eui64-dotted",
            "mac=0242.acff.fe11.0002",
            "mac=[REDACTED:MAC_ADDRESS]",
        ),
        (
            "extended-eui64-space",
            "mac=02 42 ac ff fe 11 00 02",
            "mac=[REDACTED:MAC_ADDRESS]",
        ),
        ("extended-eui48-bare", "mac=0242ac110002", "mac=[REDACTED:MAC_ADDRESS]"),
        (
            "extended-eui48-bare-standalone",
            "adapter 0242ac110002",
            "adapter [REDACTED:MAC_ADDRESS]",
        ),
        (
            "extended-eui64-bare",
            "adapter 0242acfffe110002",
            "adapter [REDACTED:MAC_ADDRESS]",
        ),
    )
    for case_id, message, expected in cases:
        _assert_message(case_id, redact_message(message).message, expected)

    safe = (
        "localhost 127.0.0.1:80 10.0.0.1 169.254.1.2 192.0.2.1 "
        "2001:db8::1 src/main.py:42"
    )
    _assert_message("extended-safe", redact_message(safe).message, safe)


def test_spaced_absolute_values_and_combining_mark_identities_are_whole() -> None:
    """Catch decoded spaces or combining marks causing partial PII redaction."""
    cases = (
        (
            "whole-spaced-path",
            "opened /Users/Synthetic Person/Library Logs/app.log",
            "opened [REDACTED:PATH]",
        ),
        (
            "whole-json-spaced-path",
            '{"detail":"opened /Users/Synthetic Person/Library Logs/app.log"}',
            '{"detail":"opened [REDACTED:PATH]"}',
        ),
        (
            "whole-percent-space-url",
            "request https://host.invalid/a%20b?q=x%20y#z%20q",
            "request [REDACTED:URL]",
        ),
        (
            "whole-devanagari-email",
            "contact उपयोगकर्ता@उदाहरण.भारत",
            "contact [REDACTED:EMAIL]",
        ),
        (
            "whole-devanagari-host",
            "remote उदाहरण.भारत",
            "remote [REDACTED:HOSTNAME]",
        ),
    )
    for case_id, message, expected in cases:
        _assert_message(case_id, redact_message(message).message, expected)
    _assert_message(
        "whole-relative-frame",
        redact_message("src/main.py:42").message,
        "src/main.py:42",
    )


def test_mac_addresses_use_exact_typed_placeholder() -> None:
    """Catch colon or hyphen MAC forms surviving PII redaction."""
    for case_id, message, expected in _positive_inputs("mac_address"):
        result = redact_message(message)
        _assert_message(case_id, result.message, expected)


def test_only_globally_routable_ip_addresses_are_redacted() -> None:
    """Catch public-IP leakage or redaction of local/reserved address classes."""
    for case_id, message, expected in _positive_inputs("ip_address"):
        result = redact_message(message)
        _assert_message(case_id, result.message, expected)

    safe = (
        "localhost 127.0.0.1 ::1 10.0.0.1 172.16.0.1 192.168.0.1 "
        "169.254.1.2 192.0.2.1 198.51.100.2 203.0.113.3 2001:db8::1"
    )
    assert redact_message(safe).message == safe


def test_phone_candidates_require_conventional_structure_and_digit_bounds() -> None:
    """Catch phone PII leakage or timestamp/version/counter false positives."""
    for case_id, message, expected in _positive_inputs("phone"):
        result = redact_message(message)
        _assert_message(case_id, result.message, expected)

    safe = (
        "2026-08-26T12:34:56.789Z version 1.2.3 counter 1234567890123456 "
        "private 10.20.30.40 uuid 123e4567-e89b-42d3-a456-426614174000"
    )
    assert redact_message(safe).message == safe


def test_usernames_require_explicit_context() -> None:
    """Catch contextual usernames leaking without redacting ordinary words."""
    for case_id, message, expected in _positive_inputs("username"):
        result = redact_message(message)
        _assert_message(case_id, result.message, expected)

    assert redact_message("alpha operator finished build").message == (
        "alpha operator finished build"
    )


def test_hostnames_require_context_or_standalone_fqdn_syntax() -> None:
    """Catch contextual/FQDN host leakage or redaction of localhost/plain words."""
    for case_id, message, expected in _positive_inputs("hostname"):
        result = redact_message(message)
        _assert_message(case_id, result.message, expected)

    assert redact_message("connected api.synthetic.example").message == (
        "connected [REDACTED:HOSTNAME]"
    )
    assert redact_message("host=localhost ordinary-host-word").message == (
        "host=localhost ordinary-host-word"
    )


def test_ssh_userinfo_redacts_username_and_hostname_separately() -> None:
    """Catch SSH userinfo being leaked or misclassified as an email address."""
    parts = _load_fixture("planted_secret_parts.json")
    assert isinstance(parts, dict)
    username = "".join(parts["username"][0])
    hostname = "".join(parts["hostname"][0])

    result = redact_message(f"ssh {username}@{hostname}")

    _assert_message(
        "ssh-userinfo",
        result.message,
        "ssh [REDACTED:USERNAME]@[REDACTED:HOSTNAME]",
    )


def test_placeholders_are_canonical_idempotent_and_do_not_shield_adjacency() -> None:
    """Catch placeholder corruption, legacy drift, or adjacent-secret shielding."""
    parts = _load_fixture("planted_secret_parts.json")
    assert isinstance(parts, dict)
    adjacent = "".join(parts["api_key"][0])
    message = f"[redacted][REDACTED:TOKEN]{adjacent}"

    first = redact_message(message)
    second = redact_message(first.message)  # type: ignore[arg-type]

    expected = "[REDACTED:SECRET][REDACTED:TOKEN][REDACTED:API_KEY]"
    _assert_message("placeholder-adjacency", first.message, expected)
    assert second == RedactionResult(
        message=expected,
        fingerprint=first.fingerprint,
        drop_reason=None,
        changed=False,
        truncated=False,
    )


def test_reserved_placeholder_syntax_accepts_only_the_exact_vocabulary() -> None:
    """Catch malformed or invented placeholders bypassing later validation."""
    canonical = " ".join(f"[REDACTED:{kind.value.upper()}]" for kind in RedactionKind)
    _assert_message(
        "placeholder-canonical", redact_message(canonical).message, canonical
    )
    _assert_message(
        "placeholder-legacy",
        redact_message("[ReDaCtEd]").message,
        "[REDACTED:SECRET]",
    )
    for case_id, message in (
        ("placeholder-empty", "[REDACTED:]"),
        ("placeholder-unknown", "[REDACTED:UNKNOWN]"),
        ("placeholder-extra-colon", "[REDACTED:TOKEN:EXTRA]"),
        ("placeholder-mixed-case", "[Redacted:TOKEN]"),
        ("placeholder-unclosed", "[REDACTED:TOKEN"),
        ("placeholder-json-bypass", '[REDACTED:UNKNOWN]{"value":'),
    ):
        _assert_drop(
            case_id,
            redact_message(message),
            RedactionDropReason.MALFORMED_STRUCTURE,
        )


def test_nested_json_redacts_sensitive_values_and_serializes_canonically() -> None:
    """Catch recursive leaks, array reordering, or nondeterministic JSON output."""
    parts = _load_fixture("planted_secret_parts.json")
    assert isinstance(parts, dict)
    payload = {
        "safe": "ok",
        "nested": {
            "api_key": "".join(parts["api_key"][0]),
            "items": [
                {"email": "".join(parts["email"][0])},
                {"count": 3},
            ],
            "Env": {"TOKEN": "".join(parts["environment"][0])},
        },
    }

    result = redact_message(json.dumps(payload))

    _assert_message(
        "json-nested",
        result.message,
        '{"nested":{"Env":"[REDACTED:ENVIRONMENT]",'
        '"api_key":"[REDACTED:API_KEY]","items":['
        '{"email":"[REDACTED:EMAIL]"},{"count":3}]},"safe":"ok"}',
    )


@pytest.mark.parametrize("message", ['{"a":1,"a":2}', '{"a":', "[1,"])
def test_malformed_or_duplicate_json_fails_closed(message: str) -> None:
    """Catch ambiguous or malformed JSON falling back to textual output."""
    assert redact_message(message) == RedactionResult(
        message=None,
        fingerprint=None,
        drop_reason=RedactionDropReason.MALFORMED_STRUCTURE,
        changed=False,
        truncated=False,
    )


def test_json_nonfinite_numeric_results_fail_closed_and_stay_idempotent() -> None:
    """Catch overflow becoming non-standard Infinity on the second pass."""
    for case_id, message in (
        ("json-positive-overflow", '{"value":1e309}'),
        ("json-negative-overflow", '{"value":-1e309}'),
        ("json-nested-overflow", '{"items":[0,1e309]}'),
    ):
        _assert_drop(
            case_id,
            redact_message(message),
            RedactionDropReason.MALFORMED_STRUCTURE,
        )

    accepted = redact_message('{"value":1e308}')
    _assert_message("json-finite-boundary", accepted.message, '{"value":1e+308}')
    assert accepted.message is not None
    assert redact_message(accepted.message) == RedactionResult(
        message=accepted.message,
        fingerprint=accepted.fingerprint,
        drop_reason=None,
        changed=False,
        truncated=False,
    )


def test_normalized_json_key_collisions_fail_closed() -> None:
    """Catch case/separator variants becoming ambiguous sensitive-key aliases."""
    result = redact_message('{"api-key":"a","API_key":"b"}')

    assert result.drop_reason is RedactionDropReason.MALFORMED_STRUCTURE


def test_json_keys_containing_secret_or_pii_fail_closed() -> None:
    """Catch dangerous key renaming/collision when a key itself is sensitive."""
    parts = _load_fixture("planted_secret_parts.json")
    assert isinstance(parts, dict)
    dangerous_keys = (
        ("json-secret-key", "".join(parts["api_key"][0])),
        ("json-pii-key", "".join(parts["email"][0])),
    )
    for case_id, dangerous_key in dangerous_keys:
        result = redact_message(json.dumps({dangerous_key: "safe"}))
        if result.drop_reason is not RedactionDropReason.MALFORMED_STRUCTURE:
            pytest.fail(f"{case_id}: did not fail closed", pytrace=False)


def test_json_depth_limit_has_n_minus_one_n_and_n_plus_one_boundaries() -> None:
    """Catch unbounded recursive structure or an off-by-one depth rejection."""

    def nested_array(depth: int) -> object:
        value: object = "ok"
        for _ in range(depth - 1):
            value = [value]
        return value

    assert redact_message(json.dumps(nested_array(15))).drop_reason is None
    assert redact_message(json.dumps(nested_array(16))).drop_reason is None
    assert redact_message(json.dumps(nested_array(17))).drop_reason is (
        RedactionDropReason.STRUCTURE_LIMIT
    )


def test_json_node_limit_has_n_minus_one_n_and_n_plus_one_boundaries() -> None:
    """Catch unbounded node work or an off-by-one node rejection."""
    assert redact_message(json.dumps([0] * 2046)).drop_reason is None
    assert redact_message(json.dumps([0] * 2047)).drop_reason is None
    assert redact_message(json.dumps([0] * 2048)).drop_reason is (
        RedactionDropReason.STRUCTURE_LIMIT
    )


def test_json_key_limit_has_n_minus_one_n_and_n_plus_one_boundaries() -> None:
    """Catch oversized keys or an off-by-one UTF-8 key rejection."""
    assert redact_message(json.dumps({"k" * 255: 0})).drop_reason is None
    assert redact_message(json.dumps({"k" * 256: 0})).drop_reason is None
    assert redact_message(json.dumps({"k" * 257: 0})).drop_reason is (
        RedactionDropReason.STRUCTURE_LIMIT
    )


def test_json_string_limit_counts_utf8_n_minus_one_n_and_n_plus_one() -> None:
    """Catch character-count bounds or off-by-one multibyte string handling."""
    values = ("é" * 32767 + "a", "é" * 32768, "é" * 32768 + "a")
    results = [
        redact_message(json.dumps({"value": value}, ensure_ascii=False))
        for value in values
    ]

    assert results[0].drop_reason is None
    assert results[1].drop_reason is None
    assert results[2].drop_reason is RedactionDropReason.STRUCTURE_LIMIT


def test_json_limits_apply_before_sensitive_subtree_replacement() -> None:
    """Catch oversized secret values bypassing structural validation."""
    result = redact_message(json.dumps({"secret": "a" * (64 * 1024 + 1)}))

    assert result.drop_reason is RedactionDropReason.STRUCTURE_LIMIT


def test_final_utf8_clamp_has_exact_boundary_and_fixed_suffix() -> None:
    """Catch pre-redaction truncation, UTF-8 splitting, or an oversized result."""
    at_limit = "é" * (48 * 1024 // 2)
    over_limit = at_limit + "é"

    accepted = redact_message(at_limit)
    truncated = redact_message(over_limit)

    assert accepted.message == at_limit
    assert accepted.truncated is False
    assert truncated.message is not None
    assert truncated.message.endswith("[TRUNCATED]")
    assert len(truncated.message.encode("utf-8")) == 48 * 1024 - 1
    assert truncated.truncated is True


def test_clamp_never_splits_a_placeholder_created_at_the_boundary() -> None:
    """Catch a raw or partial replacement when a secret spans the clamp point."""
    parts = _load_fixture("planted_secret_parts.json")
    assert isinstance(parts, dict)
    planted = "".join(parts["api_key"][0])
    result = redact_message("a" * 49134 + " " + planted)

    _assert_message(
        "clamp-placeholder",
        result.message,
        "a" * 49134 + " " + "[TRUNCATED]",
    )
    assert result.truncated is True


def test_fixture_safe_near_misses_pass_unchanged() -> None:
    """Catch false positives for canonical IDs, hashes, versions, and local data."""
    cases = _load_fixture("redaction_cases.json")
    assert isinstance(cases, dict)
    for index, message in enumerate(cases["safe_near_misses"]):
        result = redact_message(message)
        _assert_message(f"near-miss-{index + 1}", result.message, message)


def test_text_work_limit_fails_closed_before_unbounded_line_scanning() -> None:
    """Catch detector work growing without a fixed message-line bound."""
    result = redact_message("ok\n" * 4097)

    assert result == RedactionResult(
        message=None,
        fingerprint=None,
        drop_reason=RedactionDropReason.WORK_LIMIT,
        changed=False,
        truncated=False,
    )


def test_detector_findings_are_deduplicated_bounded_and_linear(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch repeated whole-message replacement or unbounded detector findings."""

    class SyntheticDetector:
        secret_type = "AWS Access Key"

    detector = SyntheticDetector()
    monkeypatch.setattr(redactor_module, "_DETECTORS", (detector, detector))

    def split_values(_detector: object, line: str) -> tuple[str, ...]:
        values = tuple(line.split())
        return values + values

    monkeypatch.setattr(redactor_module, "_detector_values", split_values)
    limit = redactor_module._MAX_DETECTOR_FINDINGS
    at_limit = " ".join(f"v{index:04d}" for index in range(limit))
    accepted = redact_message(at_limit)
    assert accepted.drop_reason is None
    assert accepted.message is not None
    assert accepted.message.count("[REDACTED:API_KEY]") == limit
    _assert_drop(
        "detector-finding-over-limit",
        redact_message(at_limit + " overflow"),
        RedactionDropReason.WORK_LIMIT,
    )

    inspected: list[int] = []

    def count_work(_detector: object, line: str) -> tuple[str, ...]:
        inspected.append(len(line))
        return ()

    monkeypatch.setattr(redactor_module, "_DETECTORS", (detector,))
    monkeypatch.setattr(redactor_module, "_detector_values", count_work)
    redactor_module._redact_detected("a" * (128 * 1024))
    first_work = sum(inspected)
    inspected.clear()
    redactor_module._redact_detected("a" * (256 * 1024))
    assert sum(inspected) == first_work * 2


def test_final_postcondition_catches_sabotaged_sensitive_stages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch a stage regression returning known sensitive syntax as success."""
    parts = _load_fixture("planted_secret_parts.json")
    assert isinstance(parts, dict)
    provider_value = "".join(parts["api_key"][2])

    monkeypatch.setattr(redactor_module, "_redact_detected", lambda message: message)
    _assert_drop(
        "postcondition-provider-sabotage",
        redact_message(provider_value),
        RedactionDropReason.INTERNAL_ERROR,
    )
    monkeypatch.undo()

    monkeypatch.setattr(redactor_module, "_redact_text", lambda message: message)
    _assert_drop(
        "postcondition-context-sabotage",
        redact_message("token=x"),
        RedactionDropReason.INTERNAL_ERROR,
    )


def test_independent_deny_scan_survives_each_primary_helper_sabotage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch the final privacy gate sharing implementation with primary stages."""
    parts = _load_fixture("planted_secret_parts.json")
    assert isinstance(parts, dict)
    provider = "".join(parts["api_key"][2])
    cases = (
        (
            "deny-provider",
            "_detector_values",
            lambda *_args: (),
            provider,
        ),
        (
            "deny-public-ip",
            "_redact_public_ip",
            lambda match: match.group(0),
            "remote 8.8.8.8",
        ),
        (
            "deny-fqdn",
            "_redact_fqdns",
            lambda message: message,
            "remote api.synthetic.example",
        ),
        (
            "deny-private-tail",
            "_redact_private_keys",
            lambda message: message,
            "QQ==\n-----END PRIVATE KEY-----",
        ),
        (
            "deny-email",
            "_redact_emails",
            lambda message: message,
            "contact उपयोगकर्ता@उदाहरण.भारत",
        ),
        (
            "deny-path",
            "_redact_text",
            lambda message: message,
            "/Users/Synthetic Person/Library Logs/app.log",
        ),
        (
            "deny-url",
            "_redact_text",
            lambda message: message,
            "https://host.invalid/a?q=x#z",
        ),
        (
            "deny-mac",
            "_redact_text",
            lambda message: message,
            "02:42:ac:11:00:02",
        ),
        (
            "deny-phone",
            "_redact_text",
            lambda message: message,
            "+44 (0)20 7946 0958",
        ),
        (
            "deny-authorization",
            "_redact_text",
            lambda message: message,
            "Authorization: x",
        ),
    )
    for case_id, target, replacement, message in cases:
        monkeypatch.setattr(redactor_module, target, replacement)
        _assert_drop(
            case_id,
            redact_message(message),
            RedactionDropReason.INTERNAL_ERROR,
        )
        monkeypatch.undo()


@pytest.mark.parametrize(
    ("target", "message"),
    [
        ("_normalize", "safe text"),
        ("_redact_detected", "safe text"),
        ("_redact_whole_json", '{"safe":"text"}'),
    ],
)
def test_internal_stage_exceptions_are_content_free(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    target: str,
    message: str,
) -> None:
    """Catch exception text escaping through results, reprs, or logs."""
    parts = _load_fixture("planted_secret_parts.json")
    assert isinstance(parts, dict)
    planted = "".join(parts["secret"][1])

    def fail_stage(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError(planted)

    monkeypatch.setattr(redactor_module, target, fail_stage)
    try:
        result = redact_message(message)
    except Exception:  # noqa: BLE001 - the assertion verifies nothing escapes
        result = None
    if result is None:
        pytest.fail(f"exception-{target}: exception escaped", pytrace=False)

    assert result == RedactionResult(
        message=None,
        fingerprint=None,
        drop_reason=RedactionDropReason.INTERNAL_ERROR,
        changed=False,
        truncated=False,
    )
    assert planted not in repr(result)
    assert planted not in caplog.text


def test_seeded_fixture_corpus_is_deterministic_bounded_and_idempotent() -> None:
    """Catch rule-order drift, encoded leaks, nondeterminism, or unstable output."""
    parts = _load_fixture("planted_secret_parts.json")
    cases = _load_fixture("redaction_cases.json")
    assert isinstance(parts, dict)
    assert isinstance(cases, dict)
    rng = random.Random(0xD1A6)
    kinds = sorted(cases["positive_cases"])

    for iteration in range(64):
        kind = rng.choice(kinds)
        index = rng.randrange(2)
        raw = "".join(parts[kind][index])
        if iteration % 4 == 0:
            encoded = "".join(f"\\u{ord(character):04x}" for character in raw)
            rounds = rng.randrange(3)
        else:
            encoded = raw
            rounds = rng.randrange(4)
        for _ in range(rounds):
            encoded = quote(encoded, safe="")
        if iteration % 5 == 0:
            midpoint = len(encoded) // 2
            encoded = encoded[:midpoint] + "\u200b" + encoded[midpoint:]
        case = cases["positive_cases"][kind]
        message = case["templates"][index].format(needle=encoded)
        expected = case["expected"][index]

        first = redact_message(message)
        repeated = redact_message(message)
        if first.drop_reason is not None or first.message is None:
            pytest.fail(f"random-{iteration}: unexpected drop", pytrace=False)
        _assert_message(f"random-{iteration}", first.message, expected)
        assert first == repeated
        assert redact_message(first.message).message == first.message
        assert len(first.message.encode("utf-8")) <= 48 * 1024
        if raw in first.message or quote(raw, safe="") in first.message:
            pytest.fail(f"random-{iteration}: planted value survived", pytrace=False)


def test_every_positive_fixture_variant_has_exact_idempotent_known_output() -> None:
    """Catch an unvisited fixture variant, encoded leak, or fingerprint drift."""
    parts = _load_fixture("planted_secret_parts.json")
    cases = _load_fixture("redaction_cases.json")
    assert isinstance(parts, dict)
    assert isinstance(cases, dict)
    for kind, case in sorted(cases["positive_cases"].items()):
        fingerprints = case.get("fingerprints")
        if fingerprints is None:
            pytest.fail(
                f"exhaustive-{kind}: fingerprint fixture missing", pytrace=False
            )
        variants = parts[kind]
        if not (
            len(variants) >= len(case["templates"])
            and len(case["templates"]) == len(case["expected"]) == len(fingerprints)
        ):
            pytest.fail(f"exhaustive-{kind}: fixture lengths differ", pytrace=False)
        for index, fragments in enumerate(variants[: len(case["templates"])]):
            case_id = f"exhaustive-{kind}-{index}"
            raw = "".join(fragments)
            encoded = quote(raw, safe="")
            expected = case["expected"][index]
            for form_id, needle in (("raw", raw), ("encoded", encoded)):
                message = case["templates"][index].format(needle=needle)
                first = redact_message(message)
                if first.drop_reason is not None or first.message is None:
                    pytest.fail(f"{case_id}-{form_id}: unexpected drop", pytrace=False)
                _assert_message(f"{case_id}-{form_id}", first.message, expected)
                if raw in first.message or encoded in first.message:
                    pytest.fail(
                        f"{case_id}-{form_id}: planted form survived", pytrace=False
                    )
                if first.fingerprint != fingerprints[index]:
                    pytest.fail(
                        f"{case_id}-{form_id}: fingerprint drift", pytrace=False
                    )
                assert redact_message(first.message) == RedactionResult(
                    message=expected,
                    fingerprint=fingerprints[index],
                    drop_reason=None,
                    changed=False,
                    truncated=False,
                )


def test_fingerprint_depends_only_on_final_canonical_message() -> None:
    """Catch value-derived hashes/counts or omission of safe surrounding text."""
    parts = _load_fixture("planted_secret_parts.json")
    assert isinstance(parts, dict)
    first_value = "".join(parts["api_key"][0])
    second_value = "".join(parts["api_key"][1])

    first = redact_message(f"key {first_value}")
    second = redact_message(f"key {second_value}")
    changed_context = redact_message(f"other {second_value}")

    assert first.message == second.message == "key [REDACTED:API_KEY]"
    assert first.fingerprint == second.fingerprint
    assert changed_context.fingerprint != second.fingerprint


def test_import_boundary_excludes_network_auth_and_filesystem() -> None:
    """Catch coupling the pure redactor to privileged or ambient-state modules."""
    source_path = Path(redactor_module.__file__)
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported.add(node.module)

    forbidden = (
        "backend",
        "detect_secrets.core.scan",
        "detect_secrets.settings",
        "google",
        "httpx",
        "os",
        "pathlib",
        "requests",
        "socket",
        "urllib.request",
    )
    assert not any(
        module == prefix or module.startswith(prefix + ".")
        for module in imported
        for prefix in forbidden
    )
