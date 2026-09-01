"""Pure, bounded redaction for parsed diagnostic messages."""

from __future__ import annotations

import ipaddress
import json
import math
import re
import unicodedata
from enum import Enum
from hashlib import sha256

from detect_secrets.plugins.artifactory import ArtifactoryDetector
from detect_secrets.plugins.aws import AWSKeyDetector
from detect_secrets.plugins.azure_storage_key import AzureStorageKeyDetector
from detect_secrets.plugins.basic_auth import BasicAuthDetector
from detect_secrets.plugins.cloudant import CloudantDetector
from detect_secrets.plugins.discord import DiscordBotTokenDetector
from detect_secrets.plugins.github_token import GitHubTokenDetector
from detect_secrets.plugins.gitlab_token import GitLabTokenDetector
from detect_secrets.plugins.ibm_cloud_iam import IbmCloudIamDetector
from detect_secrets.plugins.ibm_cos_hmac import IbmCosHmacDetector
from detect_secrets.plugins.jwt import JwtTokenDetector
from detect_secrets.plugins.keyword import KeywordDetector
from detect_secrets.plugins.mailchimp import MailchimpDetector
from detect_secrets.plugins.npm import NpmDetector
from detect_secrets.plugins.openai import OpenAIDetector
from detect_secrets.plugins.private_key import PrivateKeyDetector
from detect_secrets.plugins.pypi_token import PypiTokenDetector
from detect_secrets.plugins.sendgrid import SendGridDetector
from detect_secrets.plugins.slack import SlackDetector
from detect_secrets.plugins.softlayer import SoftlayerDetector
from detect_secrets.plugins.square_oauth import SquareOAuthDetector
from detect_secrets.plugins.stripe import StripeDetector
from detect_secrets.plugins.telegram_token import TelegramBotTokenDetector
from detect_secrets.plugins.twilio import TwilioKeyDetector
from pydantic import BaseModel, ConfigDict, Field, model_validator

REDACTOR_VERSION = "1"
_MAX_INPUT_BYTES = 256 * 1024
_MAX_JSON_DEPTH = 16
_MAX_JSON_NODES = 2048
_MAX_JSON_KEY_BYTES = 256
_MAX_JSON_STRING_BYTES = 64 * 1024
_MAX_OUTPUT_BYTES = 48 * 1024
_TRUNCATED_SUFFIX = "[TRUNCATED]"
_MAX_MESSAGE_LINES = 4096
_MAX_DETECTOR_FINDINGS = 1024
_MAX_DETECTOR_WORK = 16 * 1024 * 1024
_FINGERPRINT_DOMAIN = b"neander-diagnostic-fingerprint-v1\0"
_PERCENT_RUN_RE = re.compile(r"(?:%[0-9A-Fa-f]{2})+")
_SURROGATE_PAIR_RE = re.compile(
    r"\\u([dD][89ABab][0-9A-Fa-f]{2})\\u([dD][c-fC-F][0-9A-Fa-f]{2})"
)
_SURROGATE_ESCAPE_RE = re.compile(r"\\u[dD][89A-Fa-f][0-9A-Fa-f]{2}")
_JSON_ESCAPE_RE = re.compile(
    r"\\u([0-9A-Fa-f]{4})|\\U([0-9A-Fa-f]{8})|\\x([0-9A-Fa-f]{2})"
)
_JWT_VALUE_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_.+/=-]+\b")
_API_KEY_RE = re.compile(
    r"\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,})\b",
    re.IGNORECASE,
)
_NONEMPTY_CONTEXT_VALUE = (
    r"(?!\[REDACTED:)(?:\"(?:\\.|[^\"\\])+\"|'(?:\\.|[^'\\])+'|[^\s,;\"']+)"
)
_AUTH_HEADER_RE = re.compile(
    r"(?P<prefix>\b(?:proxy-)?authorization\s*[:=]\s*)"
    r"(?P<value>(?!\[REDACTED:)[^\s\n][^\n]*)",
    re.IGNORECASE,
)
_AUTH_ASSIGN_RE = re.compile(
    r"(?P<prefix>\b(?:auth|authentication)\s*[:=]\s*)" + _NONEMPTY_CONTEXT_VALUE,
    re.IGNORECASE,
)
_BASIC_RE = re.compile(
    r"\bbasic\s+" + _NONEMPTY_CONTEXT_VALUE,
    re.IGNORECASE,
)
_BEARER_RE = re.compile(
    r"\b(?:bearer|jwt)\s+" + _NONEMPTY_CONTEXT_VALUE,
    re.IGNORECASE,
)
_COOKIE_HEADER_RE = re.compile(
    r"(?P<prefix>\b(?:set-cookie|cookie)\s*:\s*)"
    r"(?P<value>(?!\[REDACTED:)[^\s\n][^\n]*)",
    re.IGNORECASE,
)
_PRIVATE_KEY_BODY_BYTES = 64 * 1024
_PRIVATE_BEGIN = "-----BEGIN "
_PRIVATE_END = "-----END "
_PUTTY_BEGIN = "PuTTY-User-Key-File-"
_DSN_RE = re.compile(
    r"\b(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql|mariadb|redis|rediss|amqp|amqps)"
    r"://[^\s\"'<>]+",
    re.IGNORECASE,
)
_URL_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:(?:https?|wss?|ftp)://|//)[^\n\"'<>]+",
    re.IGNORECASE,
)
_PRIVATE_KEY_ASSIGN_RE = re.compile(
    r"(?P<prefix>\bprivate[-_ ]?key\s*[:=]\s*)" + _NONEMPTY_CONTEXT_VALUE,
    re.IGNORECASE,
)
_CREDENTIAL_ASSIGN_RE = re.compile(
    r"(?P<prefix>\bcredentials?\s*[:=]\s*)" + _NONEMPTY_CONTEXT_VALUE,
    re.IGNORECASE,
)
_TOKEN_ASSIGN_RE = re.compile(
    r"(?P<prefix>\b(?:access[-_ ]?token|auth[-_ ]?token|token|jwt)\s*[:=]\s*)"
    + _NONEMPTY_CONTEXT_VALUE,
    re.IGNORECASE,
)
_API_KEY_ASSIGN_RE = re.compile(
    r"(?P<prefix>\b(?:api[-_ ]?key|provider[-_ ]?key)\s*[:=]\s*)"
    + _NONEMPTY_CONTEXT_VALUE,
    re.IGNORECASE,
)
_SECRET_ASSIGN_RE = re.compile(
    r"(?P<prefix>\b(?:client[-_ ]?secret|secret|password|passwd|pwd)\s*[:=]\s*)"
    + _NONEMPTY_CONTEXT_VALUE,
    re.IGNORECASE,
)
_ENV_PREFIX_RE = re.compile(
    r"(?P<prefix>\b(?:env|environment)\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*)"
    + _NONEMPTY_CONTEXT_VALUE,
    re.IGNORECASE,
)
_ENV_SECRET_VAR_RE = re.compile(
    r"(?P<prefix>\b[A-Za-z_][A-Za-z0-9_]*_"
    r"(?:api_?key|token|secret|password|credential|private_?key)\s*=\s*)"
    + _NONEMPTY_CONTEXT_VALUE,
    re.IGNORECASE,
)
_SSH_USERINFO_RE = re.compile(
    r"(?P<prefix>\bssh\s+)[A-Za-z0-9][A-Za-z0-9._-]{0,63}@"
    r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}",
    re.IGNORECASE,
)
_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:"
    r"/(?:[^/\s\"'<>]+/)*[^/\s\"'<>]+"
    r"|[A-Za-z]:[\\/](?:[^\\/\s\"'<>]+[\\/])*[^\\/\s\"'<>]+"
    r"|\\\\[^\\\s\"'<>]+\\[^\\\s\"'<>]+(?:\\[^\\\s\"'<>]+)*"
    r")"
)
_QUOTED_PATH_RE = re.compile(
    r"(?P<quote>['\"])(?P<value>(?:/|[A-Za-z]:[\\/]|\\\\)[^\n]*?)(?P=quote)"
)
_SPACED_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:/|[A-Za-z]:[\\/]|\\\\)[^\n\"'<>]*\s+"
    r"[^\n\"'<>]+"
)
_MAC_RE = re.compile(
    r"(?<![0-9A-Fa-f:-])(?:"
    r"(?:[0-9A-Fa-f]{2}:){7}(?:[0-9A-Fa-f]{2})"
    r"|(?:[0-9A-Fa-f]{2}:){5}(?:[0-9A-Fa-f]{2})"
    r"|(?:[0-9A-Fa-f]{2}-){7}(?:[0-9A-Fa-f]{2})"
    r"|(?:[0-9A-Fa-f]{2}-){5}(?:[0-9A-Fa-f]{2})"
    r"|(?:[0-9A-Fa-f]{2} ){7}(?:[0-9A-Fa-f]{2})"
    r"|(?:[0-9A-Fa-f]{2} ){5}(?:[0-9A-Fa-f]{2})"
    r"|(?:[0-9A-Fa-f]{4}\.){3}[0-9A-Fa-f]{4}"
    r"|(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}"
    r")(?![0-9A-Fa-f:-])"
)
_MAC_BARE_CONTEXT_RE = re.compile(
    r"(?P<prefix>\bmac(?:[-_ ]?address)?\s*[:=]\s*)"
    r"(?:[0-9A-Fa-f]{16}|[0-9A-Fa-f]{12})(?![0-9A-Fa-f])",
    re.IGNORECASE,
)
_MAC_BARE_RE = re.compile(
    r"(?<![0-9A-Fa-f-])(?=[0-9A-Fa-f]{0,15}[A-Fa-f])"
    r"(?:[0-9A-Fa-f]{16}|[0-9A-Fa-f]{12})(?![0-9A-Fa-f-])"
)
_IP_CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9_.])(?:"
    r"\[[0-9A-Fa-f:.]+(?:%[A-Za-z0-9_.-]+)?\](?::\d{1,5})?"
    r"|[0-9A-Fa-f:.]+(?:%[A-Za-z0-9_.-]+)?"
    r")(?![A-Za-z0-9_.])"
)
_PHONE_RE = re.compile(
    r"(?<![A-Za-z0-9_.])\+?\d{1,3}(?:[ .-]*\(?\d{1,4}\)?){2,6}"
    r"(?![A-Za-z0-9_.])"
)
_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
_USERNAME_CONTEXT_RE = re.compile(
    r"(?P<prefix>\b(?:user|username)\s*[:=]\s*)" + _NONEMPTY_CONTEXT_VALUE,
    re.IGNORECASE,
)
_HOSTNAME_CONTEXT_RE = re.compile(
    r"(?P<prefix>\b(?:host|hostname)\s*[:=]\s*)"
    r"(?P<value>" + _NONEMPTY_CONTEXT_VALUE + r")",
    re.IGNORECASE,
)
_LEGACY_PLACEHOLDER_RE = re.compile(r"\[redacted\]", re.IGNORECASE)
_PLACEHOLDER_RE = re.compile(r"\[REDACTED:[A-Z_]+\]")
_GENERIC_SECRET_RE = re.compile(
    r"\b[A-Za-z0-9_-]*secret[A-Za-z0-9_-]{12,}\b", re.IGNORECASE
)
_DETECTORS = (
    ArtifactoryDetector(),
    AWSKeyDetector(),
    AzureStorageKeyDetector(),
    BasicAuthDetector(),
    CloudantDetector(),
    DiscordBotTokenDetector(),
    GitHubTokenDetector(),
    GitLabTokenDetector(),
    IbmCosHmacDetector(),
    IbmCloudIamDetector(),
    JwtTokenDetector(),
    KeywordDetector(),
    MailchimpDetector(),
    NpmDetector(),
    OpenAIDetector(),
    PrivateKeyDetector(),
    PypiTokenDetector(),
    SendGridDetector(),
    SlackDetector(),
    SoftlayerDetector(),
    SquareOAuthDetector(),
    StripeDetector(),
    TelegramBotTokenDetector(),
    TwilioKeyDetector(),
)
_DETECTOR_PLACEHOLDERS = {
    "Artifactory Credentials": "[REDACTED:API_KEY]",
    "AWS Access Key": "[REDACTED:API_KEY]",
    "Azure Storage Account access key": "[REDACTED:API_KEY]",
    "Basic Auth Credentials": "[REDACTED:CREDENTIAL]",
    "Cloudant Credentials": "[REDACTED:API_KEY]",
    "Discord Bot Token": "[REDACTED:API_KEY]",
    "GitHub Token": "[REDACTED:API_KEY]",
    "GitLab Token": "[REDACTED:API_KEY]",
    "IBM COS HMAC Credentials": "[REDACTED:API_KEY]",
    "IBM Cloud IAM Key": "[REDACTED:API_KEY]",
    "JSON Web Token": "[REDACTED:TOKEN]",
    "Secret Keyword": "[REDACTED:SECRET]",
    "Mailchimp Access Key": "[REDACTED:API_KEY]",
    "NPM tokens": "[REDACTED:API_KEY]",
    "OpenAI Token": "[REDACTED:API_KEY]",
    "Private Key": "[REDACTED:PRIVATE_KEY]",
    "PyPI Token": "[REDACTED:API_KEY]",
    "SendGrid API Key": "[REDACTED:API_KEY]",
    "Slack Token": "[REDACTED:API_KEY]",
    "SoftLayer Credentials": "[REDACTED:API_KEY]",
    "Square OAuth Secret": "[REDACTED:API_KEY]",
    "Stripe Access Key": "[REDACTED:API_KEY]",
    "Telegram Bot Token": "[REDACTED:API_KEY]",
    "Twilio API Key": "[REDACTED:API_KEY]",
}


class _MalformedStructure(Exception):
    pass


class _StructureLimit(Exception):
    pass


class _WorkLimit(Exception):
    pass


class _ObfuscationLimit(Exception):
    pass


class RedactionKind(str, Enum):
    """Stable v1 categories used in canonical placeholders."""

    API_KEY = "api_key"
    TOKEN = "token"
    CREDENTIAL = "credential"
    COOKIE = "cookie"
    PRIVATE_KEY = "private_key"
    DSN = "dsn"
    SECRET = "secret"
    ENVIRONMENT = "environment"
    EMAIL = "email"
    PHONE = "phone"
    IP_ADDRESS = "ip_address"
    MAC_ADDRESS = "mac_address"
    USERNAME = "username"
    HOSTNAME = "hostname"
    PATH = "path"
    URL = "url"


class RedactionDropReason(str, Enum):
    """Fixed failure reasons that are safe to count or persist."""

    INVALID_INPUT = "invalid_input"
    INPUT_TOO_LARGE = "input_too_large"
    OBFUSCATION_LIMIT = "obfuscation_limit"
    STRUCTURE_LIMIT = "structure_limit"
    MALFORMED_STRUCTURE = "malformed_structure"
    WORK_LIMIT = "work_limit"
    INTERNAL_ERROR = "internal_error"


class RedactionResult(BaseModel):
    """Content-free outcome metadata plus private sanitized content fields."""

    model_config = ConfigDict(
        extra="forbid", frozen=True, hide_input_in_errors=True, strict=True
    )

    message: str | None = Field(repr=False)
    fingerprint: str | None = Field(repr=False)
    drop_reason: RedactionDropReason | None
    changed: bool
    truncated: bool

    @model_validator(mode="after")
    def validate_content_state(self) -> RedactionResult:
        success = self.message is not None and self.fingerprint is not None
        if success != (self.drop_reason is None):
            raise ValueError("redaction result has an invalid content state")
        if not success and (self.message is not None or self.fingerprint is not None):
            raise ValueError("redaction result has an invalid content state")
        if not success and (self.changed or self.truncated):
            raise ValueError("failed redaction cannot report content changes")
        if success:
            assert self.message is not None
            expected = sha256(
                _FINGERPRINT_DOMAIN + self.message.encode("utf-8")
            ).hexdigest()
            if self.fingerprint != expected:
                raise ValueError("success fingerprint does not match message")
            if self.truncated and not self.changed:
                raise ValueError("truncated success must report a content change")
        return self


def _drop(reason: RedactionDropReason) -> RedactionResult:
    return RedactionResult(
        message=None,
        fingerprint=None,
        drop_reason=reason,
        changed=False,
        truncated=False,
    )


def _is_default_ignorable(character: str) -> bool:
    codepoint = ord(character)
    if unicodedata.category(character) == "Cf":
        return True
    return (
        codepoint == 0x034F
        or 0x115F <= codepoint <= 0x1160
        or 0x17B4 <= codepoint <= 0x17B5
        or 0x180B <= codepoint <= 0x180F
        or 0x200B <= codepoint <= 0x200F
        or 0x202A <= codepoint <= 0x202E
        or 0x2060 <= codepoint <= 0x206F
        or codepoint == 0x3164
        or 0xFE00 <= codepoint <= 0xFE0F
        or codepoint == 0xFEFF
        or codepoint == 0xFFA0
        or 0xFFF0 <= codepoint <= 0xFFF8
        or 0x1BCA0 <= codepoint <= 0x1BCAF
        or 0x1D173 <= codepoint <= 0x1D17A
        or 0xE0000 <= codepoint <= 0xE0FFF
    )


def _strip_unsafe_characters(message: str) -> str:
    return "".join(
        character
        for character in message
        if character == "\n"
        or (
            unicodedata.category(character) != "Cc"
            and not _is_default_ignorable(character)
        )
    )


def _normalize(message: str) -> str:
    normalized = unicodedata.normalize(
        "NFKC", message.replace("\r\n", "\n").replace("\r", "\n").replace("\t", " ")
    )
    stripped = _strip_unsafe_characters(normalized)
    return _strip_unsafe_characters(unicodedata.normalize("NFKC", stripped))


def _reject_suspicious_percent_escapes(message: str) -> None:
    valid_count = 0
    malformed = False
    index = 0
    hexadecimal = "0123456789abcdefABCDEF"
    while index < len(message):
        if message[index] != "%":
            index += 1
            continue
        if (
            index + 2 < len(message)
            and message[index + 1] in hexadecimal
            and message[index + 2] in hexadecimal
        ):
            valid_count += 1
            index += 3
            continue
        malformed = True
        index += 1
    if malformed and valid_count >= 2:
        raise _ObfuscationLimit


def _decode_once(message: str) -> str:
    _reject_suspicious_percent_escapes(message)

    def decode_percent(match: re.Match[str]) -> str:
        raw = bytes.fromhex(match.group(0).replace("%", ""))
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise _ObfuscationLimit from error

    def decode_pair(match: re.Match[str]) -> str:
        high = int(match.group(1), 16)
        low = int(match.group(2), 16)
        return chr(0x10000 + ((high - 0xD800) << 10) + low - 0xDC00)

    def decode_json(match: re.Match[str]) -> str:
        raw = next(group for group in match.groups() if group is not None)
        codepoint = int(raw, 16)
        if codepoint > 0x10FFFF or 0xD800 <= codepoint <= 0xDFFF:
            raise _ObfuscationLimit
        return chr(codepoint)

    decoded = _PERCENT_RUN_RE.sub(decode_percent, message)
    decoded = _SURROGATE_PAIR_RE.sub(decode_pair, decoded)
    if _SURROGATE_ESCAPE_RE.search(decoded):
        raise _ObfuscationLimit
    return _JSON_ESCAPE_RE.sub(decode_json, decoded)


def _decode_obfuscation(message: str) -> str:
    decoded = message
    for _ in range(3):
        next_value = _normalize(_decode_once(decoded))
        if next_value == decoded:
            return decoded
        decoded = next_value
    if _normalize(_decode_once(decoded)) != decoded:
        raise _ObfuscationLimit
    return decoded


def _is_private_key_label(label: str) -> bool:
    normalized = " ".join(label.upper().split())
    return normalized.endswith(("PRIVATE KEY", "PRIVATE KEY BLOCK"))


def _redact_pem_private_keys(message: str) -> str:
    output: list[str] = []
    cursor = 0
    while True:
        start = message.find(_PRIVATE_BEGIN, cursor)
        if start < 0:
            output.append(message[cursor:])
            return "".join(output)
        output.append(message[cursor:start])
        header_end = message.find("-----", start + len(_PRIVATE_BEGIN))
        if header_end < 0:
            if "PRIVATE KEY" in message[start:].upper():
                raise _MalformedStructure
            output.append(message[start:])
            return "".join(output)
        label = message[start + len(_PRIVATE_BEGIN) : header_end]
        if not _is_private_key_label(label):
            output.append(message[start : header_end + 5])
            cursor = header_end + 5
            continue
        marker_end = header_end + 5
        body_start = marker_end + (message[marker_end : marker_end + 1] == "\n")
        expected_end = f"{_PRIVATE_END}{label}-----"
        close_start = message.find(expected_end, body_start)
        any_close = message.find(_PRIVATE_END, body_start)
        if close_start < 0 or (0 <= any_close < close_start):
            body_end = len(message) if any_close < 0 else any_close
            body = message[body_start:body_end].removesuffix("\n")
            if len(body.encode("utf-8")) > _PRIVATE_KEY_BODY_BYTES:
                raise _WorkLimit
            raise _MalformedStructure
        body = message[body_start:close_start].removesuffix("\n")
        if len(body.encode("utf-8")) > _PRIVATE_KEY_BODY_BYTES:
            raise _WorkLimit
        close_end = close_start + len(expected_end)
        output.append("[REDACTED:PRIVATE_KEY]")
        cursor = close_end


def _redact_putty_private_keys(message: str) -> str:
    output: list[str] = []
    cursor = 0
    while True:
        start = message.find(_PUTTY_BEGIN, cursor)
        if start < 0:
            output.append(message[cursor:])
            return "".join(output)
        output.append(message[cursor:start])
        private_lines = message.find("\nPrivate-Lines:", start)
        private_mac = message.find("\nPrivate-MAC:", start)
        if private_lines < 0 or private_mac < private_lines:
            if len(message[start:].encode("utf-8")) > _PRIVATE_KEY_BODY_BYTES:
                raise _WorkLimit
            raise _MalformedStructure
        value_start = private_mac + len("\nPrivate-MAC:")
        while value_start < len(message) and message[value_start] in " \t":
            value_start += 1
        value_end = value_start
        while (
            value_end < len(message) and message[value_end] in "0123456789abcdefABCDEF"
        ):
            value_end += 1
        if value_end == value_start:
            raise _MalformedStructure
        if len(message[start:value_end].encode("utf-8")) > _PRIVATE_KEY_BODY_BYTES:
            raise _WorkLimit
        output.append("[REDACTED:PRIVATE_KEY]")
        cursor = value_end


def _redact_private_keys(message: str) -> str:
    redacted = _redact_putty_private_keys(_redact_pem_private_keys(message))
    folded = redacted.casefold()
    if "private-lines:" in folded or "private-mac:" in folded:
        raise _MalformedStructure
    cursor = 0
    while True:
        start = redacted.find(_PRIVATE_END, cursor)
        if start < 0:
            return redacted
        label_end = redacted.find("-----", start + len(_PRIVATE_END))
        if label_end < 0:
            raise _MalformedStructure
        label = redacted[start + len(_PRIVATE_END) : label_end]
        if _is_private_key_label(label):
            raise _MalformedStructure
        cursor = label_end + 5


def _redact_text(message: str) -> str:
    redacted = _LEGACY_PLACEHOLDER_RE.sub("[REDACTED:SECRET]", message)
    redacted = _redact_private_keys(redacted)
    redacted = _DSN_RE.sub("[REDACTED:DSN]", redacted)
    redacted = _URL_RE.sub("[REDACTED:URL]", redacted)
    redacted = _COOKIE_HEADER_RE.sub(
        lambda match: match.group("prefix") + "[REDACTED:COOKIE]", redacted
    )
    redacted = _AUTH_HEADER_RE.sub(_redact_authorization, redacted)
    redacted = _AUTH_ASSIGN_RE.sub(
        lambda match: match.group("prefix") + "[REDACTED:CREDENTIAL]", redacted
    )
    redacted = _BASIC_RE.sub("[REDACTED:CREDENTIAL]", redacted)
    redacted = _BEARER_RE.sub("[REDACTED:TOKEN]", redacted)
    redacted = _ENV_PREFIX_RE.sub(
        lambda match: match.group("prefix") + "[REDACTED:ENVIRONMENT]", redacted
    )
    redacted = _ENV_SECRET_VAR_RE.sub(
        lambda match: match.group("prefix") + "[REDACTED:ENVIRONMENT]", redacted
    )
    redacted = _PRIVATE_KEY_ASSIGN_RE.sub(
        lambda match: match.group("prefix") + "[REDACTED:PRIVATE_KEY]", redacted
    )
    redacted = _CREDENTIAL_ASSIGN_RE.sub(
        lambda match: match.group("prefix") + "[REDACTED:CREDENTIAL]", redacted
    )
    redacted = _TOKEN_ASSIGN_RE.sub(
        lambda match: match.group("prefix") + "[REDACTED:TOKEN]", redacted
    )
    redacted = _API_KEY_ASSIGN_RE.sub(
        lambda match: match.group("prefix") + "[REDACTED:API_KEY]", redacted
    )
    redacted = _SECRET_ASSIGN_RE.sub(
        lambda match: match.group("prefix") + "[REDACTED:SECRET]", redacted
    )
    redacted = _API_KEY_RE.sub("[REDACTED:API_KEY]", redacted)
    redacted = _SSH_USERINFO_RE.sub(
        lambda match: match.group("prefix") + "[REDACTED:USERNAME]@[REDACTED:HOSTNAME]",
        redacted,
    )
    redacted = _redact_emails(redacted)
    redacted = _QUOTED_PATH_RE.sub(
        lambda match: match.group("quote") + "[REDACTED:PATH]" + match.group("quote"),
        redacted,
    )
    redacted = _SPACED_PATH_RE.sub("[REDACTED:PATH]", redacted)
    redacted = _PATH_RE.sub("[REDACTED:PATH]", redacted)
    redacted = _MAC_BARE_CONTEXT_RE.sub(
        lambda match: match.group("prefix") + "[REDACTED:MAC_ADDRESS]", redacted
    )
    redacted = _MAC_BARE_RE.sub("[REDACTED:MAC_ADDRESS]", redacted)
    redacted = _MAC_RE.sub("[REDACTED:MAC_ADDRESS]", redacted)
    redacted = _IP_CANDIDATE_RE.sub(_redact_public_ip, redacted)
    redacted = _PHONE_RE.sub(_redact_phone, redacted)
    redacted = _USERNAME_CONTEXT_RE.sub(
        lambda match: match.group("prefix") + "[REDACTED:USERNAME]", redacted
    )
    redacted = _HOSTNAME_CONTEXT_RE.sub(_redact_contextual_hostname, redacted)
    redacted = _redact_fqdns(redacted)
    return _GENERIC_SECRET_RE.sub("[REDACTED:SECRET]", redacted)


def _redact_public_ip(match: re.Match[str]) -> str:
    candidate = match.group(0)
    suffix = ""
    if candidate.startswith("["):
        close = candidate.find("]")
        address_text = candidate[1:close]
        suffix = candidate[close + 1 :]
    else:
        address_text = candidate
        if candidate.count(":") == 1:
            possible_address, separator, possible_port = candidate.rpartition(":")
            if separator and possible_port.isdigit():
                address_text = possible_address
                suffix = separator + possible_port
    try:
        address = ipaddress.ip_address(address_text)
    except ValueError:
        return candidate
    return "[REDACTED:IP_ADDRESS]" + suffix if address.is_global else candidate


def _is_valid_idna_hostname(value: str) -> bool:
    candidate = value.rstrip(".")
    if "." not in candidate:
        return False
    try:
        ascii_value = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return False
    labels = ascii_value.split(".")
    return (
        len(ascii_value) <= 253
        and all(
            label
            and len(label) <= 63
            and not label.startswith("-")
            and not label.endswith("-")
            and all(character.isalnum() or character == "-" for character in label)
            for label in labels
        )
        and not labels[-1].isdigit()
    )


def _is_unicode_word_part(character: str) -> bool:
    return character.isalnum() or unicodedata.category(character).startswith("M")


def _redact_emails(message: str) -> str:
    spans: list[tuple[int, int]] = []
    local_punctuation = ".!#$%&'*+/?^_`{|}~-"
    for index, character in enumerate(message):
        if character != "@":
            continue
        start = index
        while start > 0 and (
            _is_unicode_word_part(message[start - 1])
            or message[start - 1] in local_punctuation
        ):
            start -= 1
        end = index + 1
        while end < len(message) and (
            _is_unicode_word_part(message[end]) or message[end] in ".-"
        ):
            end += 1
        candidate = message[start:end]
        local = candidate[: index - start]
        hostname = candidate[index - start + 1 :]
        if local and _is_valid_idna_hostname(hostname):
            spans.append((start, end))
    if not spans:
        return message
    output: list[str] = []
    cursor = 0
    for start, end in spans:
        if start < cursor:
            continue
        output.extend((message[cursor:start], "[REDACTED:EMAIL]"))
        cursor = end
    output.append(message[cursor:])
    return "".join(output)


def _redact_fqdns(message: str) -> str:
    output: list[str] = []
    cursor = 0
    index = 0
    while index < len(message):
        character = message[index]
        if not (_is_unicode_word_part(character) or character in "_.-"):
            index += 1
            continue
        end = index + 1
        while end < len(message) and (
            _is_unicode_word_part(message[end]) or message[end] in "_.-"
        ):
            end += 1
        candidate = message[index:end]
        blocked_prefix = index > 0 and message[index - 1] in "./\\:-@"
        if not blocked_prefix and _is_valid_idna_hostname(candidate):
            output.extend((message[cursor:index], "[REDACTED:HOSTNAME]"))
            cursor = end
        index = end
    output.append(message[cursor:])
    return "".join(output)


def _redact_authorization(match: re.Match[str]) -> str:
    value = match.group("value").casefold()
    placeholder = (
        "[REDACTED:TOKEN]"
        if value.startswith(("bearer ", "jwt "))
        else "[REDACTED:CREDENTIAL]"
    )
    return match.group("prefix") + placeholder


def _redact_phone(match: re.Match[str]) -> str:
    candidate = match.group(0)
    for possible_ip in re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", candidate):
        try:
            ipaddress.ip_address(possible_ip)
        except ValueError:
            continue
        return candidate
    digit_count = sum(character.isdigit() for character in candidate)
    if not 7 <= digit_count <= 15 or _DATE_RE.fullmatch(candidate):
        return candidate
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        return candidate
    has_structure = (
        candidate.startswith("+")
        or "(" in candidate
        or any(separator in candidate for separator in " .-")
    )
    return "[REDACTED:PHONE]" if has_structure else candidate


def _redact_contextual_hostname(match: re.Match[str]) -> str:
    value = match.group("value")
    if value.strip("\"'").casefold() == "localhost":
        return match.group(0)
    return match.group("prefix") + "[REDACTED:HOSTNAME]"


def _validate_placeholders(message: str) -> None:
    valid = {f"[REDACTED:{kind.value.upper()}]" for kind in RedactionKind}
    folded = message.casefold()
    cursor = 0
    while True:
        start = folded.find("[redacted", cursor)
        if start < 0:
            return
        end = message.find("]", start + 1)
        if end < 0 or message[start : end + 1] not in valid:
            raise _MalformedStructure
        cursor = end + 1


def _has_surviving_sensitive_content(message: str) -> bool:
    valid_placeholders = tuple(
        f"[REDACTED:{kind.value.upper()}]" for kind in RedactionKind
    )
    shielded = message

    folded = shielded.casefold()
    private_marker = (
        "-----begin " in folded or "-----end " in folded
    ) and "private key" in folded
    if private_marker or any(
        marker in folded
        for marker in ("putty-user-key-file-", "private-lines:", "private-mac:")
    ):
        return True

    deny_patterns = (
        re.compile(
            r"\b(?:proxy-)?authorization\s*[:=]\s*(?!\[REDACTED:)[^\s\n]",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:auth|authentication)\s*[:=]\s*(?!\[REDACTED:)"
            r"(?:\"(?:\\.|[^\"\\])+\"|'(?:\\.|[^'\\])+'|[^\s\"'])",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:token|api[-_ ]?key|secret|password|credential|private[-_ ]?key)"
            r"\s*[:=]\s*(?!\[REDACTED:)"
            r"(?:\"(?:\\.|[^\"\\])+\"|'(?:\\.|[^'\\])+'|[^\s\"'])",
            re.IGNORECASE,
        ),
        re.compile(r"(?<![A-Za-z0-9_])(?:(?:https?|wss?|ftp)://|//)"),
        re.compile(r"(?<![A-Za-z0-9_])(?:/[A-Za-z0-9_.~-]|[A-Za-z]:[\\/]|\\\\)"),
        re.compile(
            r"(?<![0-9A-Fa-f:-])(?:"
            r"(?:[0-9A-Fa-f]{2}[:-]){5,7}[0-9A-Fa-f]{2}"
            r"|(?:[0-9A-Fa-f]{4}\.){2,3}[0-9A-Fa-f]{4}"
            r")(?![0-9A-Fa-f:-])"
        ),
    )
    if any(pattern.search(shielded) for pattern in deny_patterns):
        return True

    ip_candidates = re.finditer(
        r"(?<![A-Za-z0-9_.])(?:\[[0-9A-Fa-f:.%_-]+\](?::\d{1,5})?"
        r"|[0-9A-Fa-f:.]+(?:%[A-Za-z0-9_.-]+)?)(?![A-Za-z0-9_.])",
        shielded,
    )
    for match in ip_candidates:
        candidate = match.group(0)
        if candidate.startswith("["):
            address_text = candidate[1 : candidate.find("]")]
        elif candidate.count(":") == 1 and candidate.rpartition(":")[2].isdigit():
            address_text = candidate.rpartition(":")[0]
        else:
            address_text = candidate
        try:
            address = ipaddress.ip_address(address_text)
        except ValueError:
            continue
        if address.is_global:
            return True

    phone_candidates = re.finditer(
        r"(?<![A-Za-z0-9_.])\+?\d{1,3}(?:[ .-]*\(?\d{1,4}\)?){2,6}"
        r"(?![A-Za-z0-9_.])",
        shielded,
    )
    for match in phone_candidates:
        candidate = match.group(0)
        contains_ip = False
        for possible_ip in re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", candidate):
            try:
                ipaddress.ip_address(possible_ip)
            except ValueError:
                continue
            contains_ip = True
            break
        if contains_ip:
            continue
        digits = sum(character.isdigit() for character in candidate)
        if not 7 <= digits <= 15 or re.fullmatch(r"\d{4}-\d{2}-\d{2}", candidate):
            continue
        if any(separator in candidate for separator in ("+", "(", " ", ".", "-")):
            return True

    def is_word_part(character: str) -> bool:
        return character.isalnum() or unicodedata.category(character).startswith("M")

    def valid_hostname(candidate: str) -> bool:
        hostname = candidate.rstrip(".")
        if "." not in hostname:
            return False
        try:
            ascii_hostname = hostname.encode("idna").decode("ascii")
        except UnicodeError:
            return False
        labels = ascii_hostname.split(".")
        return (
            len(ascii_hostname) <= 253
            and not labels[-1].isdigit()
            and all(
                label
                and len(label) <= 63
                and not label.startswith("-")
                and not label.endswith("-")
                and all(character.isalnum() or character == "-" for character in label)
                for label in labels
            )
        )

    token_characters = "_.-@+!#$%&'*?^`{|}~"
    index = 0
    while index < len(shielded):
        if not (is_word_part(shielded[index]) or shielded[index] in token_characters):
            index += 1
            continue
        end = index + 1
        while end < len(shielded) and (
            is_word_part(shielded[end]) or shielded[end] in token_characters
        ):
            end += 1
        candidate = shielded[index:end]
        if "@" in candidate:
            local, separator, hostname = candidate.rpartition("@")
            if separator and local and valid_hostname(hostname):
                return True
        elif valid_hostname(candidate) and not (
            index > 0 and shielded[index - 1] in "./\\:-"
        ):
            return True
        index = end

    finding_count = 0
    work = 0
    detector_text = shielded
    for placeholder in valid_placeholders:
        detector_text = detector_text.replace(placeholder, " " * len(placeholder))
    for line in detector_text.split("\n"):
        for detector in _DETECTORS:
            work += len(line)
            if work > _MAX_DETECTOR_WORK:
                raise _WorkLimit
            analyze_string = getattr(detector, "analyze_string", None)
            if analyze_string is None:
                continue
            for _finding in analyze_string(line):
                finding_count += 1
                if finding_count > _MAX_DETECTOR_FINDINGS:
                    raise _WorkLimit
                return True
    return False


def _clamp_message(message: str) -> tuple[str, bool]:
    encoded = message.encode("utf-8")
    if len(encoded) <= _MAX_OUTPUT_BYTES:
        return message, False
    prefix_budget = _MAX_OUTPUT_BYTES - len(_TRUNCATED_SUFFIX.encode("ascii"))
    prefix = encoded[:prefix_budget].decode("utf-8", errors="ignore")
    possible_start = prefix.rfind("[")
    if possible_start >= 0:
        match = _PLACEHOLDER_RE.match(message, possible_start)
        if match is not None and match.end() > len(prefix):
            prefix = prefix[:possible_start]
    return prefix + _TRUNCATED_SUFFIX, True


def _detector_values(detector: object, line: str) -> tuple[str, ...]:
    if type(detector).__name__ == "JwtTokenDetector":
        return tuple(match.group(0) for match in _JWT_VALUE_RE.finditer(line))
    patterns = getattr(detector, "denylist", None)
    if patterns is None:
        return tuple(detector.analyze_string(line))  # type: ignore[attr-defined]
    values: list[str] = []
    for pattern in patterns:
        for match in pattern.finditer(line):
            groups = [group for group in match.groups() if group]
            longest_group = max(groups, key=len, default="")
            values.append(longest_group if len(longest_group) >= 8 else match.group(0))
    return tuple(values)


def _redact_detected(message: str) -> str:
    finding_count = 0
    work = 0
    output: list[str] = []
    placeholder_priority = {
        "[REDACTED:PRIVATE_KEY]": 0,
        "[REDACTED:CREDENTIAL]": 1,
        "[REDACTED:TOKEN]": 2,
        "[REDACTED:SECRET]": 3,
        "[REDACTED:API_KEY]": 4,
    }
    for line in message.split("\n"):
        spans: list[tuple[int, int, str]] = []
        seen_values: set[tuple[str, str]] = set()
        for detector in _DETECTORS:
            work += len(line)
            if work > _MAX_DETECTOR_WORK:
                raise _WorkLimit
            secret_type = detector.secret_type
            replacement = _DETECTOR_PLACEHOLDERS[secret_type]
            for secret_value in _detector_values(detector, line):
                if not secret_value or (secret_type, secret_value) in seen_values:
                    continue
                seen_values.add((secret_type, secret_value))
                work += len(line)
                if work > _MAX_DETECTOR_WORK:
                    raise _WorkLimit
                start = 0
                while True:
                    start = line.find(secret_value, start)
                    if start < 0:
                        break
                    end = start + len(secret_value)
                    finding_count += 1
                    if finding_count > _MAX_DETECTOR_FINDINGS:
                        raise _WorkLimit
                    spans.append((start, end, replacement))
                    start = end

        if not spans:
            output.append(line)
            continue
        spans.sort(key=lambda span: (span[0], span[1]))
        combined: list[tuple[int, int, str]] = []
        for start, end, replacement in spans:
            if combined and start < combined[-1][1]:
                old_start, old_end, old_replacement = combined[-1]
                combined[-1] = (
                    old_start,
                    max(old_end, end),
                    min(
                        (old_replacement, replacement),
                        key=placeholder_priority.__getitem__,
                    ),
                )
            else:
                combined.append((start, end, replacement))
        cursor = 0
        pieces: list[str] = []
        for start, end, replacement in combined:
            pieces.extend((line[cursor:start], replacement))
            cursor = end
        pieces.append(line[cursor:])
        output.append("".join(pieces))
    return "\n".join(output)


def _normalized_json_key(key: str) -> str:
    return "".join(
        character
        for character in unicodedata.normalize("NFKC", key).casefold()
        if character.isalnum()
    )


def _json_key_placeholder(key: str) -> str | None:
    normalized = _normalized_json_key(key)
    if normalized in {"env", "environment"}:
        return "[REDACTED:ENVIRONMENT]"
    suffixes = (
        ("privatekey", "[REDACTED:PRIVATE_KEY]"),
        ("apikey", "[REDACTED:API_KEY]"),
        ("cookie", "[REDACTED:COOKIE]"),
        ("dsn", "[REDACTED:DSN]"),
        ("databaseurl", "[REDACTED:DSN]"),
        ("connectionstring", "[REDACTED:DSN]"),
        ("credential", "[REDACTED:CREDENTIAL]"),
        ("authorization", "[REDACTED:CREDENTIAL]"),
        ("token", "[REDACTED:TOKEN]"),
        ("password", "[REDACTED:SECRET]"),
        ("secret", "[REDACTED:SECRET]"),
        ("email", "[REDACTED:EMAIL]"),
        ("phone", "[REDACTED:PHONE]"),
        ("ipaddress", "[REDACTED:IP_ADDRESS]"),
        ("macaddress", "[REDACTED:MAC_ADDRESS]"),
        ("username", "[REDACTED:USERNAME]"),
        ("hostname", "[REDACTED:HOSTNAME]"),
        ("path", "[REDACTED:PATH]"),
        ("url", "[REDACTED:URL]"),
    )
    return next(
        (
            placeholder
            for suffix, placeholder in suffixes
            if normalized.endswith(suffix)
        ),
        None,
    )


def _validate_json_structure(
    value: object, depth: int = 1, nodes: list[int] | None = None
) -> None:
    if nodes is None:
        nodes = [0]
    nodes[0] += 1
    if nodes[0] > _MAX_JSON_NODES:
        raise _StructureLimit
    if depth > _MAX_JSON_DEPTH:
        raise _StructureLimit
    if isinstance(value, dict):
        for child in value.values():
            _validate_json_structure(child, depth + 1, nodes)
    elif isinstance(value, list):
        for child in value:
            _validate_json_structure(child, depth + 1, nodes)
    elif isinstance(value, str) and len(value.encode("utf-8")) > _MAX_JSON_STRING_BYTES:
        raise _StructureLimit


def _redact_json_value(value: object) -> object:
    if isinstance(value, dict):
        output: dict[str, object] = {}
        for key, child in value.items():
            if _redact_detected(_redact_text(key)) != key:
                raise _MalformedStructure
            placeholder = _json_key_placeholder(key)
            output[key] = (
                placeholder if placeholder is not None else _redact_json_value(child)
            )
        return output
    if isinstance(value, list):
        return [_redact_json_value(child) for child in value]
    if isinstance(value, str):
        return _redact_detected(_redact_text(value))
    return value


def _redact_whole_json(message: str) -> str | None:
    stripped = message.lstrip()
    if stripped.startswith("[REDACTED:"):
        return None
    if not stripped.startswith(("{", "[")):
        return None

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        output: dict[str, object] = {}
        normalized_keys: set[str] = set()
        for key, value in pairs:
            if len(key.encode("utf-8")) > _MAX_JSON_KEY_BYTES:
                raise _StructureLimit
            normalized_key = _normalized_json_key(key)
            if normalized_key in normalized_keys:
                raise _MalformedStructure
            normalized_keys.add(normalized_key)
            output[key] = value
        return output

    def reject_constant(_value: str) -> object:
        raise _MalformedStructure

    def finite_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise _MalformedStructure
        return parsed

    try:
        value = json.loads(
            message,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
            parse_float=finite_float,
        )
    except (json.JSONDecodeError, OverflowError, ValueError) as error:
        raise _MalformedStructure from error
    _validate_json_structure(value)
    sanitized = _redact_json_value(value)
    try:
        return json.dumps(
            sanitized,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (OverflowError, ValueError) as error:
        raise _MalformedStructure from error


def redact_message(message: str) -> RedactionResult:
    """Return a deterministic sanitized message result."""
    if type(message) is not str:
        return _drop(RedactionDropReason.INVALID_INPUT)
    try:
        encoded = message.encode("utf-8")
    except UnicodeEncodeError:
        return _drop(RedactionDropReason.INVALID_INPUT)
    if len(encoded) > _MAX_INPUT_BYTES:
        return _drop(RedactionDropReason.INPUT_TOO_LARGE)
    try:
        normalized = _decode_obfuscation(_normalize(message))
    except _ObfuscationLimit:
        return _drop(RedactionDropReason.OBFUSCATION_LIMIT)
    except Exception:  # noqa: BLE001 - fail closed across normalization internals
        return _drop(RedactionDropReason.INTERNAL_ERROR)
    normalized = _LEGACY_PLACEHOLDER_RE.sub("[REDACTED:SECRET]", normalized)
    if normalized.count("\n") + 1 > _MAX_MESSAGE_LINES:
        return _drop(RedactionDropReason.WORK_LIMIT)
    try:
        _validate_placeholders(normalized)
        sanitized = _redact_whole_json(normalized)
        if sanitized is None:
            sanitized = _redact_detected(_redact_text(normalized))
        if _has_surviving_sensitive_content(sanitized):
            return _drop(RedactionDropReason.INTERNAL_ERROR)
    except _MalformedStructure:
        return _drop(RedactionDropReason.MALFORMED_STRUCTURE)
    except _StructureLimit:
        return _drop(RedactionDropReason.STRUCTURE_LIMIT)
    except _WorkLimit:
        return _drop(RedactionDropReason.WORK_LIMIT)
    except Exception:  # noqa: BLE001 - fail closed across detectors and JSON internals
        return _drop(RedactionDropReason.INTERNAL_ERROR)
    sanitized, truncated = _clamp_message(sanitized)
    fingerprint = sha256(_FINGERPRINT_DOMAIN + sanitized.encode("utf-8")).hexdigest()
    return RedactionResult(
        message=sanitized,
        fingerprint=fingerprint,
        drop_reason=None,
        changed=sanitized != message,
        truncated=truncated,
    )
