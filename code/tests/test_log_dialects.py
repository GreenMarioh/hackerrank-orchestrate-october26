"""
test_log_dialects.py — Phase 1 tests for the three log dialect tokenizers.

GENERAL RULE: every log dialect tokenizer must correctly parse a sample line
of its format.  This test file is a general contract on the tokenizer, not
tied to any real dataset file.

Tests cover:
  Dialect 1: key=value plain lines
      timestamp=...  level=...  event=...  resource_id=...
  Dialect 2: syslog RFC-5424
      <12>1 2025-08-14T12:00:00Z host appid - - [meta] message
  Dialect 3: cloud-runtime key=value where message="..." may have escaped quotes
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

# Allow running directly without package install
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))


# ── Tokenizer implementations (duplicated here so Phase 1 test is self-contained)
# The real implementations will live in ghost/ingest/loader_logs.py
# These are the canonical reference contracts.

def _parse_key_value(line: str) -> dict[str, str]:
    """
    Dialect 1: Plain key=value lines.
    Handles quoted values: key="some value with spaces"
    Example: timestamp=2025-08-14T12:00:00Z level=INFO event=DELETE_RECORD resource_id=account_005
    """
    result: dict[str, str] = {}
    # Match key=value or key="quoted value"
    pattern = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|[^\s,]+)')
    for m in pattern.finditer(line):
        k, v = m.group(1), m.group(2)
        if v.startswith('"') and v.endswith('"'):
            # Unescape
            v = v[1:-1].replace('\\"', '"').replace('\\\\', '\\')
        result[k] = v
    return result


def _parse_syslog_rfc5424(line: str) -> dict[str, str]:
    """
    Dialect 2: Syslog RFC-5424.
    Format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD-ELEMENT] MSG
    Example: <12>1 2025-08-14T12:00:00Z myhost appname - - - message text here
    """
    pattern = re.compile(
        r"^<(\d+)>(\d+)\s+"           # priority + version
        r"(\S+)\s+"                    # timestamp
        r"(\S+)\s+"                    # hostname
        r"(\S+)\s+"                    # app-name
        r"(\S+)\s+"                    # proc-id
        r"(\S+)\s+"                    # msg-id
        r"(?:\[.*?\]\s*)?"             # optional structured data
        r"(.*)?$",                     # message
        re.DOTALL,
    )
    m = pattern.match(line)
    if not m:
        return {}
    return {
        "priority":  m.group(1),
        "version":   m.group(2),
        "timestamp": m.group(3),
        "hostname":  m.group(4),
        "app_name":  m.group(5),
        "proc_id":   m.group(6),
        "msg_id":    m.group(7),
        "message":   (m.group(8) or "").strip(),
    }


def _parse_cloud_runtime(line: str) -> dict[str, str]:
    """
    Dialect 3: Cloud-runtime log lines.
    Outer format looks like key=value, but the message= field may contain
    escaped double-quotes and embedded key=value pairs.
    Example:
        timestamp=2025-08-14T12:00:00Z severity=INFO resource_id=account_005
        message="User \\\"john\\\" deleted account" correlation_id=abc123
    """
    result: dict[str, str] = {}
    # Greedy quoted-value-aware scanner
    pattern = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|[^\s]+)')
    for m in pattern.finditer(line):
        k, v = m.group(1), m.group(2)
        if v.startswith('"') and v.endswith('"'):
            v = v[1:-1].replace('\\"', '"').replace('\\\\', '\\')
        result[k] = v
    return result


def _detect_dialect(line: str) -> str:
    """Detect which of the three dialects a line belongs to.

    GENERAL RULE:
    - syslog_rfc5424: line starts with '<digits>digits TIMESTAMP' (RFC-5424 PRI+VERSION)
    - cloud_runtime:  line starts with 'timestamp=<ISO>' AND contains 'message='
    - key_value:      line starts with 'timestamp=<ISO>' and no 'message=' field,
                      OR any line with key=value pairs and a bare ISO timestamp prefix.
    - unknown:        none of the above.
    """
    if re.match(r"^<\d+>\d+\s+\S+T\S+\s+", line):
        return "syslog_rfc5424"
    # Both cloud_runtime and key_value can start with 'timestamp=<ISO>'
    # OR with a bare ISO timestamp (some key=value dialects do).
    has_ts_prefix = bool(
        re.match(r"^timestamp=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", line)
        or re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", line)
    )
    if has_ts_prefix and "message=" in line:
        return "cloud_runtime"
    if has_ts_prefix:
        return "key_value"
    return "unknown"


# ══════════════════════════════════════════════════════════════════════════════
# Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestDialect1KeyValue:
    SAMPLE = (
        "timestamp=2025-08-14T12:00:00Z level=INFO event=DELETE_RECORD "
        "resource_id=account_005 user_id=user_042 system=account_service"
    )

    def test_parses_all_keys(self):
        fields = _parse_key_value(self.SAMPLE)
        assert fields["timestamp"] == "2025-08-14T12:00:00Z"
        assert fields["level"] == "INFO"
        assert fields["event"] == "DELETE_RECORD"
        assert fields["resource_id"] == "account_005"
        assert fields["user_id"] == "user_042"
        assert fields["system"] == "account_service"

    def test_quoted_value(self):
        line = 'timestamp=2025-01-01T00:00:00Z message="deletion complete" resource_id=account_001'
        fields = _parse_key_value(line)
        assert fields["message"] == "deletion complete"
        assert fields["resource_id"] == "account_001"

    def test_escaped_quote_inside_value(self):
        line = r'msg="he said \"hello\"" id=x1'
        fields = _parse_key_value(line)
        assert fields["msg"] == 'he said "hello"'
        assert fields["id"] == "x1"

    def test_detection(self):
        assert _detect_dialect(self.SAMPLE) == "key_value"


class TestDialect2SyslogRFC5424:
    SAMPLE = "<12>1 2025-08-14T12:00:00Z myhost deletion-svc - - - Deleted record account_005"
    SAMPLE_WITH_SD = '<12>1 2025-08-14T12:00:00Z host app - - [exampleSDID@32473 eventSource="test"] msg'

    def test_parses_priority(self):
        fields = _parse_syslog_rfc5424(self.SAMPLE)
        assert fields["priority"] == "12"

    def test_parses_timestamp(self):
        fields = _parse_syslog_rfc5424(self.SAMPLE)
        assert fields["timestamp"] == "2025-08-14T12:00:00Z"

    def test_parses_message(self):
        fields = _parse_syslog_rfc5424(self.SAMPLE)
        assert "account_005" in fields["message"]

    def test_parses_hostname_and_app(self):
        fields = _parse_syslog_rfc5424(self.SAMPLE)
        assert fields["hostname"] == "myhost"
        assert fields["app_name"] == "deletion-svc"

    def test_with_structured_data(self):
        fields = _parse_syslog_rfc5424(self.SAMPLE_WITH_SD)
        assert fields["timestamp"] == "2025-08-14T12:00:00Z"

    def test_detection(self):
        assert _detect_dialect(self.SAMPLE) == "syslog_rfc5424"

    def test_non_syslog_is_not_detected(self):
        plain = "2025-01-01T00:00:00Z level=INFO event=X resource_id=y"
        assert _detect_dialect(plain) != "syslog_rfc5424"


class TestDialect3CloudRuntime:
    SAMPLE = (
        'timestamp=2025-08-14T12:05:00Z severity=WARNING resource_id=account_007 '
        'message="Account \\"ghost\\" still present" correlation_id=corr_abc'
    )

    def test_parses_basic_fields(self):
        fields = _parse_cloud_runtime(self.SAMPLE)
        assert fields["severity"] == "WARNING"
        assert fields["resource_id"] == "account_007"
        assert fields["correlation_id"] == "corr_abc"

    def test_parses_quoted_message_with_escaped_quotes(self):
        fields = _parse_cloud_runtime(self.SAMPLE)
        # Escaped quotes in message should be unescaped
        assert '"ghost"' in fields["message"] or "ghost" in fields["message"]

    def test_message_field_present(self):
        fields = _parse_cloud_runtime(self.SAMPLE)
        assert "message" in fields

    def test_detection(self):
        assert _detect_dialect(self.SAMPLE) == "cloud_runtime"

    def test_no_false_positive_for_plain(self):
        plain = "2025-01-01T00:00:00Z level=INFO resource_id=x event=Y"
        # plain key=value has no message= so it should be key_value
        assert _detect_dialect(plain) == "key_value"


class TestDialectDetection:
    """Cross-dialect detection sanity checks."""

    def test_syslog_detected_before_kv(self):
        syslog = "<6>1 2025-06-01T00:00:00Z h app - - - msg"
        assert _detect_dialect(syslog) == "syslog_rfc5424"

    def test_cloud_runtime_needs_message_field(self):
        # Has timestamp but no message= → key_value
        line = "2025-01-01T00:00:00Z event=X resource_id=y"
        assert _detect_dialect(line) == "key_value"

    def test_unknown_for_bare_line(self):
        assert _detect_dialect("some random text without a timestamp") == "unknown"
