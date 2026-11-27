"""Regression tests for findings F7 and F8 of issue #7.

F7: an executor that raises left the approval live and wrote no audit
    event, so the same approval could be retried and the log could not
    say whether anything went out.
F8: an audit write failure was swallowed silently (`except: pass`).
"""

import json
import logging
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gate import ApprovalStore, SendGate  # noqa: E402

MANIFEST = {
    "version": 1,
    "tools": {
        "mail.search": {"tier": "read"},
        "mail.send": {"tier": "send"},
    },
}
KEY = "test-approver-secret"


@pytest.fixture(autouse=True)
def approver_key(monkeypatch):
    monkeypatch.setenv("SEND_GATE_APPROVER_KEY", KEY)


class Flaky:
    """Executor that raises on every call and counts attempts."""

    def __init__(self, exc):
        self.exc = exc
        self.calls = 0

    def __call__(self, **kwargs):
        self.calls += 1
        raise self.exc


def make_gate(tmp_path, send, search=lambda q: "hits", audit_path=None):
    manifest_path = tmp_path / "permissions.json"
    manifest_path.write_text(json.dumps(MANIFEST), encoding="utf-8")
    executors = {"mail.search": search, "mail.send": send}
    return SendGate.from_files(manifest_path, executors, tmp_path / "store.jsonl", audit_path=audit_path)


def types(store):
    return [e["type"] for e in store.events()]


# -- F7: executor failure is recorded and consumes the approval -------------


def test_f7_send_executor_failure_is_recorded_not_raised(tmp_path):
    send = Flaky(RuntimeError("smtp down"))
    gate = make_gate(tmp_path, send)
    rid = gate.call("mail.send", to="a@b.c", body="hi").request_id
    gate.approve(rid, approver="human")

    result = gate.execute_approved(rid)

    assert result.status == "failed"
    assert "smtp down" in result.detail
    assert gate.store.request_state(rid, KEY.encode())["last_event"] == "failed"
    failed = [e for e in gate.store.events() if e["type"] == "failed"]
    assert len(failed) == 1 and "RuntimeError: smtp down" in failed[0]["error"]
    assert "audit:failed" in types(gate.store)
    assert "sent" not in types(gate.store)


def test_f7_failed_approval_cannot_be_retried(tmp_path):
    send = Flaky(RuntimeError("smtp down"))
    gate = make_gate(tmp_path, send)
    rid = gate.call("mail.send", to="a@b.c", body="hi").request_id
    gate.approve(rid, approver="human")
    gate.execute_approved(rid)

    retry = gate.execute_approved(rid)

    assert retry.status == "denied"
    assert send.calls == 1  # the executor ran once; the approval is spent


def test_f7_failed_request_can_be_requested_again(tmp_path):
    """A failure is not a denial: the agent may re-request, a human re-approves."""
    gate = make_gate(tmp_path, Flaky(RuntimeError("smtp down")))
    rid = gate.call("mail.send", to="a@b.c", body="hi").request_id
    gate.approve(rid, approver="human")
    gate.execute_approved(rid)

    again = gate.call("mail.send", to="a@b.c", body="hi")

    assert again.status == "pending" and again.request_id != rid


def test_f7_sent_event_cannot_follow_failed(tmp_path):
    gate = make_gate(tmp_path, Flaky(RuntimeError("smtp down")))
    rid = gate.call("mail.send", to="a@b.c", body="hi").request_id
    gate.approve(rid, approver="human")
    gate.execute_approved(rid)
    gate.store.append({"type": "sent", "request_id": rid, "at": 0.0})

    assert gate.store.request_state(rid, KEY.encode())["last_event"] == "failed"


def test_f7_read_executor_failure_is_audited(tmp_path):
    search = Flaky(TimeoutError("index offline"))
    gate = make_gate(tmp_path, Flaky(RuntimeError("unused")), search=search)

    result = gate.call("mail.search", q="x")

    assert result.status == "failed"
    assert "index offline" in result.detail
    failed = [e for e in gate.store.events() if e["type"] == "audit:failed"]
    assert len(failed) == 1 and failed[0]["tier"] == "read"
    assert "TimeoutError: index offline" in failed[0]["error"]


def test_f7_error_text_is_bounded(tmp_path):
    gate = make_gate(tmp_path, Flaky(RuntimeError("x" * 10_000)))
    rid = gate.call("mail.send", to="a@b.c", body="hi").request_id
    gate.approve(rid, approver="human")
    gate.execute_approved(rid)

    failed = next(e for e in gate.store.events() if e["type"] == "failed")
    assert len(failed["error"]) <= 500


# -- F8: audit write failure is observable, never silent ---------------------


class BrokenSink(ApprovalStore):
    def append(self, event):
        raise OSError("disk full")


def test_f8_audit_failure_is_logged_and_counted(tmp_path, caplog):
    gate = make_gate(tmp_path, Flaky(RuntimeError("unused")))
    gate.audit = BrokenSink(tmp_path / "audit.jsonl")

    with caplog.at_level(logging.ERROR, logger="send_gate"):
        result = gate.call("mail.undeclared")

    assert result.status == "denied"  # the refusal stands
    assert gate.audit_failures == 1
    assert any("audit:denied_unknown_tool" in r.getMessage() and "disk full" in r.getMessage() for r in caplog.records)


def test_f8_audit_failure_never_turns_a_block_into_a_send(tmp_path):
    send = Flaky(RuntimeError("must not run"))
    gate = make_gate(tmp_path, send)
    gate.audit = BrokenSink(tmp_path / "audit.jsonl")

    result = gate.call("mail.send", to="a@b.c", body="hi")

    assert result.status == "pending"
    assert send.calls == 0
    assert gate.audit_failures == 1
