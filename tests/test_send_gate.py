"""The gate's promises, as tests. Run: python -m pytest tests/ -q"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gate import ApprovalStore, GateError, SendGate  # noqa: E402

MANIFEST = {"version": 1, "tools": {
    "mail.search": {"tier": "read"},
    "mail.draft": {"tier": "draft"},
    "mail.send": {"tier": "send"},
}}


@pytest.fixture()
def sent_box():
    return []


@pytest.fixture()
def gate(tmp_path, sent_box):
    manifest_path = tmp_path / "permissions.json"
    manifest_path.write_text(json.dumps(MANIFEST), encoding="utf-8")
    executors = {
        "mail.search": lambda q: f"hits for {q}",
        "mail.draft": lambda body: f"draft: {body}",
        "mail.send": lambda to, body: sent_box.append((to, body)) or "sent",
    }
    return SendGate.from_files(manifest_path, executors, tmp_path / "store.jsonl")


def test_read_and_draft_execute_immediately(gate):
    assert gate.call("mail.search", q="x").status == "executed"
    assert gate.call("mail.draft", body="hi").status == "executed"


def test_send_is_blocked_and_nothing_is_sent(gate, sent_box):
    result = gate.call("mail.send", to="a@b.c", body="hello")
    assert result.status == "pending"
    assert result.request_id
    assert sent_box == []


def test_approved_send_executes_exactly_once(gate, sent_box):
    rid = gate.call("mail.send", to="a@b.c", body="hello").request_id
    gate.approve(rid, approver="human")
    assert gate.execute_approved(rid).status == "executed"
    assert sent_box == [("a@b.c", "hello")]
    replay = gate.execute_approved(rid)
    assert replay.status == "denied"
    assert sent_box == [("a@b.c", "hello")]


def test_denied_send_never_executes(gate, sent_box):
    rid = gate.call("mail.send", to="a@b.c", body="hello").request_id
    gate.deny(rid, approver="human")
    assert gate.execute_approved(rid).status == "denied"
    assert sent_box == []


def test_unapproved_execution_is_denied(gate, sent_box):
    rid = gate.call("mail.send", to="a@b.c", body="hello").request_id
    assert gate.execute_approved(rid).status == "denied"
    assert sent_box == []


def test_undeclared_tool_is_denied(gate):
    assert gate.call("mail.delete_everything").status == "denied"
    assert gate.call("shell.exec", cmd="rm -rf /").status == "denied"


def test_deciding_twice_is_refused(gate):
    rid = gate.call("mail.send", to="a@b.c", body="x").request_id
    gate.approve(rid, approver="human")
    with pytest.raises(GateError):
        gate.deny(rid, approver="human")


def test_missing_manifest_denies_everything(tmp_path):
    with pytest.raises(GateError):
        SendGate.from_files(tmp_path / "nope.json", {}, tmp_path / "s.jsonl")


def test_corrupt_store_blocks_execution(tmp_path, gate):
    rid = gate.call("mail.send", to="a@b.c", body="hello").request_id
    gate.approve(rid, approver="human")
    gate.store.path.write_text("{not json\n", encoding="utf-8")
    assert gate.execute_approved(rid).status == "denied"


def test_audit_log_records_the_whole_story(gate, tmp_path):
    rid = gate.call("mail.send", to="a@b.c", body="hello").request_id
    gate.approve(rid, approver="human")
    gate.execute_approved(rid)
    types = [e["type"] for e in ApprovalStore(gate.store.path).events()]
    assert "audit:blocked_pending" in types
    assert "audit:approved" in types
    assert "audit:sent" in types
