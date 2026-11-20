"""Regression tests for the P0/P1 findings of issue #7 (F1-F6).

Each attack here succeeded against the pre-fix gate.
"""

import hashlib
import json
import multiprocessing
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gate import ApprovalStore, GateError, SendGate, StoreIntegrityError  # noqa: E402
from gate.send_gate import GENESIS, main  # noqa: E402

MANIFEST = {"version": 1, "tools": {
    "mail.draft": {"tier": "draft"},
    "mail.send": {"tier": "send"},
}}
KEY = "test-approver-secret"


def make_gate(tmp_path, sent_box, **kw):
    manifest_path = tmp_path / "permissions.json"
    manifest_path.write_text(json.dumps(MANIFEST), encoding="utf-8")
    executors = {
        "mail.draft": lambda body: f"draft: {body}",
        "mail.send": lambda to, body: sent_box.append((to, body)) or "sent",
    }
    return SendGate.from_files(manifest_path, executors, tmp_path / "store.jsonl", **kw)


@pytest.fixture(autouse=True)
def approver_key(monkeypatch):
    monkeypatch.setenv("SEND_GATE_APPROVER_KEY", KEY)


@pytest.fixture()
def sent_box():
    return []


@pytest.fixture()
def gate(tmp_path, sent_box):
    return make_gate(tmp_path, sent_box)


def rewrite(store: ApprovalStore, mutate):
    """Sophisticated attacker: edit events, then recompute chain AND head."""
    events = store.events()
    mutate(events)
    prev, lines = GENESIS, []
    for ev in events:
        ev["prev"] = prev
        line = json.dumps(ev, ensure_ascii=False, sort_keys=True)
        lines.append(line)
        prev = hashlib.sha256(line.encode()).hexdigest()
    store.path.write_text("".join(x + "\n" for x in lines), encoding="utf-8")
    store.head_path.write_text(json.dumps({"count": len(lines), "hash": prev}), encoding="utf-8")


def approved(gate, to="a@b.c", body="hello"):
    rid = gate.call("mail.send", to=to, body=body).request_id
    gate.approve(rid, approver="human")
    return rid


# -- F1 -----------------------------------------------------------------

def test_f1_tampered_args_after_approval_do_not_execute(gate, sent_box):
    rid = approved(gate)

    def evil(events):
        for ev in events:
            if ev["type"] == "pending":
                ev["args"] = {"to": "evil@x.y", "body": "pwned"}

    rewrite(gate.store, evil)
    res = gate.execute_approved(rid)
    assert res.status == "denied"
    assert sent_box == []
    assert "audit:denied_args_tampered" in [e["type"] for e in gate.store.events()]


def test_f1_tampered_args_with_matching_hash_still_void(gate, sent_box):
    rid = approved(gate)
    evil_args = {"to": "evil@x.y", "body": "pwned"}
    evil_hash = hashlib.sha256(json.dumps(evil_args, sort_keys=True).encode()).hexdigest()

    def evil(events):
        for ev in events:
            if ev["type"] == "pending":
                ev["args"], ev["args_sha256"] = evil_args, evil_hash

    rewrite(gate.store, evil)
    assert gate.execute_approved(rid).status == "denied"  # approval signed the original hash
    assert sent_box == []


# -- F2 -----------------------------------------------------------------

def test_f2_later_events_cannot_replace_tool_or_args(gate, sent_box):
    rid = approved(gate)
    gate.store.append({"type": "approved", "request_id": rid, "tool": "mail.send",
                       "args": {"to": "evil@x.y", "body": "pwned"}})
    gate.store.append({"type": "pending", "request_id": rid, "tool": "shell.exec", "args": {"cmd": "x"}})
    state = gate.store.request_state(rid)
    assert state["tool"] == "mail.send"
    assert state["args"] == {"to": "a@b.c", "body": "hello"}
    assert gate.execute_approved(rid).status == "executed"
    assert sent_box == [("a@b.c", "hello")]


def test_f2_tool_revalidated_against_manifest_at_execution(gate, sent_box):
    rid = approved(gate)
    gate.manifest["mail.send"] = "draft"  # tier downgraded since approval
    assert gate.execute_approved(rid).status == "denied"
    del gate.manifest["mail.send"]
    assert gate.execute_approved(rid).status == "denied"
    assert sent_box == []


def test_f2_non_send_tool_in_store_is_refused(gate, sent_box):
    """A forged request for a draft tool cannot be run through the send path."""
    rid = approved(gate)

    def retool(events):
        for ev in events:
            if ev["type"] == "pending":
                ev["tool"] = "mail.draft"

    rewrite(gate.store, retool)
    assert gate.execute_approved(rid).status == "denied"


# -- F3 -----------------------------------------------------------------

def test_f3_self_approval_without_key_is_impossible(gate, sent_box, monkeypatch):
    rid = gate.call("mail.send", to="a@b.c", body="x").request_id
    monkeypatch.delenv("SEND_GATE_APPROVER_KEY")
    with pytest.raises(GateError):
        gate.approve(rid, approver="agent")


def test_f3_forged_approval_event_is_refused(gate, sent_box):
    res = gate.call("mail.send", to="a@b.c", body="x")
    st = gate.store.request_state(res.request_id)
    for sig in (None, "00" * 32):
        gate.store.append({"type": "approved", "request_id": res.request_id, "by": "agent",
                           "at": 1.0, "args_sha256": st["args_sha256"],
                           **({"signature": sig} if sig else {})})
    assert gate.execute_approved(res.request_id).status == "denied"
    assert sent_box == []
    assert "audit:denied_bad_signature" in [e["type"] for e in gate.store.events()]
    # forged approvals must not block the real human approval
    gate.approve(res.request_id, approver="human")
    assert gate.execute_approved(res.request_id).status == "executed"


def test_f3_approval_signed_with_wrong_key_is_refused(gate, sent_box, monkeypatch):
    monkeypatch.setenv("SEND_GATE_APPROVER_KEY", "attacker-guess")
    rid = gate.call("mail.send", to="a@b.c", body="x").request_id
    gate.approve(rid, approver="agent")
    monkeypatch.setenv("SEND_GATE_APPROVER_KEY", KEY)
    assert gate.execute_approved(rid).status == "denied"
    assert sent_box == []


def test_f3_execution_without_key_is_refused(gate, sent_box, monkeypatch):
    rid = approved(gate)
    monkeypatch.delenv("SEND_GATE_APPROVER_KEY")
    assert gate.execute_approved(rid).status == "denied"
    assert sent_box == []


def test_f3_cli_approve_signs(tmp_path, sent_box, gate, capsys):
    rid = gate.call("mail.send", to="a@b.c", body="x").request_id
    assert main(["--store", str(gate.store.path), "approve", rid, "--by", "me"]) == 0
    assert gate.execute_approved(rid).status == "executed"


def test_f3_cli_approve_without_key_refused(gate, monkeypatch):
    rid = gate.call("mail.send", to="a@b.c", body="x").request_id
    monkeypatch.delenv("SEND_GATE_APPROVER_KEY")
    assert main(["--store", str(gate.store.path), "approve", rid, "--by", "me"]) == 1


def test_f3_truncating_the_ledger_fails_closed(gate, sent_box):
    rid = approved(gate)
    lines = gate.store.path.read_text().splitlines(keepends=True)
    gate.store.path.write_text("".join(lines[:-2]), encoding="utf-8")  # drop approval + audit
    with pytest.raises(StoreIntegrityError):
        gate.store.verify()
    assert gate.execute_approved(rid).status == "denied"
    assert gate.call("mail.send", to="a@b.c", body="y").status == "denied"


def test_f3_dropping_the_sent_event_cannot_enable_replay(gate, sent_box):
    rid = approved(gate)
    gate.execute_approved(rid)
    lines = gate.store.path.read_text().splitlines(keepends=True)
    keep = [x for x in lines if '"type": "sent"' not in x and '"type":"sent"' not in x]
    gate.store.path.write_text("".join(keep), encoding="utf-8")
    assert gate.execute_approved(rid).status == "denied"
    assert len(sent_box) == 1


def test_f3_rewriting_a_middle_line_fails_closed(gate):
    approved(gate)
    text = gate.store.path.read_text().replace("hello", "HELLO", 1)
    gate.store.path.write_text(text, encoding="utf-8")
    with pytest.raises(StoreIntegrityError):
        gate.store.verify()


def test_f3_deleting_the_store_fails_closed(gate):
    rid = approved(gate)
    gate.store.path.unlink()
    with pytest.raises(StoreIntegrityError):
        gate.store.verify()
    assert gate.execute_approved(rid).status == "denied"


def test_f3_cli_verify(gate, capsys):
    approved(gate)
    assert main(["--store", str(gate.store.path), "verify"]) == 0
    gate.store.path.write_text(gate.store.path.read_text().replace("hello", "HELLO", 1))
    assert main(["--store", str(gate.store.path), "verify"]) == 1


def test_f3_replayed_approval_cannot_resurrect_sent_request(gate, sent_box):
    rid = approved(gate)
    approval = next(e for e in gate.store.events() if e["type"] == "approved")
    gate.execute_approved(rid)
    gate.store.append({k: v for k, v in approval.items() if k != "prev"})  # valid signed copy
    assert gate.execute_approved(rid).status == "denied"
    assert len(sent_box) == 1


# -- F4 -----------------------------------------------------------------

def _race(args):
    tmp, rid = args
    sent = []

    def slow_send(to, body):
        import time
        time.sleep(0.3)
        sent.append(1)
        return "sent"

    manifest = Path(tmp) / "permissions.json"
    g = SendGate.from_files(manifest, {"mail.send": slow_send}, Path(tmp) / "store.jsonl")
    return g.execute_approved(rid).status, len(sent)


def test_f4_concurrent_execution_sends_once(tmp_path, sent_box):
    gate = make_gate(tmp_path, sent_box)
    rid = approved(gate)
    ctx = multiprocessing.get_context("fork")
    with ctx.Pool(4) as pool:
        results = pool.map(_race, [(str(tmp_path), rid)] * 4)
    assert sum(sent for _, sent in results) == 1
    assert sorted(s for s, _ in results) == ["denied"] * 3 + ["executed"]


# -- F5 -----------------------------------------------------------------

def test_f5_expired_approval_is_refused(tmp_path, sent_box):
    now = [1000.0]
    gate = make_gate(tmp_path, sent_box)
    gate._clock = lambda: now[0]
    rid = approved(gate)
    now[0] += 24 * 3600 + 1
    assert gate.execute_approved(rid).status == "denied"
    assert sent_box == []
    assert "audit:denied_expired" in [e["type"] for e in gate.store.events()]


def test_f5_within_ttl_and_custom_ttl(tmp_path, sent_box):
    now = [1000.0]
    gate = make_gate(tmp_path, sent_box, approval_ttl=60)
    gate._clock = lambda: now[0]
    rid = approved(gate)
    now[0] += 59
    assert gate.execute_approved(rid).status == "executed"
    rid2 = approved(gate, body="two")
    now[0] += 61
    assert gate.execute_approved(rid2).status == "denied"


def test_f5_extending_approval_time_invalidates_signature(tmp_path, sent_box):
    now = [1000.0]
    gate = make_gate(tmp_path, sent_box)
    gate._clock = lambda: now[0]
    rid = approved(gate)
    now[0] += 24 * 3600 + 1

    def refresh(events):
        for ev in events:
            if ev["type"] == "approved":
                ev["at"] = now[0]

    rewrite(gate.store, refresh)
    assert gate.execute_approved(rid).status == "denied"


# -- F6 -----------------------------------------------------------------

def test_f6_identical_request_after_denial_is_refused(gate):
    first = gate.call("mail.send", to="a@b.c", body="spam")
    gate.deny(first.request_id, approver="human")
    again = gate.call("mail.send", to="a@b.c", body="spam")
    assert again.status == "denied"
    assert again.request_id == first.request_id
    assert gate.pending() == []


def test_f6_changed_args_may_be_requested(gate):
    first = gate.call("mail.send", to="a@b.c", body="spam")
    gate.deny(first.request_id, approver="human")
    assert gate.call("mail.send", to="a@b.c", body="different").status == "pending"
