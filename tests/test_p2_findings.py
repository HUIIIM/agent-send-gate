"""Regression tests for the P2 findings of issue #7 (F9-F11, F13-F16).

Each test fails against the gate as it was before this change.
"""

import datetime
import io
import json
import subprocess
import sys
from contextlib import redirect_stdout
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from gate import GateError, SendGate  # noqa: E402
from gate.send_gate import main, sign_decision  # noqa: E402

KEY = "test-approver-secret"
MANIFEST = {"version": 1, "tools": {"mail.send": {"tier": "send"}}}


@pytest.fixture(autouse=True)
def approver_key(monkeypatch):
    monkeypatch.setenv("SEND_GATE_APPROVER_KEY", KEY)


def write_manifest(tmp_path, data):
    p = tmp_path / "permissions.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def make_gate(tmp_path, sent=None):
    sent = [] if sent is None else sent
    executors = {"mail.send": lambda **kw: sent.append(kw) or "sent"}
    return SendGate.from_files(write_manifest(tmp_path, MANIFEST), executors, tmp_path / "store.jsonl")


# -- F9: the manifest is validated against its own schema ---------------------


@pytest.mark.parametrize(
    "bad",
    [
        {"tools": {"x": {"tier": "read"}}},  # missing version
        {"version": 2, "tools": {"x": {"tier": "read"}}},  # wrong version
        {"version": 1, "tools": {"x": {"tier": "read"}}, "extra": True},  # unknown top-level key
        {"version": 1, "tools": {"x": {"tier": "read", "bogus": 1}}},  # unknown tool key
        {"version": 1, "tools": {}},  # no tools
        {"version": 1, "tools": {"x": {"tier": "read", "description": 5}}},  # wrong type
        {"version": True, "tools": {"x": {"tier": "read"}}},  # bool is not the integer 1
    ],
)
def test_f9_manifest_violating_schema_is_refused(tmp_path, bad):
    with pytest.raises(GateError):
        SendGate.from_files(write_manifest(tmp_path, bad), {}, tmp_path / "s.jsonl")


def test_f9_example_manifest_still_loads(tmp_path):
    path = ROOT / "examples" / "gmail" / "permissions.json"
    gate = SendGate.from_files(path, {}, tmp_path / "s.jsonl")
    assert gate.manifest["gmail.send_message"] == "send"


# -- F10: arguments that do not survive JSON unchanged are refused -------------


@pytest.mark.parametrize(
    "value",
    [datetime.date(2026, 1, 1), b"bytes", ("a", "b"), float("nan"), {1: "int key"}],
)
def test_f10_non_json_args_are_refused_not_coerced(tmp_path, value):
    sent = []
    gate = make_gate(tmp_path, sent)
    result = gate.call("mail.send", to=value, body="hi")
    assert result.status == "denied"
    assert "JSON" in result.detail
    assert gate.pending() == []
    assert sent == []


def test_f10_plain_json_args_still_queue(tmp_path):
    gate = make_gate(tmp_path)
    assert gate.call("mail.send", to=["a@b.c"], body={"text": "hi", "n": 1.5}).status == "pending"


# -- F11: the reviewer sees invisible and bidi characters escaped --------------


def test_f11_cli_list_escapes_bidi_and_control_characters(tmp_path):
    gate = make_gate(tmp_path)
    gate.call("mail.send", to="moc.live@rekcatta‮", body="a​b\x1b[31m")
    buf = io.StringIO()
    with redirect_stdout(buf):
        assert main(["--store", str(gate.store.path), "list"]) == 0
    out = buf.getvalue()
    for raw in ("‮", "​", "\x1b"):
        assert raw not in out
    assert "\\u202e" in out and "\\u200b" in out and "\\u001b" in out


def test_f11_cli_list_keeps_cjk_readable(tmp_path):
    gate = make_gate(tmp_path)
    gate.call("mail.send", to="张三 <a@b.c>", body="你好")
    buf = io.StringIO()
    with redirect_stdout(buf):
        main(["--store", str(gate.store.path), "list"])
    assert "张三" in buf.getvalue() and "你好" in buf.getvalue()


# -- F13: request ids are full-width and unique within the store ---------------


def test_f13_request_id_is_128_bit(tmp_path):
    rid = make_gate(tmp_path).call("mail.send", to="a@b.c", body="hi").request_id
    assert rid is not None and len(rid) == 32
    int(rid, 16)


def test_f13_colliding_request_id_is_regenerated(tmp_path, monkeypatch):
    import gate.send_gate as sg

    gate = make_gate(tmp_path)
    ids = iter(["a" * 32, "a" * 32, "b" * 32])

    class FakeUUID:
        def __init__(self, h):
            self.hex = h

    monkeypatch.setattr(sg.uuid, "uuid4", lambda: FakeUUID(next(ids)))
    first = gate.call("mail.send", to="a@b.c", body="one").request_id
    second = gate.call("mail.send", to="a@b.c", body="two").request_id
    assert first == "a" * 32 and second == "b" * 32
    assert {s["request_id"] for s in gate.pending()} == {"a" * 32, "b" * 32}


# -- F14: the approver's identity is bound into the signature ------------------


def test_f14_rewriting_approver_name_invalidates_the_approval(tmp_path):
    from tests.test_hardening import rewrite

    sent = []
    gate = make_gate(tmp_path, sent)
    rid = gate.call("mail.send", to="a@b.c", body="hi").request_id
    gate.approve(rid, approver="alice")
    rewrite(gate.store, lambda ev: [e.__setitem__("by", "mallory") for e in ev if e["type"] == "approved"])
    assert gate.execute_approved(rid).status == "denied"
    assert sent == []


def test_f14_decision_records_os_user_under_signature(tmp_path):
    gate = make_gate(tmp_path)
    rid = gate.call("mail.send", to="a@b.c", body="hi").request_id
    gate.approve(rid, approver="alice")
    ev = next(e for e in gate.store.events() if e["type"] == "approved")
    assert ev["by"] == "alice" and isinstance(ev.get("os_user"), str)
    legacy = sign_decision(KEY.encode(), rid, ev["args_sha256"], "approved", ev["at"])
    assert ev["signature"] != legacy  # identity fields are inside the MAC


@pytest.mark.parametrize("name", ["", " ", "a‮b", "x" * 65, "line\nbreak"])
def test_f14_unusable_approver_names_are_refused(tmp_path, name):
    gate = make_gate(tmp_path)
    rid = gate.call("mail.send", to="a@b.c", body="hi").request_id
    with pytest.raises(GateError):
        gate.approve(rid, approver=name)


# -- F15: README claims match the code ----------------------------------------


def test_f15_readme_makes_no_stale_size_or_count_claims():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "~250 lines" not in text
    assert "tests-41%20passing" not in text and "tests-33%20passing" not in text
    assert "# 41 tests" not in text and "# 10 tests" not in text
    assert "the agent cannot rewrite" not in text


# -- F16: `python -m gate` runs the CLI without a RuntimeWarning ---------------


def test_f16_python_dash_m_gate_runs_without_warning(tmp_path):
    proc = subprocess.run(
        [sys.executable, "-W", "error::RuntimeWarning", "-m", "gate", "--store", str(tmp_path / "s.jsonl"), "list"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "RuntimeWarning" not in proc.stderr
