"""send_gate: a human-approval gate for outbound agent actions.

The gate sits between an agent and its tools. Every tool is declared at
one of three tiers in a permissions manifest:

    read   - look, search, fetch. Executes immediately.
    draft  - prepare content that stays inside the system (a draft, a
             local file, a queued post). Executes immediately.
    send   - anything that leaves the system or commits you in front of
             another person: sending mail, posting, messaging, paying.
             NEVER executes on the agent's word alone.

A `send` call does not run. It is recorded as a pending approval request
and the agent gets a receipt, not a result. A human reviews the request
out of band (CLI below, or your own UI on top of the store) and either
approves or denies it. Only an approved request can be executed, exactly
once, through `execute_approved`.

Fail-closed rules, everywhere:

- A tool that is not in the manifest is denied. There is no default tier.
- A missing or corrupt manifest denies everything.
- A missing or corrupt approval store blocks every send execution.
- An approval is single-use: executing twice is denied.
- A denial is final for that request; an identical (tool, args) re-request
  is refused until the arguments change.
- Approvals are HMAC-SHA256 signed with SEND_GATE_APPROVER_KEY (held only
  by the approver CLI and the executor, never the agent), bind the args
  hash, and expire (default 24h). Args are re-hashed and the tool
  re-checked against the manifest at execution.
- The store is hash-chained; truncation or rewrites fail closed.
- Execution is serialized by an inter-process file lock.
- An executor that raises is recorded, not propagated: an approved send
  moves to the terminal state `failed` (the approval is spent; a retry
  needs a new request and a new approval), and every failure is audited.
- An audit write that fails never changes a decision, but it is never
  silent either: it is logged at ERROR on the `send_gate` logger and
  counted in `SendGate.audit_failures`.

Every decision is appended to an audit log (JSON lines) that the gate
never rewrites: executed, blocked_pending, approved, denied, sent,
failed, denied_unknown_tool, denied_replay, store_unavailable.

This is a reference implementation: single process, JSON file store,
standard library only. The security model is the point; swap the store
for your database and the CLI for your UI without changing the rules.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import hmac
import json
import logging
import os
import sys
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

TIERS = ("read", "draft", "send")
KEY_ENV = "SEND_GATE_APPROVER_KEY"
DEFAULT_APPROVAL_TTL = 24 * 60 * 60.0
GENESIS = "0" * 64
MAX_ERROR_CHARS = 500

log = logging.getLogger("send_gate")


class GateError(Exception):
    """Raised when the gate refuses an action. Refusal is the default."""


class StoreIntegrityError(GateError):
    """The store's hash chain is broken (rewrite, truncation, deletion)."""


@dataclass
class GateResult:
    status: str  # executed | pending | denied | failed
    tool: str
    detail: str
    request_id: str | None = None
    value: Any = None


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def args_digest(args: dict[str, Any]) -> str:
    """Canonical SHA-256 of a request's arguments."""
    return _sha256(json.dumps(args, ensure_ascii=False, sort_keys=True, default=str))


def sign_decision(key: bytes, request_id: str, args_sha256: str, decision: str, at: float) -> str:
    """HMAC-SHA256 over (request_id, args_sha256, decision, at).

    `at` is included so the approval time (which drives expiry) cannot be
    altered without the key.
    """
    msg = "\n".join([request_id, args_sha256, decision, repr(float(at))]).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _describe(exc: BaseException) -> str:
    """Bounded one-line description of an executor error, for the log."""
    return f"{type(exc).__name__}: {exc}"[:MAX_ERROR_CHARS]


def approver_key() -> bytes | None:
    """The approver secret from the environment, or None if unset/empty."""
    raw = os.environ.get(KEY_ENV, "")
    return raw.encode("utf-8") if raw else None


def _decision_valid(key: bytes, event: dict[str, Any], decision: str) -> bool:
    sig = event.get("signature")
    try:
        want = sign_decision(key, str(event["request_id"]), str(event["args_sha256"]), decision, float(event["at"]))
    except (KeyError, TypeError, ValueError):
        return False
    return isinstance(sig, str) and hmac.compare_digest(sig, want)


@contextmanager
def _file_lock(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)  # closing releases the flock


@dataclass
class ApprovalStore:
    """Append-only, hash-chained JSON-lines store.

    Every line carries `prev`, the SHA-256 of the previous raw line
    (GENESIS for the first). A sidecar `<store>.head` records the line
    count and last hash so tail truncation and deletion are detected too.
    Any inconsistency raises StoreIntegrityError: the store fails closed.
    Note: the chain detects tampering; it cannot stop a writer who rewrites
    the store AND head consistently. Approval authenticity rests on the
    HMAC signatures, and the store should live where the agent cannot write.
    """

    path: Path

    @property
    def head_path(self) -> Path:
        return self.path.with_name(self.path.name + ".head")

    def _lock(self) -> Any:
        return _file_lock(self.path.with_name(self.path.name + ".lock"))

    def _load(self) -> tuple[list[dict[str, Any]], str]:
        """Verify the chain; return (events, hash of last line)."""
        lines: list[str] = []
        if self.path.exists():
            text = self.path.read_text(encoding="utf-8")
            if text and not text.endswith("\n"):
                raise StoreIntegrityError("store ends with a partial line")
            lines = text.split("\n")[:-1] if text else []
        events: list[dict[str, Any]] = []
        prev = GENESIS
        hashes = [GENESIS]
        for n, line in enumerate(lines, 1):
            try:
                event = json.loads(line)
            except ValueError as exc:
                raise StoreIntegrityError(f"line {n} is not valid JSON") from exc
            if not isinstance(event, dict) or event.get("prev") != prev:
                raise StoreIntegrityError(f"hash chain broken at line {n}")
            events.append(event)
            prev = _sha256(line)
            hashes.append(prev)
        self._check_head(len(lines), hashes)
        return events, prev

    def _check_head(self, count: int, hashes: list[str]) -> None:
        if not self.head_path.exists():
            if count:
                raise StoreIntegrityError("store has entries but head record is missing")
            return
        try:
            head = json.loads(self.head_path.read_text(encoding="utf-8"))
            h_count, h_hash = int(head["count"]), str(head["hash"])
        except (ValueError, KeyError, TypeError) as exc:
            raise StoreIntegrityError("head record unreadable") from exc
        # count == h_count + 1 tolerates a crash between append and head update.
        if count not in (h_count, h_count + 1) or h_count >= len(hashes) or hashes[h_count] != h_hash:
            raise StoreIntegrityError("store does not match head record (truncated or rewritten)")

    def verify(self) -> None:
        """Verify the whole store; raises StoreIntegrityError on any tampering."""
        self._load()

    def append(self, event: dict[str, Any]) -> None:
        with self._lock():
            events, last = self._load()  # refuse to extend a broken chain
            line = json.dumps({**event, "prev": last}, ensure_ascii=False, sort_keys=True)
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(fd, (line + "\n").encode("utf-8"))
                os.fsync(fd)
            finally:
                os.close(fd)
            tmp = self.head_path.with_name(self.head_path.name + ".tmp")
            tmp.write_text(json.dumps({"count": len(events) + 1, "hash": _sha256(line)}), encoding="utf-8")
            os.replace(tmp, self.head_path)

    def events(self) -> list[dict[str, Any]]:
        return self._load()[0]

    def fold(self, key: bytes | None = None) -> dict[str, dict[str, Any]]:
        """Fold the verified log into the state of every request.

        - tool/args/args_sha256 are pinned from the FIRST `pending` event for
          a request id; later events can never replace them.
        - Transitions are a state machine: pending -> approved|denied,
          approved -> sent|failed. Anything else is ignored (no resurrecting a
          sent or denied request by re-appending an old event).
        - With `key`, approved/denied events whose HMAC is invalid do not
          transition; approvals counted in `bad_decisions`.
        Audit events share the log but never move state.
        """
        states: dict[str, dict[str, Any]] = {}
        for event in self.events():
            rid = event.get("request_id")
            typ = str(event.get("type", ""))
            if not isinstance(rid, str) or typ.startswith("audit:"):
                continue
            state = states.get(rid)
            if typ == "pending":
                if state is None:
                    states[rid] = {
                        "request_id": rid,
                        "tool": event.get("tool", ""),
                        "args": event.get("args", {}),
                        "args_sha256": event.get("args_sha256", ""),
                        "created_at": event.get("created_at"),
                        "last_event": "pending",
                        "bad_decisions": 0,
                    }
                continue
            if state is None:
                continue
            last = state["last_event"]
            if typ in ("approved", "denied") and last == "pending":
                if key is not None and not _decision_valid(key, event, typ):
                    state["bad_decisions"] += 1
                    continue
                state["last_event"] = typ
                state["decision"] = event
            elif typ in ("sent", "failed") and last == "approved":
                state["last_event"] = typ
        return states

    def request_state(self, request_id: str, key: bytes | None = None) -> dict[str, Any] | None:
        return self.fold(key).get(request_id)


@dataclass
class SendGate:
    manifest: dict[str, str]  # tool name -> tier
    executors: dict[str, Callable[..., Any]]
    store: ApprovalStore
    audit: ApprovalStore | None = None
    approval_ttl: float = DEFAULT_APPROVAL_TTL
    _clock: Callable[[], float] = field(default=time.time)
    audit_failures: int = 0  # audit writes that failed; see _audit

    # -- construction -----------------------------------------------------

    @classmethod
    def from_files(
        cls,
        manifest_path: str | Path,
        executors: dict[str, Callable[..., Any]],
        store_path: str | Path,
        audit_path: str | Path | None = None,
        approval_ttl: float = DEFAULT_APPROVAL_TTL,
    ) -> SendGate:
        try:
            raw = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
            manifest = {name: spec["tier"] for name, spec in raw["tools"].items()}
        except Exception as exc:  # missing/corrupt manifest -> deny all
            raise GateError(f"manifest unavailable or invalid: {exc}") from exc
        for name, tier in manifest.items():
            if tier not in TIERS:
                raise GateError(f"tool {name!r} declares unknown tier {tier!r}")
        store = ApprovalStore(Path(store_path))
        audit = ApprovalStore(Path(audit_path)) if audit_path else store
        return cls(manifest=manifest, executors=executors, store=store, audit=audit, approval_ttl=approval_ttl)

    # -- agent side -------------------------------------------------------

    def call(self, tool: str, **kwargs: Any) -> GateResult:
        tier = self.manifest.get(tool)
        if tier is None:
            self._audit("denied_unknown_tool", tool=tool)
            return GateResult("denied", tool, f"tool {tool!r} is not declared in the manifest")
        if tier in ("read", "draft"):
            try:
                value = self._execute(tool, kwargs)
            except Exception as exc:
                error = _describe(exc)
                self._audit("failed", tool=tool, tier=tier, error=error)
                return GateResult("failed", tool, f"tier={tier} executor failed: {error}")
            self._audit("executed", tool=tool, tier=tier)
            return GateResult("executed", tool, f"tier={tier}", value=value)
        # tier == send: never execute here. Record and hand back a receipt.
        request_id = uuid.uuid4().hex[:12]
        args_json = json.dumps(kwargs, ensure_ascii=False, sort_keys=True, default=str)
        digest = _sha256(args_json)
        try:
            for st in self.store.fold().values():
                if st["last_event"] == "denied" and st["tool"] == tool and st["args_sha256"] == digest:
                    self._audit("denied_repeat_after_denial", tool=tool, request_id=st["request_id"])
                    return GateResult(
                        "denied",
                        tool,
                        "an identical request was already denied; change the arguments to re-request",
                        request_id=st["request_id"],
                    )
            event = {
                "type": "pending",
                "request_id": request_id,
                "tool": tool,
                "args": json.loads(args_json),
                "args_sha256": digest,
                "created_at": self._clock(),
            }
            self.store.append(event)
        except Exception as exc:
            self._audit("store_unavailable", tool=tool)
            return GateResult("denied", tool, f"approval store unavailable: {exc}")
        self._audit("blocked_pending", tool=tool, request_id=request_id)
        return GateResult(
            "pending",
            tool,
            "send blocked: recorded as a pending approval request; nothing was sent",
            request_id=request_id,
        )

    # -- human side -------------------------------------------------------

    def approve(self, request_id: str, approver: str) -> dict[str, Any]:
        return self._decide(request_id, approver, "approved")

    def deny(self, request_id: str, approver: str) -> dict[str, Any]:
        return self._decide(request_id, approver, "denied")

    def _decide(self, request_id: str, approver: str, decision: str) -> dict[str, Any]:
        key = approver_key()
        if key is None:
            raise GateError(f"{KEY_ENV} is not set; only the approver side may decide")
        with self._decision_lock():
            state = self._require_pending(request_id, key)
            if args_digest(state["args"]) != state["args_sha256"]:
                self._audit("denied_args_tampered", request_id=request_id, phase=decision)
                raise GateError(f"request {request_id} args do not match their recorded hash")
            at = self._clock()
            self.store.append(
                {
                    "type": decision,
                    "request_id": request_id,
                    "by": approver,
                    "at": at,
                    "args_sha256": state["args_sha256"],
                    "signature": sign_decision(key, request_id, state["args_sha256"], decision, at),
                }
            )
        self._audit(decision, request_id=request_id, by=approver)
        return state

    def execute_approved(self, request_id: str) -> GateResult:
        key = approver_key()
        try:
            lock = self._decision_lock()
            lock.__enter__()
        except Exception as exc:
            return GateResult("denied", "", f"execution lock unavailable: {exc}")
        try:
            return self._execute_locked(request_id, key)
        finally:
            lock.__exit__(None, None, None)

    def _execute_locked(self, request_id: str, key: bytes | None) -> GateResult:
        try:
            state = self.store.request_state(request_id, key)
        except Exception as exc:
            self._audit("store_unavailable", request_id=request_id)
            return GateResult("denied", "", f"approval store unavailable: {exc}")
        if state is None:
            return GateResult("denied", "", f"no such request: {request_id}")
        tool = str(state.get("tool", ""))
        last = state["last_event"]
        if last == "sent":
            self._audit("denied_replay", tool=tool, request_id=request_id)
            return GateResult("denied", tool, "already executed; approvals are single-use")
        if last != "approved":
            if state["bad_decisions"]:
                self._audit("denied_bad_signature", tool=tool, request_id=request_id)
            return GateResult("denied", tool, f"request is {last}, not approved")
        if key is None:  # unreachable via fold(key), kept as a fail-closed guard
            return GateResult("denied", tool, f"{KEY_ENV} is not set")
        approval = state["decision"]
        if self.manifest.get(tool) != "send":
            self._audit("denied_manifest", tool=tool, request_id=request_id)
            return GateResult("denied", tool, f"tool {tool!r} is not a declared send-tier tool")
        args = state["args"]
        if (
            not isinstance(args, dict)
            or not hmac.compare_digest(args_digest(args), str(state["args_sha256"]))
            or not hmac.compare_digest(str(approval["args_sha256"]), str(state["args_sha256"]))
        ):
            self._audit("denied_args_tampered", tool=tool, request_id=request_id)
            return GateResult("denied", tool, "arguments do not match the approved hash; approval void")
        if self._clock() - float(approval["at"]) > self.approval_ttl:
            self._audit("denied_expired", tool=tool, request_id=request_id)
            return GateResult("denied", tool, "approval expired")
        try:
            value = self._execute(tool, args)
        except Exception as exc:
            # The approval is spent: it may have partly gone out, so it must
            # never be replayed automatically. A retry is a new request.
            error = _describe(exc)
            try:
                self.store.append({"type": "failed", "request_id": request_id, "at": self._clock(), "error": error})
            except Exception as store_exc:
                self._audit("failed", tool=tool, request_id=request_id, error=error, recorded=False)
                return GateResult(
                    "failed",
                    tool,
                    f"executor failed ({error}) and the failure could not be recorded: {store_exc}",
                    request_id=request_id,
                )
            self._audit("failed", tool=tool, request_id=request_id, error=error)
            return GateResult(
                "failed",
                tool,
                f"executor failed: {error}; approval consumed, re-request to retry",
                request_id=request_id,
            )
        self.store.append({"type": "sent", "request_id": request_id, "at": self._clock()})
        self._audit("sent", tool=tool, request_id=request_id)
        return GateResult("executed", tool, "approved send executed", request_id=request_id, value=value)

    def pending(self) -> list[dict[str, Any]]:
        states = self.store.fold(approver_key())
        return [s for s in states.values() if s["last_event"] == "pending"]

    # -- internals --------------------------------------------------------

    def _decision_lock(self) -> Any:
        return _file_lock(self.store.path.with_name(self.store.path.name + ".exec.lock"))

    def _require_pending(self, request_id: str, key: bytes | None = None) -> dict[str, Any]:
        try:
            state = self.store.request_state(request_id, key)
        except Exception as exc:
            raise GateError(f"approval store unavailable: {exc}") from exc
        if state is None:
            raise GateError(f"no such request: {request_id}")
        if state["last_event"] != "pending":
            raise GateError(f"request {request_id} is {state['last_event']}, not pending")
        return state

    def _execute(self, tool: str, kwargs: dict[str, Any]) -> Any:
        fn = self.executors.get(tool)
        if fn is None:
            raise GateError(f"no executor registered for declared tool {tool!r}")
        return fn(**kwargs)

    def _audit(self, type_: str, **fields: Any) -> None:
        sink = self.audit or self.store
        try:
            sink.append({"type": f"audit:{type_}", "at": self._clock(), **fields})
        except Exception as exc:
            # Never let an audit failure change a decision, but never hide it.
            self.audit_failures += 1
            log.error("audit write failed for audit:%s (%s): %s", type_, fields, _describe(exc))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="send_gate", description="Human side of the send gate")
    parser.add_argument("--store", required=True, help="path to the approval store (JSON lines)")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="list pending approval requests")
    sub.add_parser("verify", help="verify the store's hash chain (exit 1 if tampered)")
    for name in ("approve", "deny"):
        p = sub.add_parser(name)
        p.add_argument("request_id")
        p.add_argument("--by", required=True, help="who is deciding (recorded in the audit log)")
    args = parser.parse_args(argv)

    gate = SendGate(manifest={}, executors={}, store=ApprovalStore(Path(args.store)))
    if args.cmd == "verify":
        try:
            gate.store.verify()
        except GateError as exc:
            print(f"store INVALID: {exc}", file=sys.stderr)
            return 1
        print("store ok")
        return 0
    if args.cmd == "list":
        try:
            for state in gate.pending():
                shown = json.dumps(state.get("args", {}), ensure_ascii=False)
                print(f"{state['request_id']}  {state['tool']}  args={shown}")
        except GateError as exc:
            print(f"refused: {exc}", file=sys.stderr)
            return 1
        return 0
    try:
        if args.cmd == "approve":
            gate.approve(args.request_id, args.by)
            print(f"approved {args.request_id} by {args.by}")
        else:
            gate.deny(args.request_id, args.by)
            print(f"denied {args.request_id} by {args.by}")
    except GateError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
