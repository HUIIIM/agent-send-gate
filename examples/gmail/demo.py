"""Runnable demo: an agent with Gmail-like tools behind the send gate.

    python examples/gmail/demo.py agent     # the agent works; its send is blocked
    python -m gate.send_gate --store demo_store.jsonl list
    python -m gate.send_gate --store demo_store.jsonl approve <id> --by you
    python examples/gmail/demo.py execute <id>   # the approved send runs, once

The "Gmail API" here is a fake that prints what it would do. Swap the
three executor functions for a real MCP client and nothing else changes:
the gate never learns the difference.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from gate import SendGate  # noqa: E402

HERE = Path(__file__).resolve().parent
STORE = HERE / "demo_store.jsonl"


# -- fake executors: in production these call the real tools -------------

def search(query: str) -> str:
    return f"3 messages match {query!r}: invoice #1042, invoice #1043, receipt"


def create_draft(to: str, subject: str, body: str) -> str:
    return f"draft saved for {to} with subject {subject!r}"


def send_message(to: str, subject: str, body: str) -> str:
    return f"SENT to {to}: {subject!r}"


EXECUTORS = {
    "gmail.search": search,
    "gmail.create_draft": create_draft,
    "gmail.send_message": send_message,
}


def make_gate() -> SendGate:
    return SendGate.from_files(HERE / "permissions.json", EXECUTORS, STORE)


def agent_side() -> None:
    gate = make_gate()
    print("agent: searching the mailbox (tier=read)")
    print("  ->", gate.call("gmail.search", query="invoice").value)

    print("agent: preparing a draft (tier=draft)")
    print(
        "  ->",
        gate.call(
            "gmail.create_draft",
            to="client@example.com",
            subject="Invoice #1042",
            body="Hi, attaching invoice #1042 as discussed.",
        ).value,
    )

    print("agent: trying to send the email itself (tier=send)")
    result = gate.call(
        "gmail.send_message",
        to="client@example.com",
        subject="Invoice #1042",
        body="Hi, attaching invoice #1042 as discussed.",
    )
    print(f"  -> [{result.status}] {result.detail}")
    print(f"  -> approval request id: {result.request_id}")
    print()
    print("Nothing was sent. Review the queue and decide as a human:")
    print(f"  python -m gate.send_gate --store {STORE.name} list")
    print(f"  python -m gate.send_gate --store {STORE.name} approve {result.request_id} --by you")
    print(f"  python examples/gmail/demo.py execute {result.request_id}")


def execute_side(request_id: str) -> None:
    gate = make_gate()
    result = gate.execute_approved(request_id)
    print(f"[{result.status}] {result.detail}")
    if result.value:
        print("  ->", result.value)


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "execute" and len(sys.argv) == 3:
        execute_side(sys.argv[2])
    else:
        agent_side()
