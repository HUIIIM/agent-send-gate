<h1 align="center">agent-send-gate</h1>

<p align="center"><strong>Agents draft. Humans send.</strong><br/>
A permission-tier template that physically blocks every outbound send from your agent's tools until a human approves it.</p>

<p align="center">Works with any MCP server or agent tool layer. The gate sits between the agent and the tool, so it does not live inside any one product.</p>

<p align="center">
<img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-green"/>
<img alt="Python 3.10+" src="https://img.shields.io/badge/python-3.10%2B-blue"/>
<img alt="Dependencies: none" src="https://img.shields.io/badge/dependencies-none-brightgreen"/>
<img alt="Tests" src="https://img.shields.io/badge/tests-10%20passing-brightgreen"/>
</p>

---

Most agent setups hand the model a mailbox, a posting API, or a messaging account and rely on the prompt to keep it polite. Prompts fail quietly. This template takes the opposite approach: **capability, not instructions.** Every tool is declared at one of three tiers, and the `send` tier cannot execute on the agent's word alone. It is recorded, queued, and stopped, until a human approves that exact request out of band.

Here is the reference implementation doing exactly that (real output from `examples/gmail/demo.py`):

```
agent: searching the mailbox (tier=read)
  -> 3 messages match 'invoice': invoice #1042, invoice #1043, receipt
agent: preparing a draft (tier=draft)
  -> draft saved for client@example.com with subject 'Invoice #1042'
agent: trying to send the email itself (tier=send)
  -> [pending] send blocked: recorded as a pending approval request; nothing was sent
```

The human side is three commands:

```
$ python -m gate.send_gate --store demo_store.jsonl list
f5a6849a7aa8  gmail.send_message  args={"body": "Hi, attaching invoice #1042 ...", "subject": "Invoice #1042", "to": "client@example.com"}

$ python -m gate.send_gate --store demo_store.jsonl approve f5a6849a7aa8 --by you
approved f5a6849a7aa8 by you

$ python examples/gmail/demo.py execute f5a6849a7aa8
[executed] approved send executed
  -> SENT to client@example.com: 'Invoice #1042'
```

Approvals are single-use. Running the same execute again answers `[denied] already executed; approvals are single-use`.

## Quick start

```
git clone https://github.com/HUIIIM/agent-send-gate
cd agent-send-gate
python examples/gmail/demo.py          # watch a send get blocked
python -m pytest tests/ -q             # 10 tests, all of the gate's promises
```

No dependencies. Python 3.10+, standard library only.

## The tier model

| Tier | Meaning | Gate behavior |
|---|---|---|
| `read` | Look, search, fetch | Executes immediately |
| `draft` | Prepare content that stays inside the system | Executes immediately |
| `send` | Leaves the system, or commits you in front of another person | **Blocked.** Queued for human approval; executes only after approval, exactly once |

Two rules do most of the work:

1. **Tier follows effect, not the tool's name.** A `reply` or `share` that transmits is a send. A `delete` that only marks a draft is a draft. When a tool mixes effects, split it or tier it at its most dangerous effect.
2. **Undeclared means denied.** A tool missing from the manifest does not get a default tier, a warning, or a second chance. It is denied and logged. A missing or corrupt manifest denies everything.

## What's in the pack

```
schema/tool-permissions.schema.json   JSON Schema for the manifest: declare every tool, once
gate/send_gate.py                     The gate itself (reference implementation, ~250 lines)
examples/gmail/permissions.json       A mail toolset declared at honest tiers
examples/gmail/demo.py                The runnable story above, with fake executors
examples/gmail/README.md              How to wire this to a real MCP server
CHECKLIST.md                          A self-audit checklist for any agent setup
tests/test_send_gate.py               Every promise above, as an executable test
```

## How it works

- The agent calls tools only through the gate. `read` and `draft` pass through. `send` is converted into a pending approval request (tool, exact arguments, and a hash of them) appended to a JSON-lines store, and the agent receives a receipt instead of a result.
- A human reviews the queue on a surface the agent cannot write to (this CLI, or your own UI over the same store), and appends an approval or a denial.
- A separate executor step runs an approved request once. The arguments that execute are the arguments that were approved; the approval is consumed by executing.
- Every step appends to an audit log the agent cannot rewrite: `blocked_pending`, `approved`, `denied`, `sent`, plus every refusal. If the store is unavailable or corrupt, sends stop. Refusal is the default in every failure mode.

## Limits

What this template deliberately does not do:

- **It only governs tools routed through it.** If the agent also holds a direct credential for the same account, it can walk around the gate. The checklist covers this: the agent must not hold send-capable credentials at all.
- **It is not a sandbox.** It governs outbound sends, not code execution, file access, or what the agent reads. Pair it with your own controls for those.
- **Approval quality is on the human.** The gate guarantees a human sees the real recipient and content before anything leaves. It cannot make them read it.
- **The reference store is a file.** Single-process JSON lines are for clarity and small setups. The rules are the product; move them onto your database and UI without changing them.

## License

MIT. Copyright (c) 2026 Jiahui Miao. See [LICENSE](LICENSE).
