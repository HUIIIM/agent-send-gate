# agent-send-gate

agent-send-gate (W43): a send-gate for agent-originated outbound messages
— checks an outbound send against policy before it leaves. Public, MIT.

## How work happens here

- Direction arrives in-repo: GitHub Issues labeled `jarvis-task`, PR
  review comments, and `CLAUDE.md` / `LOOP.md`. Read both at session start.
- External Claude works on `claude/*` branches and opens PRs; it never
  merges its own PRs. Jarvis reviews and merges.
- Review verdicts exist only as PR comments.

## Working rules

- The gate's own test suite is the contract: behavior changes arrive with
  test changes in the same PR.
- No real outbound sends in tests; the gate is exercised against fixtures
  only.
