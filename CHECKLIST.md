# Send-gate self-audit checklist

Run this against any agent setup that can touch the outside world. Every
box should be checkable with evidence, not with intentions.

## Declare

- [ ] Every tool the agent can call is listed in a permissions manifest.
- [ ] Every tool has exactly one tier: `read`, `draft`, or `send`.
- [ ] Tier follows the tool's *effect*, not its name (a "reply" or "share"
      that transmits is `send`).
- [ ] Tools that mix effects (read + write in one call) are split, or
      tiered at their most dangerous effect.
- [ ] Undeclared tools are denied by default. There is no fallback tier.

## Separate

- [ ] The send path is physically separate from the draft path: different
      tool, different code path, no shared "just transmit it" helper the
      agent can reach.
- [ ] The agent holds no credentials that can send directly. If the agent
      can bypass the gate, the gate is decoration.
- [ ] The agent cannot approve its own requests, and cannot write to the
      approval store.
- [ ] Approval happens out of band (a human surface the agent cannot
      post to), not as a chat message the agent can fake or "interpret".

## Approve

- [ ] The reviewer sees the actual content and recipient, not a summary
      written by the agent.
- [ ] The reviewer sees the exact arguments that will execute (hash them;
      if the arguments change after approval, the approval is void).
- [ ] Approvals are single-use and expire. A stale approval is no approval.
- [ ] Denial is a real, easy option, and a denied request cannot be
      re-queued unchanged by the agent in a loop.

## Fail closed

- [ ] Missing or corrupt manifest: everything is denied.
- [ ] Approval store unavailable: sends stop; reads may continue only if
      their tier does not depend on the store.
- [ ] Unknown tool, unknown tier, malformed arguments: denied, logged,
      and the agent stops instead of shopping for another route.

## Audit

- [ ] Every blocked send, approval, denial, and execution appends an
      audit event with who/what/when.
- [ ] The audit log is append-only for the agent. The agent can read its
      own history but never rewrite it.
- [ ] You can answer, from the log alone: what did the agent try to send
      this week, who approved it, and what actually went out?
