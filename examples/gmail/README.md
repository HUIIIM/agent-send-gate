# Example: a Gmail-style MCP toolset behind the gate

`permissions.json` declares seven tools from a typical mail MCP server at
the tier their *effect* deserves:

| Tool | Tier | Why |
|---|---|---|
| `gmail.search` | read | Looks, sends nothing |
| `gmail.read_message` | read | Looks, sends nothing |
| `gmail.create_draft` | draft | Content stays inside the account |
| `gmail.update_draft` | draft | Same containment |
| `gmail.send_message` | send | Irreversible, seen by another person |
| `gmail.reply` | send | A reply is a send with a friendlier name |
| `gmail.forward` | send | Moves content to a new audience |

`demo.py` wires three of them to fake executors and runs the whole story:
the agent searches and drafts freely, its attempt to send is blocked and
queued, a human approves out of band, and only then does the send execute
(exactly once).

To adapt this to a real MCP server:

1. List every tool your server exposes in `permissions.json`. If you are
   tempted to skip one, that is the one that matters.
2. Point each executor at your MCP client call. The gate does not care
   what the transport is.
3. Remove any direct send credential from the agent's environment. The
   only process that can execute an approved send is the one holding the
   credential, and it should not be the agent.
4. Put the approval step wherever your human already is: the CLI in this
   repo, a chat button, a web page. The store is plain JSON lines, so any
   UI can read the queue and append decisions.
