# mailgate

A deliberately restricted, fully audited MCP server that gives a locally-running
agent **read and organise** access to Gmail, Microsoft 365 and IMAP mailboxes.

It has no send capability and no delete capability — not as a permission setting,
but because the verbs are absent from the tool surface, absent from the adapters,
and blocked at a request chokepoint. What it *does* have is a human approval gate
that mailgate itself carries out, and a hash-chained audit log of every action and
every refusal.

**No real email account has been contacted.** The three provider adapters are
written and reviewed but disabled: they refuse to construct unless both `live=true`
and `--enable-live-providers` are set, and Spencer has not approved live testing.
The default and only enabled backend is a fixture mailbox.

## The six tools, and nothing else

| Tool | Kind |
|---|---|
| `list_accounts` | read |
| `list_folders` | read |
| `list_messages` | read — envelope metadata only, never a body |
| `get_message` | read — sanitised plaintext, fenced, size-capped |
| `apply_labels` | mutate — allowlisted labels only, add *and* remove |
| `move_message` | mutate — allowlisted destinations only |

Deliberately absent: delete, trash, expunge, send, reply, forward, draft, create
folder, create label, set mode, reload config, undo, and any raw passthrough.

## Quick start (fixture mailbox, nothing real)

```sh
pip install -e '.[dev]'

# mailgate refuses to read a policy file that others could write, and a freshly
# cloned file is 0644. This is deliberate; chmod it once.
chmod 600 examples/policy.fixture.toml

mailgate doctor --policy examples/policy.fixture.toml     # policy, chain, destinations
python -m pytest -q                                        # 113 tests, no network

# run the server for an agent
mailgate-server --policy examples/policy.fixture.toml
# in another terminal, approve what it asks for
mailgate approve
```

Note that the fixture mailbox lives in memory, so each new process starts from the
same seeded state. That is why `mailgate undo` on a fixture move from an *earlier*
process reports a divergence and refuses — the guard working correctly, on a
mailbox that reset underneath it. Against a real provider the state persists.

The agent-facing skill is `skill/SKILL.md`. Point your local agent at it and at the
server above.

## Read these three files before enabling anything real

- **`docs/PLAN.md`** — the design, and the part that shapes everything else:
  "no deletion" is worthless if a *move* or a *label* can destroy mail, which on
  every one of the three providers it can.
- **`docs/REVIEW.md`** — two independent adversarial reviews of the plan and what
  changed as a result. Twelve findings were rated critical, meaning the first
  design was wrong rather than merely incomplete. Read this one even if you skip
  the others.
- **`docs/HARDENING.md`** — the two controls the code cannot strengthen on its own
  (same-user separation and policy pinning), plus the order in which to enable a
  real mailbox.

## The honest summary of what is guaranteed

Enforced by the provider: nothing on Gmail; on Microsoft 365, only that sending is
impossible, because `Mail.Send` is withheld. No provider offers a scope that means
"may file mail, may not delete it".

Enforced by mailgate: the tool surface, the destination attribute checks, the
allowlists, the reserved-label denylist, the request chokepoint, the budgets, the
approval gate, and the audit chain.

Enforced by the deployment: whether the agent can bypass all of the above by
writing to mailgate's own files. See `docs/HARDENING.md`. Same-user separation is a
speed bump, not a boundary, and `mailgate doctor` says so every time it runs.
