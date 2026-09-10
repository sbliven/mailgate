# Hardening: what the code cannot do for itself

Two of mailgate's controls are only as strong as the deployment around them, and
both reviewers said so. This file is the honest list.

## 1. Same-user separation is a speed bump, not a boundary

By default the agent and mailgate run as the same OS user. That user can, in
principle, write to the approval socket, edit the policy file, rewrite the audit
log, and read the state DB. Every in-process control assumes an agent that is
*misled*, not one that is *executing arbitrary code as Spencer*.

To make the approval gate a real boundary:

```ini
# /etc/systemd/system/mailgate.service
[Service]
User=mailgate
Group=mailgate
# the agent gets only the stdio pipe
StandardInput=socket
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
NoNewPrivileges=yes
ReadWritePaths=/var/lib/mailgate
Environment=XDG_RUNTIME_DIR=/run/mailgate
```

Then the audit log and state DB are owned by `mailgate` and unwritable by the
agent, and the approval socket can be group-restricted so only Spencer's session
and the server share it.

## 2. Policy pinning requires a digest the agent cannot edit

Under stdio transport, the MCP client — the agent's own process tree — spawns
mailgate, so it controls both the config file and the environment. An env-var pin
pins nothing. mailgate therefore reports `UNPINNED` unless the digest comes from a
root-owned file:

```sh
sudo install -d -m 755 /etc/mailgate
mailgate doctor --policy ~/.config/mailgate/policy.toml   # prints the digest
sudo sh -c 'echo <digest> > /etc/mailgate/policy.sha78'   # root-owned
```

`mailgate doctor` prints the digest in exactly the form this file needs, so a
one-line policy edit does not become a reason to stop pinning.

## 3. Egress confinement

`backends/httpgate.py` allowlists `(method, host, path)` for every provider call,
which turns an unintended verb into a hard error. It is not confinement: a
dependency can open its own socket. For `auto` mode on a real mailbox, put the
service in a network namespace that can reach only the provider hosts:

```sh
# nftables sketch, applied inside the mailgate netns
table inet mailgate {
  chain output {
    type filter hook output priority 0; policy drop;
    ip daddr @provider_hosts tcp dport 443 accept
    ct state established,related accept
  }
}
```

An IMAP-only deployment should also block port 25/465/587 outright: an app
password usually unlocks SMTP even though mailgate never imports `smtplib`.

## 4. Credential confinement, per provider

- **Microsoft 365** — withhold `Mail.Send` and sending is impossible at the token
  level. Request `Mail.ReadWrite` + `MailboxFolder.Read`; never
  `Mail.ReadWrite.All`. Delete-prevention is still application-level.
- **Gmail** — the token mailgate needs is send-capable on the documented path
  (`gmail.modify` = "read, compose and send"), and `gmail.labels` alone cannot
  label a message. So: a dedicated Google Cloud project with only the Gmail API
  enabled, the OAuth consent screen restricted to Spencer's own account, the
  refresh token in his secret manager, and `mailgate auth` recording which scope
  was actually granted. Probe `gmail.modify.restricted` first — it appears in the
  method reference but not the scope overview, so treat its existence as
  unconfirmed.
- **IMAP** — no scoping exists. Use a dedicated app password, and if the provider
  supports per-password capability limits, disable SMTP on it.

## 5. Order of enablement on a real mailbox

1. `mode = "dry_run"` against a **throwaway account** with a couple of test
   messages. Read the audit log; confirm `prior`/`post` look right.
2. `mode = "training"` on the same throwaway account. Approve and reject a few, and
   run `mailgate undo` on one of each.
3. `mode = "dry_run"` against the real mailbox, with `move_allowlist` containing
   exactly one non-critical folder.
4. `mode = "training"` on the real mailbox. Stay here until the approval prompts
   have stopped surprising you.
5. Only then `supervised`, and only then `auto` — and only with §1, §2 and §3 in
   place. Re-run `mailgate doctor` first: it re-checks every destination for
   retention policies, server-side rules and shared-namespace membership.
