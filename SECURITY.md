# Security

## Reporting

Please report a suspected vulnerability privately, via GitHub's "Report a
vulnerability" on the Security tab, rather than opening a public issue.

## What is and is not guaranteed

mailgate exists to give an agent read-and-organise access to a mailbox with no send
and no delete capability. It is worth being precise about where that comes from,
because two of the three layers are not mailgate's code.

**Enforced by mailgate.** The six-tool surface; destination checks against the
provider's own special-use attributes; move and label allowlists resolved to
provider ids at startup; the provider-reserved label denylist; the outbound request
chokepoint; per-hour and per-day budgets; the approval gate; the hash-chained audit
log.

**Enforced by the provider.** Very little. No provider offers a scope meaning "may
file mail, may not delete it". Withholding `Mail.Send` on Microsoft Graph blocks
sending at the token level; that is the only provider-level guarantee available.
On Gmail, the token needed to label a message is documented as also permitting
sending. On IMAP there is no scoping at all.

**Enforced by the deployment, and not otherwise true.** Whether the agent can bypass
everything above by writing to mailgate's own policy file, audit log or approval
channel. By default they run as the same OS user, and same-user separation is a
speed bump rather than a boundary. `docs/HARDENING.md` describes what to do about
it. `mailgate doctor` reports the current state on every run, including whether the
policy digest is actually pinned.

## Threat model

The two adversaries assumed throughout are (a) anyone who can send Spencer an email,
and therefore controls message bodies, subjects, sender names and MIME structure,
and (b) a fully prompt-injected agent that will call any tool with any arguments in
any order. `docs/REVIEW.md` records two independent adversarial reviews against that
model and what changed as a result.

Notably **not** assumed: an attacker executing arbitrary code as the user running
mailgate. Against that, only the deployment hardening helps.

## Live providers

The Gmail, Microsoft Graph and IMAP adapters have never been run against a real
account. They refuse to construct unless both `live = true` and
`--enable-live-providers` are set. Follow the enablement order in
`docs/HARDENING.md`: throwaway account, `dry_run`, `training`, then a real mailbox.
