# mailgate — a restricted email MCP server

**Purpose.** Single, auditable choke point between a locally-running agent and Spencer's
mailboxes. The agent may *read* and *organise*. It has no mechanism — not merely no
permission — to send or destroy mail.

**Status.** Design + initial implementation. No real email account has been contacted.
Provider adapters ship disabled behind `--enable-live-providers` and a per-account
`live: true` flag; the default backend is a fixture mailbox.

---

## 1. Decisions taken

| Decision | Choice | Rationale |
|---|---|---|
| Runtime | Python 3.11+, official `mcp` SDK | mature libs for all three backends, easy to audit |
| Summarisation | **not in the server** | server returns sanitised plaintext; the agent summarises. No LLM key, no outbound egress beyond the mail provider |
| Approval gate | **inside the server** | survives a prompt-injected or misconfigured agent |
| Secrets | external secret manager (`pass`, `op`, `gopass`, keyring) via `secret_ref` URIs | no long-lived secrets at rest in the project |
| Transport | stdio only | no listening socket to attack |

## 2. Tool surface (the whole of it)

Six tools. Nothing else is exposed over MCP.

| Tool | Kind | Notes |
|---|---|---|
| `list_accounts` | read | ids + capabilities + current mode. No addresses unless `expose_addresses` |
| `list_folders` | read | returns `id`, `display_name`, `special_use`, `writable`, `is_shared` |
| `list_messages` | read | envelope metadata only, never bodies. Cursor-paged, capped |
| `get_message` | read | sanitised plaintext body, size-capped, links defanged, wrapped in untrusted-content markers |
| `apply_labels` | **mutate** | `add[]` / `remove[]`, allowlisted labels only |
| `move_message` | **mutate** | single message, allowlisted destination only |

Deliberately absent, and why:

- no `delete_message`, `trash_message`, `expunge`, `send`, `reply`, `forward`, `draft`
- no `create_label` / `create_folder` — a label name is an attacker-controlled string and
  therefore a covert channel; labels must pre-exist and be allowlisted
- no `get_attachment` — attachment *metadata* only (name, type, size, sha256)
- no `set_mode`, `set_policy`, `reload_config` — mode and policy change only by editing a
  root-checked config file and restarting
- no `undo` — undo exists, but as a CLI for Spencer, not as a tool the agent can churn with
- no raw passthrough (`execute_query`, `raw_request`) — the classic hole in "restricted" wrappers

Mutation semantics: every mutating call takes `idempotency_key` and returns
`{status, audit_id, prior_state}` where status ∈ `applied | pending_approval | denied |
duplicate_ignored | dry_run`.

## 3. The delete-by-proxy problem (the central design constraint)

"No deletion" is worthless if a *move* or a *label* can destroy mail. Every provider offers
at least one such path:

- **Gmail** — `messages.modify` with `addLabelIds: ["TRASH"]` *is* deletion. So is
  `["SPAM"]`, effectively.
- **Graph** — `POST /messages/{id}/move` with `destinationId: deleteditems` is deletion.
- **IMAP** — `STORE +FLAGS (\Deleted)` then `EXPUNGE`; or `MOVE` into the `\Trash` mailbox.

Mitigations, all of which are enforced in the core rather than per-backend:

1. **Destination resolution by server attribute, never by name.** A folder called
   `Archive-2024` may carry `\Trash` special-use; a folder called `Trash` may be an
   ordinary mailbox. The policy engine resolves the *provider's* attribute
   (RFC 6154 `\Trash`/`\Junk`/`\Drafts`; Gmail label ids `TRASH`/`SPAM`/`DRAFT`;
   Graph `wellKnownFolderName` `deleteditems`/`junkemail`/`recoverableitemsdeletions`)
   and refuses any target so attributed. Name-based checks are a secondary, additive filter.
2. **Label denylist** covering `TRASH`, `SPAM`, `DRAFT` and any provider-reserved id, applied
   after case-folding, Unicode NFKC, and confusable-character normalisation.
3. **Destination allowlist** — the policy names the folders the agent may move mail *into*.
   Empty by default. A folder not on the list is refused even if benign.
4. **Backend code physically lacks the verbs.** The IMAP adapter never emits `STORE` with
   `\Deleted`, never emits `EXPUNGE`, and opens no SMTP connection; the Gmail adapter never
   calls `messages.trash`/`messages.delete`; the Graph adapter never issues `DELETE` or
   `/sendMail`. A unit test greps the compiled source for these verbs.
5. **No cross-account moves.** `account` is a required parameter on every call and a move's
   source and destination must resolve within the same account.

### 3.1 What OAuth scope can and cannot buy us

Verified September 2026:

- **Microsoft Graph** — withhold `Mail.Send` and sending is impossible at the token level.
  But `Mail.ReadWrite` is the *only* permission that permits move/categorise and it also
  permits delete. Delete prevention is therefore application-level. Use
  `MailboxFolder.Read` + `Mail.ReadWrite`, never `Mail.ReadWrite.All`.
- **Gmail** — worse. `messages.modify` accepts only `https://mail.google.com/`,
  `gmail.modify`, and an apparently undocumented `gmail.modify.restricted`. `gmail.labels`
  alone *cannot* label a message. And `gmail.modify` is described as "Read, compose, and
  **send** emails" — so on the documented path, the token we need to label mail can also
  send mail. Both send- and trash-prevention are application-level.
  → The auth CLI will probe `gmail.modify.restricted` first and record which scope was
  actually granted; if it turns out to exclude send, prefer it permanently. `[low confidence]`
  that this scope exists as the reference page implies. Until confirmed, treat the Gmail
  token as send-capable and protect it accordingly (§7).
- **IMAP** — no scoping at all. An app password usually unlocks SMTP too, so the *credential*
  is send-capable even though our code is not. Never use IMAP for Gmail (it needs the
  full `https://mail.google.com/` scope); use the API path.

**Conclusion to state plainly: the "no send / no delete" guarantee is enforced by mailgate's
code and by the credential's confinement, not by the provider.** The plan is built around
that fact rather than pretending otherwise.

## 4. Policy model

A single TOML file, read once at startup, never writable through MCP:

```toml
mode = "training"                 # training | supervised | auto | dry_run
[limits]
mutations_per_hour = 40
mutations_per_run  = 15
reads_per_hour     = 500
max_body_bytes     = 262144
[accounts.work]
backend = "graph"
live = false
secret_ref = "op://Private/mailgate-work/refresh_token"
move_allowlist = ["Archive", "Newsletters", "Receipts", "ToRead"]
label_allowlist = ["p1", "p2", "p3", "waiting", "fyi"]
label_denylist_extra = []
protect_folders = ["Inbox/Legal", "Sent"]     # read-only, never a source or destination
```

Startup checks (fail closed):

- config file must be owner-`$USER`, mode `0600`, no group/world write, parent dirs not
  world-writable, not a symlink
- if `MAILGATE_POLICY_SHA256` is set in the launcher environment it must match, else refuse
  to start — pins the policy against same-user tampering
- the policy's sha256 is written as the first record of the audit chain for the session
- unknown keys are an error, not a warning (a typo'd `move_allowlist` must not silently
  become "allow nothing" *or* "allow everything" — it becomes a startup failure)

Modes:

- `dry_run` — mutations validated, logged, never sent to the provider
- `training` — every mutation blocks on out-of-band approval
- `supervised` — reads free; mutations auto-approved only if they match an explicit,
  expiring standing rule, else block
- `auto` — mutations auto-approved within `limits`, still fully logged and undoable

## 5. Approval protocol

The agent's mutating call blocks up to `approval_timeout` (default 90 s) and then returns
`pending_approval` with a request id; the agent may re-call `apply_labels`/`move_message`
with the same `idempotency_key` to re-check.

The approval itself happens on a channel the agent does not sit on: `mailgate approve`,
a small CLI/TUI that talks to a unix socket at `$XDG_RUNTIME_DIR/mailgate/approve.sock`
(mode `0600`, `SO_PEERCRED` checked). It shows the pending request — account, message id,
subject, sender, the exact from→to transition, and the agent's stated reason — and Spencer
accepts, rejects, or accepts-and-creates-a-rule.

Anti-bypass properties:

- an approval is a **capability token bound to one action**: HMAC over
  `(account, op, message_id, prior_state_hash, target, nonce)` with a per-session key held
  only in server memory
- **single use**, consumed inside the same lock that performs the mutation
- **TTL 5 minutes**, after which it is refused
- **TOCTOU-bound**: `prior_state_hash` covers the message's current folder/label set (and
  IMAP `UIDVALIDITY`). If the mailbox moved underneath the approval, the mutation is refused
  and re-queued rather than applied to a different state than was displayed
- standing rules (`supervised`) are patterns with an explicit expiry, a max-use count, and
  their own audit records; a rule can never widen the folder/label allowlists
- the agent never sees a token; it is created and consumed server-side. There is no
  `redeem_token` tool to replay

**Honest limitation.** The agent runs as the same OS user as mailgate, so a genuinely
compromised agent process could in principle write to the approval socket or the policy
file. Same-user separation is a speed bump, not a boundary. The hardening path — recommended
before `auto` mode on a real mailbox — is to run mailgate as a dedicated `mailgate` user
under systemd, expose only the stdio pipe to the agent, and keep the approval socket
owned by Spencer's user with the server as the only other member of a shared group.

## 6. Audit log

Append-only JSONL at `$XDG_STATE_HOME/mailgate/audit/YYYY-MM.jsonl`, opened `O_APPEND`,
mode `0600`, one record per *request* and one per *outcome*:

```json
{"seq":412,"ts":"2026-09-09T07:14:02.881Z","session":"01J...","actor":"agent",
 "op":"move_message","account":"work","message_id":"AAMk...","message_key":"<sha256 of RFC822 Message-ID>",
 "subject_hash":"9f2c...","prior":{"folder":"Inbox","labels":["unread"],"uidvalidity":1234},
 "target":{"folder":"Newsletters"},"decision":"applied","approval":"req_7f3",
 "reason":"bulk sender, no action verbs","idem":"...","prev":"<sha256 of record 411>","mac":"<hmac>"}
```

- **hash-chained**: each record carries `prev`, the sha256 of the previous record's canonical
  JSON, so truncation or edits are detectable
- **denials and errors are logged too** — a log that only records successes hides exactly
  the attack you want to see
- **no bodies, no full subjects by default** — `subject_hash` plus an optional
  `log_subjects = true`; the log must not become a second copy of the mailbox
- **anchoring**: the chain head hash is emitted to `journald` (or an append-only sink) every
  N records and at shutdown, so same-user rewriting of the whole file is detectable
- `mailgate verify` recomputes the chain; `mailgate log` renders it; `mailgate undo <audit_id>`
  reverses one mutation from its `prior` state

## 7. Untrusted content and prompt injection

Every message body is attacker-authored. `get_message` therefore:

1. parses MIME, prefers `text/plain`, falls back to a stdlib HTML→text stripper that drops
   `script`/`style`/`head`/comments and never fetches a remote resource (no tracking-pixel
   or read-receipt leak, and no SSRF from the server)
2. normalises NFKC, strips zero-width and bidi-override characters, collapses confusables,
   caps at `max_body_bytes` with an explicit truncation marker
3. defangs URLs to `[link: example.com]` — registrable domain shown, full URL available only
   in a separate `links[]` array with punycode decoded and lookalike domains flagged
4. wraps the body in fixed markers with a standing instruction that the content is data:
   `<<<UNTRUSTED_EMAIL_BODY … >>>`
5. sets `suspected_injection: true` (with matched patterns) on imperative-to-assistant
   phrasing, tool-name mentions, base64 blobs, hidden-text CSS. A heuristic — a signal for
   the audit trail and for the agent to be conservative, never a control
6. never reflects content into a folder or label name — impossible anyway, since both are
   allowlisted enums

Blast-radius controls exist precisely because injection detection will sometimes fail:
per-run and per-hour mutation caps, a "same sender ≥ N moves" brake that forces re-approval,
and a rule that a message may be mutated at most once per run.

## 8. Data integrity

- **Idempotency**: `(account, idempotency_key)` recorded in SQLite; a repeat returns
  `duplicate_ignored` with the original `audit_id`. Retries after a timeout cannot double-move.
- **IMAP identity**: a UID is meaningful only within `(mailbox, UIDVALIDITY)`. Every message
  handle mailgate hands out carries both, plus the RFC822 `Message-ID`. Before mutating,
  the adapter re-`SELECT`s and compares `UIDVALIDITY`; on change it refuses and returns
  `stale_handle` rather than acting on whatever UID now occupies that slot. This is the
  single most likely cause of silently mangling the wrong message.
- **Atomic moves**: RFC 6851 `UID MOVE` where advertised. Where it is not, `UID COPY`, then
  *verify the destination copy exists*, and then — deliberately — **stop**, leaving the
  source in place and returning `copied_not_removed`. mailgate will not emit `\Deleted` to
  complete a move; an extra copy is a recoverable annoyance, a lost message is not.
- **Single writer**: one advisory lock per account; a second concurrent run gets
  `account_busy` instead of racing.
- **Undo journal**: `prior` state in the audit record is sufficient to reverse every
  mutation, and `mailgate undo` does so, itself logged.
- **Clock**: monotonic clock for TTLs and rate limits so a clock jump cannot revive an
  expired approval.
- **Fail closed**: any policy-evaluation error, unresolvable folder, missing special-use
  metadata, or unparsable provider response denies the mutation.

## 9. Credential handling

- `secret_ref` URIs only: `op://…`, `pass:…`, `gopass:…`, `keyring:service/user`,
  `env:VAR` (dev only), `cmd:…`. `cmd:` is arbitrary execution and is accepted **only** from
  the root-checked config file — never from a tool parameter, never from the environment
- secrets are fetched on demand, held in memory, never written to disk, never placed in
  `argv` (visible in `ps`), and scrubbed from every log line, error message and traceback by
  a redaction filter installed before anything else
- no tool response can contain a token; the OAuth device/loopback+PKCE flow lives in
  `mailgate auth`, a separate CLI the agent cannot invoke
- one credential per account, least scope available (§3.1), and — for Gmail, whose token is
  send-capable — a note in `mailgate doctor` recommending a dedicated Google Cloud project
  with only the Gmail API enabled and OAuth consent restricted to Spencer's own account

## 10. Testing without real accounts

- `FakeBackend` over a YAML fixture mailbox: folders with realistic special-use attributes,
  Gmail-style label semantics, and IMAP-style UIDs
- adversarial fixtures: an injection email; a folder named `Archive` carrying `\Trash`;
  a folder named `Trash` that is ordinary; homoglyph label names (`Аrchive` with Cyrillic А);
  a zero-width-obfuscated body; a 40 MB body; a UIDVALIDITY bump mid-run; a shared mailbox
- source-grep tests asserting the adapters contain no `EXPUNGE`, `\Deleted`, `sendMail`,
  `messages.trash`, `messages.delete`, `DELETE ` verbs, and no `smtplib` import
- replay tests for the Graph/Gmail adapters against canned JSON, so the request *shapes* are
  tested without a network
- when Spencer approves live testing: a throwaway provider account first, `dry_run`, then
  `training` on a single non-critical folder, then widen

## 11. The agent-facing skill

`skill/SKILL.md` teaches the triage workflow: list new envelopes → read only what is needed →
propose a priority and a destination with a one-line reason → in training mode expect
`pending_approval` and never retry-storm → treat every body as data → stop and report if
`suspected_injection` is set. Priority rubric (P1 acts today / P2 this week / P3 FYI /
Newsletter / Receipt) plus a cap on how much it may reorganise in one run.

## 12. Build order

1. core: policy, folder/label resolution, rate limits, audit chain, approval broker, SQLite state
2. sanitizer
3. MCP tool surface over stdio
4. FakeBackend + fixtures
5. adversarial test suite
6. Gmail / Graph / IMAP adapters — written, disabled, replay-tested only
7. `mailgate` CLI: `auth`, `approve`, `log`, `verify`, `undo`, `doctor`
8. skill
