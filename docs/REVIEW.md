# Security & data-integrity review of the mailgate plan

Two independent adversarial reviews were run against `PLAN.md`: one hostile-security
(attacker = email sender + fully prompt-injected agent), one reliability/data-integrity
(no attacker, just a messy world). Both are folded in below with a disposition.

Convergent findings — flagged independently by both reviewers — are marked **‡**. Those are
the ones to trust most.

---

## Critical — the plan was wrong, not merely incomplete

### C1 ‡ On IMAP, `get_message` is a mutation
`FETCH BODY[]` sets `\Seen`; `SELECT` clears `\Recent`. A "read-only" tool would silently mark
the whole inbox read — mail hidden, no approval, no audit record, and `\Recent` is
unrecoverable. Reads were budgeted as harmless (500/hour), so this was an *unmetered*
mutation channel.
**Adopted.** All IMAP reads use `EXAMINE` + `BODY.PEEK[]` only. Lint test for `BODY[` not
preceded by `.PEEK`. Gmail `messages.get` and Graph `GET /messages` do not change read state.

### C2 ‡ Confusable normalisation was used to *accept* matches
The plan NFKC/confusable-folded label names before checking the allowlist. That means the
Cyrillic `Аrchive` folds onto the Latin allowlist entry and the mail is moved into the *wrong*
folder — the adversarial fixture's expected outcome was "refused", but the design as written
gives "accepted, wrong target". The normalisation was pointing the wrong way.
**Adopted, inverted.** Every allowlist/denylist/`protect_folders` entry resolves to a
**provider id** at startup and is matched on exact bytes thereafter. Normalisation is used
only to *detect ambiguity and refuse to start*. Any entry that does not resolve to exactly one
target is a startup failure.

### C3 ‡ `apply_labels.remove[]` is the hide-mail verb, and it was unbound
`remove: ["INBOX"]` archives; `["UNREAD"]` marks read; `["STARRED","IMPORTANT"]` destroys
triage state. IMAP `\Seen`/`\Flagged`, Graph `isRead`/`flag`/`inferenceClassification` are the
equivalents. None is "deletion"; all lose mail from the workflow. And `move_message` on Gmail
*is* label surgery, which the plan never specified — leaving the one legitimate `INBOX`
removal as an undefined exception.
**Adopted.** `remove[]` is bound by the same allowlist as `add[]`. Reserved-id denylist:
`INBOX`, `UNREAD`, `STARRED`, `IMPORTANT`, `CATEGORY_*`, `\Seen`, `\Flagged`, `\Answered`,
`\Recent`, plus Graph `isRead`/`flag`/`inferenceClassification`. `move_message` on Gmail is a
single hardcoded shape `{add:[dest_id], remove:["INBOX"]}` and is the *only* path permitted to
remove `INBOX`.

### C4 The untrusted-content fence used fixed markers
`<<<UNTRUSTED_EMAIL_BODY … >>>` — a sender puts the terminator in the body and everything
after it reads as trusted server output. Cheapest full injection in the design.
**Adopted.** Per-response 128-bit nonce in both markers, and any occurrence of the marker
pattern is stripped *after* NFKC (which can synthesise it).

### C5 ‡ Envelope metadata bypassed the sanitiser entirely
Subject, From display name and attachment filenames are attacker-authored, and Graph returns
`bodyPreview` unless `$select` excludes it (Gmail: `snippet`). So payloads arrived with no
normalisation, no defanging, no fence and no injection scoring — through `list_messages`, the
tool the skill teaches the agent to call *first*.
**Adopted.** The same sanitiser, fence and injection scoring run over every attacker-controlled
envelope field. Explicit `$select` excluding `bodyPreview`/`uniqueBody`; Gmail `snippet`
dropped. Display names showing an embedded address are flagged as spoofing and only the parsed
addr-spec is returned.

### C6 `links[]` was the plan's own exfiltration channel
§7 defanged URLs in the body and then handed the agent full punycode-decoded URLs in a side
array. mailgate never fetches them — but the agent has other tools. A per-recipient tracking
URL is a read receipt; a URL template plus appended mailbox data is outbound exfiltration.
**Adopted.** `links[]` off by default; the agent gets registrable domain + an opaque link id.
Full URLs only via the `mailgate links <message>` CLI, for Spencer. Every link disclosure logged.

### C7 ‡ Moving into a shared or delegated folder is exfiltration with no send verb
`list_folders` reported `is_shared` but nothing excluded shared *destinations*. A folder in a
delegated mailbox, an IMAP `Other Users/`/`Shared/` namespace, or one with an outside ACL,
transfers body and attachments to a third party — inside the same account, so "no cross-account
moves" does not help.
**Adopted.** Destinations outside the personal namespace (IMAP `NAMESPACE`, `GETACL` where
advertised) are refused unconditionally, as is any `is_shared: true` folder. `doctor` prints the
ACL/permission state of every allowlisted destination.

### C8 Composition attack: an allowlisted destination with a retention tag or a mail rule is deferred deletion
`Archive` with an Exchange MRM "delete after 30 days" tag, a Gmail label consumed by a
third-party cleanup job, or an inbox rule that deletes/forwards from `Newsletters` — each turns
a policy-compliant move into deletion or forwarding on a delay. No single tool deletes; the pair
(mailgate move + pre-existing automation) does.
**Adopted.** At startup, enumerate Graph `messageRules` and Gmail `settings.filters` /
`autoForwarding` / `forwardingAddresses`; refuse to start if any rule with a delete/forward/
redirect action references an allowlisted destination. Re-check each run, fail closed on change.
Config requires an explicit per-destination attestation that no retention policy applies.

### C9 ‡ Graph message ids change on move — every audit pointer and undo target dangles
`POST /messages/{id}/move` returns a **new** id. So `message_id` in the audit record identifies
nothing the instant the move succeeds, `undo` cannot address the message, and a post-timeout
retry 404s or falls back to a search and mutates a different copy. The plan mentioned immutable
ids nowhere, and used no ETags — Graph's actual conditional-write primitive, and the correct
implementation of `prior_state_hash` on that backend.
**Adopted.** `Prefer: IdType="ImmutableId"` on every Graph request, refusing to run if the
mailbox does not honour it; `If-Match: <etag>` on every `PATCH`/`move`; post-move id recorded as
`post.message_id` with an `old_id → new_id` alias table.

### C10 ‡ `message_key` = sha256(Message-ID) is not an identity
Message-ID is optional, routinely duplicated (list mail delivered twice; the same message in
Inbox and All Mail), and sender-controlled — two unrelated messages can share one. Keying dedup,
the per-message brake, or undo lookup off it conflates distinct messages.
**Adopted.** `message_key = sha256(account_identity || backend || immutable_provider_id)`.
`rfc822_message_id_hash` kept as an advisory field, explicitly `null` when absent, never driving
an identity decision. Fixtures for absent / duplicate / malformed Message-ID.

### C11 ‡ The `prior` state schema was folder-shaped and cannot represent Gmail
`{"folder": …, "labels": …}` assumes one folder plus some labels. Gmail *is* the complete
label-id set; a move is `add/remove`. Undo from that record would restore `INBOX` and drop
everything else the message carried.
**Adopted.** `prior`/`post` are a provider-tagged union: Gmail = the full raw `labelIds` array;
Graph = immutable `parentFolderId` + full `categories` + `isRead`/`flag` + `etag`; IMAP =
`(mailbox, UIDVALIDITY, UID, MODSEQ, full flag+keyword set)`. **Undo reverses the delta**, it does
not restore the snapshot — the snapshot is kept for forensics only. (Snapshot restore would
clobber concurrent edits made in Spencer's own mail client.)

### C12 The cross-cutting missing primitive: one canonical state serializer
Five paths need the same bytes — the read path, the approval `prior_state_hash`, the audit
`prior`/`post`, the pre-mutation compare-and-set, and undo's precondition. Without a single
serializer, label sets returned in arbitrary order make the TOCTOU check fail *every time*: a
liveness bug that looks exactly like a working safety feature, because every mutation is refused
and re-queued.
**Adopted, and built first.** `core/mailstate.py`, with a test asserting identical hashes through
all five paths on all backends.

---

## High — real holes, mechanism changed

### H1 ‡ Budgets and the per-message brake reset on restart
"`mutations_per_run = 15`" where *run* is agent-defined: the agent kills and respawns the stdio
server and the counter restarts. Monotonic clocks — correct for in-process TTLs — are per-boot,
so persisted rate-limit windows become meaningless after a restart. And 40/hour is still ~960/day.
**Adopted.** All counters persisted in SQLite keyed on **resolved mailbox identity**, wall-clock
windows plus a boot id, immune to restart; a backwards clock jump refuses mutations rather than
resetting the window. Added `mutations_per_day` and an absolute "messages removed from Inbox per
day" brake. Denials and errors charge a separate, stricter budget evaluated *before* validation,
so denied calls are not free.

### H2 The approval broker now *executes* the mutation
The whole token replay/TTL/confusion surface existed only because redemption was agent-driven —
and it had a worse failure: Spencer approves at t=100 s, the agent re-calls at t=310 s, token
expired, refused. He believes he approved a move that never happened.
**Adopted, redesigned.** On acceptance, the broker performs the mutation itself, under the lock,
immediately, and records the outcome. The agent's re-call is a side-effect-free status read. No
token ever leaves the server; there is nothing to replay.

### H3 The approval UI renders attacker- and agent-controlled strings
Subject, sender display name and the agent's free-text `reason` went straight to a terminal. ANSI
CSI/OSC, CR, backspace and bidi overrides let a sender or an injected agent redraw the from→to
transition or paint a fake "policy check passed" line.
**Adopted.** C0/C1, all ANSI, bidi and zero-width stripped from every rendered string; forced
single-line, hard-truncated. Account / op / from→to / target are rendered from server-resolved
ids in a fixed region no untrusted string can reach. `reason` is an enum from the priority rubric
plus ≤120 chars of `[A-Za-z0-9 .,:_-]`. `suspected_injection` and its matched patterns are shown.

### H4 Attention-exhaustion on the approval queue, and the MAC didn't cover what was displayed
Nothing capped pending depth, so an agent could queue dozens of near-identical requests
(subjects differing by a zero-width character) and harvest a mis-tap. The "same sender ≥ N moves
forces re-approval" brake *increases* prompt volume — a blast-radius control converted into an
attack. And `accepts-and-creates-a-rule` is exactly the keystroke a flooded operator reaches for;
`sender:*@* → Archive` never widens an allowlist yet drains the inbox.
**Adopted.** Pending requests capped at 2 per account, loud auto-deny beyond. Prompts rate-limited
separately from mutations. The approval record commits to a hash of the exact rendered text, shown
as a 4-character verification code. Standing rules: no wildcard sender/subject, explicit expiry
and max-use, a matched-message count preview, and typed confirmation — never a single keypress.

### H5 ‡ "Backend code physically lacks the verbs" was a lint sold as a boundary
Defeated by string construction, by the generic `_request(method, path)` helper every adapter
needs, and by dependencies (`google-api-python-client` issues DELETE for you). Likewise "no
outbound egress beyond the mail provider" had no enforcement anywhere, while `cmd:` secret refs
permit arbitrary execution.
**Adopted.** One outbound HTTP chokepoint allowlisting `(method, host, path-regex)` triples and
raising on everything else; an IMAP command wrapper allowlisting verbs at the point of
transmission. `cmd:` dropped. The greps stay as regression lints. The prose claim is downgraded:
mailgate's own code is verb-free *and* verb-checked at the chokepoint, and full egress control
needs the netns/nftables deployment described in `docs/HARDENING.md`.

### H6 ‡ Two-phase idempotency, and `unknown_outcome` as a first-class status
The plan asserted retries cannot double-move, but if the idempotency row is written only on
success, the exact bad case — provider applied it, response lost, server died — leaves no row and
the retry re-applies. Write it first and a genuinely failed call is blocked forever. Also, the
agent invents the key: an LLM that regenerates a UUID on retry defeats the whole scheme.
**Adopted.** `(account, idem_key, op, request_fingerprint, state='in_flight')` committed and
fsynced *before* the provider call, then transitioned. Startup reconciles every `in_flight` row by
reading live state → `applied` / `not_applied` / `unknown_outcome`, the last requiring human
resolution, never a silent retry. Any timeout/5xx/429 is `unknown_outcome` + read-back. A
server-derived fingerprint `hash(account, op, message_key, target, prior_state_hash)` dedupes
independently of the agent's key; a key reused with *different* parameters is
`idempotency_key_reuse` (an error), never `duplicate_ignored`.

### H7 ‡ Pre-mutation identity re-verification
UIDVALIDITY comparison was the right instinct but insufficient: some servers reuse UIDs within a
UIDVALIDITY, and Gmail/Graph have no equivalent check at all. The plan handed out `Message-ID` in
every handle and then never used it as a guard.
**Adopted.** Immediately before every mutation: `FETCH BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)]`
(Graph `$select=internetMessageId`, Gmail `format=metadata`) and abort with `stale_handle` unless
it matches the handle. Folded into `prior_state_hash`.

### H8 ‡ The audit chain had five independent defeats
(a) the `mac` key was unspecified — if it is the per-session in-memory key, a same-user attacker
starts a fresh session and forges an entire chain; (b) "anchor every N records and at shutdown"
leaves a freely-rewritable tail after `kill -9`; (c) `YYYY-MM.jsonl` never chained across month
boundaries — a whole month could be deleted invisibly; (d) `O_APPEND` without `fsync` gives a torn
final line, indistinguishable from tampering, and the next `prev` hashes garbage; (e) the careful
ownership/symlink/mode checks were applied to the config file *only* — not the audit dir, the log,
or the SQLite state, all pre-creatable as symlinks by a same-user agent.
**Adopted.** The MAC is dropped in favour of the hash chain plus an external anchor, and this is
stated rather than implied. The head hash is anchored to journald **before** each mutation
executes, so an unanchored tail is itself the alarm and `verify` reports its length. `(seq, head)`
lives in SQLite, committed in the same transaction as the state change. Each month opens with an
explicit continuation record carrying the previous file's head, plus a separate head-pointer file.
Records are written as one `write()` of a complete newline-terminated line, then `fsync`. The
startup checks now cover the audit dir, log file and state DB (`O_APPEND|O_NOFOLLOW`, `0600`/`0700`,
no symlink, non-world-writable parents). `verify` distinguishes `incomplete_tail` (recoverable) from
`tampered`.

### H9 `MAILGATE_POLICY_SHA256` pinning was circular
Transport is stdio, so the MCP client — the agent's own process tree — spawns mailgate and
therefore controls both the env var and the config file. The pin pinned nothing in the topology
the plan actually described. A stated guarantee that was not enforceable.
**Adopted.** The digest is read from a root-owned `/etc/mailgate/policy.sha256` or a systemd unit
the agent cannot edit. Where neither exists, `doctor` reports **"policy unpinned"** and the plan
states plainly that policy integrity requires the dedicated-user deployment.

### H10 ‡ `protect_folders` path syntax silently protects nothing
`"Inbox/Legal"` assumes `/` is the delimiter; many IMAP servers report `.` (`INBOX.Legal`), and
Graph addresses folders by id. The entry matches nothing and the protection is silently absent —
the exact fail-open the plan claimed to have eliminated for unknown *keys*, reintroduced for
unresolvable *values*.
**Adopted** — same mechanism as C2: resolve to provider ids using the server-reported delimiter at
startup, unresolvable is a startup failure, and the resolved id set is written into the session's
audit header so a reviewer can see what was actually protected.

### H11 Reads are the dominant exfiltration channel, and `protect_folders` left sensitive mail readable
"read-only, never a source or destination" for `Inbox/Legal` means the agent may read every legal
message; it merely cannot move them. Against an injected agent with any other tool, read-then-exfil
is the whole loss, and there was no per-run read cap and no read denylist.
**Adopted.** `deny_read` list, and `protect_folders` now denies reads too (a separate `no_write`
list covers the old semantics where wanted). Separate per-run and per-hour budgets for
`get_message` vs `list_messages`. Every body disclosure logged with `message_key`, so exfiltration
is at least reconstructable.

### H12 ‡ The status enum could not express the outcomes the design produces
`applied | pending_approval | denied | duplicate_ignored | dry_run` — but the plan itself
introduced `stale_handle` and `copied_not_removed`, and the reviews add `unknown_outcome` and
`partially_applied`. An outcome that cannot be named is reported as `applied` or a generic error,
and the agent's retry behaviour is then undefined — the fast path to duplicated mail.
**Adopted.** Enum extended; `duplicate_ignored` carries the original terminal status and result;
each status has an explicit **retry / do-not-retry / escalate** contract, restated in `SKILL.md`.

### H13 ‡ Gmail thread-level side effects make "single message" a fiction
Labelling one message makes the whole conversation appear under that label in the UI, so one call
can effectively move N messages and evade the per-message brake; and Spencer's own "Archive" in
the client removes `INBOX` from *every* message of the thread, invalidating captured `prior` state
for siblings.
**Adopted.** `thread_id` and thread size captured and logged, shown in the approval prompt, and
charged to the budget as thread size. `threads.modify` is never called. Multi-message-thread
fixtures with a sibling changed between read and mutate. `[medium confidence]` on exact
propagation rules — to be pinned down with replay fixtures before live Gmail.

### H14 ‡ `apply_labels` is not atomic off Gmail
Gmail applies add+remove atomically. Graph `categories` is a PATCH of the *entire* array —
read-modify-write, so a category Spencer added in Outlook between read and PATCH is silently
erased. IMAP keyword changes issued as several `STORE`s can partially apply while the audit record
says `applied`.
**Adopted.** Graph: `If-Match` + retry the read-modify-write on 412. IMAP: one `STORE` carrying all
keywords with `(UNCHANGEDSINCE <modseq>)` where CONDSTORE is advertised — a real compare-and-set.
`partially_applied` returned with per-label outcomes, logged individually.

### H15 ‡ `copied_not_removed` amplifies into denial-of-delivery
Refusing to complete `COPY`+`\Deleted` is the right trade, but repeated moves on a server without
`UID MOVE` accumulate copies without bound. Each copy has a new UID, so the per-message brake does
not bind it, `undo` cannot remove it (that needs a delete verb), and move/undo/move multiplies.
Enough duplicates hits quota — inbound mail bounces. Destruction achieved with allowlisted moves
only. Also: verifying the copy by Message-ID search false-positives against a pre-existing copy
and false-negatives when Message-ID is absent.
**Adopted.** `COPYUID` from UIDPLUS (RFC 4315) for authoritative destination UID; the operation is
**refused outright when UIDPLUS is absent**. Move refused when the destination already holds that
Message-ID. Source marked `copy_pending_manual` so no run retries it, with a hard per-account cap
on outstanding ones, a loud `doctor`/journald alert, and `mailgate reconcile` to list them.

### H16 Undo had no preconditions, no idempotency, and did not take the lock
Nothing prevented undoing twice, undoing a record whose message Spencer has since moved himself
(clobbering the newer state), undoing an undo, or undo racing the server — and `mailgate undo` is a
separate process, so an in-process lock never covered it.
**Adopted.** Undo takes the same `flock` on a per-account lockfile as the server and every CLI
mutator; verifies current state equals the recorded `post` and otherwise refuses without an
explicit `--force` that logs the divergence; writes a linked `undo_of` record and marks the
original `undone`, refusing a second undo; and runs through the policy engine (an undo can move
mail back into a folder no longer allowlisted).

### H17 Two account aliases pointing at one mailbox defeat every per-account control
Limits, the same-account check and the writer lock were all keyed on the config alias. A Gmail
account also configured over IMAP, or a delegated mailbox configured as its own account, doubles
every budget and lets two adapters race the same folder.
**Adopted.** Locks, limits and same-account checks key on **resolved mailbox identity** (Graph
mailbox GUID, Gmail `emailAddress`, IMAP server+authzid). Two accounts resolving to one mailbox is
a startup failure.

### H18 ‡ No schema or record versioning — canonical-JSON drift invalidates the whole chain
`verify` recomputes over "canonical JSON". The first change to field ordering or Unicode escaping
makes every historical record fail, and the operator learns to ignore `verify`. Same for the SQLite
schema, the fixture format and the policy.
**Adopted.** `v` on every audit record selecting its canonicalisation rules, frozen by golden-file
tests; `schema_version` in SQLite with forward-only migrations run under the account lock and
logged into the chain; versioned fixtures; `policy_version` in the TOML, and `doctor` prints the
policy digest in exactly the form the launcher needs (so pinning is not abandoned out of friction).

### H19 ‡ Cursor stability
"cursor-paged, capped" was the whole specification. Any `$skip`/offset paging over a folder the
agent is simultaneously emptying skips messages and repeats others; the agent then reports the
folder triaged having seen ~60% of it. Nothing invalidated a cursor across a UIDVALIDITY bump or a
Gmail `historyId` discontinuity.
**Adopted.** Cursors are opaque, provider-specific, self-validating watermarks — IMAP
`(mailbox, UIDVALIDITY, last_UID)`; Gmail `pageToken` + `historyId` at list start; Graph
`(receivedDateTime, immutable_id)` with a stable `$orderby`, never `$skip`. Explicit
`cursor_invalidated` status rather than silent resumption. A folder may not be mutated while a
listing over it is open: snapshot the id set, then mutate.

### H20 The audit record had no observed post-state
`target` is intent. Nothing recorded what the provider actually did, hiding partial application,
Gmail thread propagation, Graph id changes and IMAP renumbering — making the log a record of
*requests believed to have succeeded*.
**Adopted.** Every mutation reads state back and logs `post` in the same canonical form as `prior`,
plus returned identifiers and `etag`/`modseq`/`historyId`. Undo requires `post` to match current
state.

---

## Medium — accepted, folded into the implementation

- **M1 MIME structural bombs.** No part-count, nesting-depth or decoded-total limits; a 10,000-part
  or deeply nested message will happily consume the stdlib parser, and a `message/rfc822`
  attachment's `text/plain` could be selected as *the* body. → caps on parts (64), depth (8) and
  decoded bytes; parse under a timeout; never descend into `message/rfc822` for body selection.
- **M2 Plaintext/HTML divergence.** Preferring `text/plain` means the agent triages benign text
  while Spencer's client renders different `text/html`. → report a `body_divergence` flag rather
  than silently choosing.
- **M3 `\Sent` / `\Outbox` were not denylisted.** The plan covered `\Trash`/`\Junk`/`\Drafts` only.
  On a self-hosted MTA-watched `Outbox`, a move is a send primitive with headers the original
  sender chose. `[speculative, but concrete for Dovecot/Maildir + a client-managed outbox]` →
  `\Sent`, `\Outbox`, `\Queue`, `\All`, `\Archive`-as-Gmail-`All Mail` denylisted by attribute and name.
- **M4 `SKILL.md` is not a control.** "Never retry-storm", "stop if `suspected_injection`" and the
  reorganisation cap are advice to the component assumed compromised. → every one has a server-side
  twin; the skill documents them as *server-enforced*, not as etiquette.
- **M5 Approval socket path.** With `$XDG_RUNTIME_DIR` unset (headless, cron, container) the socket
  needs a defined home; `/tmp` lets another user pre-create the path. → refuse to start rather than
  fall back. Also: the socket is a mutation-granting channel, so it gets bounded framing, a verb
  allowlist of accept/reject on an existing request id, and `SO_PEERCRED` uid checking — the plan's
  "stdio only, nothing to attack" claim was self-contradicting.
- **M6 `subject_hash` over normalised text** would not match the real subject during forensics.
  → hash raw bytes; keep the normalised form for display only.
- **M7 Agent `reason` field unbounded** → it is written to the audit log, which was explicitly not
  meant to become a second copy of the mailbox. Enum + 120 bounded chars (also H3).
- **M8 Torn-line and crash recovery** (see H8d), plus `flock` for every CLI mutator (H16).
- **M9 Shared-mailbox third writer.** The per-account lock cannot cover a human in a delegated
  mailbox → always take the conditional/ETag path there; any precondition failure is `stale_handle`.

## One thing the reviews did not catch, found while implementing

**Undo could not return mail to INBOX.** `mailgate undo` ran the reverse move
through `check_move`, which requires the destination to be on `move_allowlist` --
and INBOX never is, because it is not a place the agent may file mail. So undo was
unusable for the single most common case. Fixed with a separate `check_undo_move`
that lifts *only* the allowlist requirement, on the grounds that the destination is
provably where the message came from: it is read from the audited record's
`from_folder`, and the move away from it was itself logged. Every other check --
destructive attributes, shared namespace, destination automation, protected
folders -- still applies, so undo cannot be used as a route into a folder the
agent could not otherwise reach.

## Rejected / deferred, with reasons

- **Netns/nftables egress confinement** (from H5) — correct, but it is deployment, not code. Written
  up in `docs/HARDENING.md` as the prerequisite for `auto` mode on a real mailbox; not implemented
  here.
- **Running mailgate as a dedicated uid** — same: documented as the prerequisite for trusting the
  approval channel and the policy pin, not something the code can do to itself.
- **Dropping `op://` because it shells out** — kept. Spencer chose an external secret manager;
  subprocess invocation of a fixed, non-configurable argv is qualitatively different from `cmd:`,
  which was dropped.

## What both reviewers checked and considered sound

Special-use/attribute-based destination resolution as the *primary* control with name matching only
additive; refusing to complete `COPY`+`\Deleted`; no LLM inside the server; the approval broker
living on a channel the agent does not sit on; the absence of `create_label`, `set_mode`,
`reload_config`, `undo`-as-a-tool and any raw passthrough; monotonic clocks for in-process TTLs;
logging denials as well as successes; unknown config keys as a startup error; UIDVALIDITY-scoped
handles; the credential indirection and redaction filter; and fixture-first development with live
adapters disabled.

Both reviewers also singled out the two most useful sentences in the plan — that no-send/no-delete
is enforced by mailgate and credential confinement rather than by the provider, and that same-user
separation is a speed bump rather than a boundary — and noted that four *other* passages ("no
mechanism", "physically lacks the verbs", the policy pin, "impossible anyway") were not written to
that standard. Those four have been rewritten.
