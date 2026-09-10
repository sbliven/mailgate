"""`mailgate` -- the human's side.

Everything here is deliberately outside the MCP surface: mode changes, policy
inspection, undo, reconciliation and approval.  An agent that could reach any of
these could widen its own permissions.
"""
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import argparse
import json
import socket
import sys
from pathlib import Path

from .approval_socket import runtime_dir
from .core.audit import AuditLog
from .core.mailstate import canonical_json, sha256_hex
from .core.store import Store
from .engine import open_mailgate
from .errors import MailgateError
from .server import default_state_dir


def _ask(sock_path: Path, payload: dict) -> dict:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(15)
    s.connect(str(sock_path))
    s.sendall((json.dumps(payload) + "\n").encode())
    buf = b""
    while b"\n" not in buf:
        chunk = s.recv(65536)
        if not chunk:
            break
        buf += chunk
    s.close()
    return json.loads(buf.split(b"\n", 1)[0] or b"{}")


def cmd_approve(args) -> int:
    """Interactive approval.  Typed confirmation, never a single keypress."""
    sock = runtime_dir() / "approve.sock"
    if not sock.exists():
        print("no running mailgate server (approval socket missing)", file=sys.stderr)
        return 2
    res = _ask(sock, {"verb": "list"})
    pending = res.get("pending", [])
    if not pending:
        print(f"mode={res.get('mode')}: nothing pending")
        return 0
    for p in pending:
        print("=" * 68)
        print(p["rendered"])
        print("-" * 68)
        print(f"verification code: {p['verification_code']}   waiting {p['age_s']}s")
        print("type 'yes' to apply, 'no' to reject, or 'skip' to leave it pending")
        try:
            answer = input("> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return 1
        if answer == "skip":
            continue
        if answer == "yes":
            out = _ask(sock, {"verb": "accept", "id": p["id"]})
        elif answer == "no":
            out = _ask(sock, {"verb": "reject", "id": p["id"], "note": "rejected"})
        else:
            print("not 'yes' or 'no' -- leaving it pending")
            continue
        print(json.dumps(out.get("outcome", out), indent=1))
    return 0


def _log_records(state: Path):
    for path in sorted((state / "audit").glob("*.jsonl")):
        for line in path.read_text().splitlines():
            if line.strip():
                yield json.loads(line)


def cmd_log(args) -> int:
    state = Path(args.state_dir) if args.state_dir else default_state_dir()
    n = 0
    for rec in _log_records(state):
        if args.mutations_only and rec.get("type") != "outcome":
            continue
        if args.op and rec.get("op") != args.op:
            continue
        if args.json:
            print(json.dumps(rec))
        else:
            # same id format the tools return: <seq>:<first 12 of this record's hash>
            aid = f"{rec.get('seq')}:{sha256_hex(canonical_json(rec))[:12]}"
            print(
                f"{rec.get('ts','')[:19]}  {aid:>16}  {rec.get('type',''):<10} "
                f"{rec.get('op',''):<14} {rec.get('decision',''):<18} "
                f"{rec.get('account','')} {rec.get('reason_code','')}"
            )
        n += 1
    print(f"-- {n} record(s)", file=sys.stderr)
    return 0


def cmd_verify(args) -> int:
    state = Path(args.state_dir) if args.state_dir else default_state_dir()
    store = Store(state)
    audit = AuditLog(state / "audit", store, anchor=False)
    r = audit.verify()
    print(r.summary())
    for p in r.problems:
        print("  !", p)
    if r.incomplete_tail:
        print("  (a torn final line is recoverable: truncate to the last newline)")
    return 0 if r.ok else 1


def cmd_undo(args) -> int:
    state = Path(args.state_dir) if args.state_dir else default_state_dir()
    mg = open_mailgate(args.policy, state, enable_live=args.enable_live_providers)
    print(json.dumps(mg.undo(args.audit_id, force=args.force), indent=1))
    return 0


def cmd_reconcile(args) -> int:
    state = Path(args.state_dir) if args.state_dir else default_state_dir()
    store = Store(state)
    rows = store.in_flight()
    dupes = list(
        store.cx.execute("SELECT * FROM copy_pending WHERE resolved=0")
    )
    if not rows and not dupes:
        print("nothing to reconcile")
        return 0
    for r in rows:
        print(
            f"UNKNOWN OUTCOME  mailbox={r['mailbox']} op={r['op']} key={r['idem_key']}\n"
            "  mailgate does not know whether the provider applied this. Check the message in "
            "your mail client, then clear it with --resolve <key> applied|not_applied."
        )
    for d in dupes:
        print(
            f"DUPLICATE  {d['message_key'][:12]} copied {d['src']} -> {d['dest']} "
            f"(uid {d['dest_uid']}) and the source was deliberately left in place.\n"
            "  Delete whichever copy you do not want, in your mail client. mailgate has no "
            "delete verb and will not do it for you."
        )
    if args.resolve:
        key, verdict = args.resolve
        store.cx.execute(
            "UPDATE idem SET state='terminal', status=? WHERE idem_key=?", (verdict, key)
        )
        store.cx.execute("UPDATE copy_pending SET resolved=1 WHERE message_key=?", (key,))
        print(f"resolved {key} as {verdict}")
    return 0


def cmd_doctor(args) -> int:
    state = Path(args.state_dir) if args.state_dir else default_state_dir()
    try:
        mg = open_mailgate(args.policy, state, enable_live=args.enable_live_providers)
    except MailgateError as exc:
        print(f"FAIL  {exc.code}: {exc}")
        return 1
    print(f"policy      : {mg.policy.path}")
    print(f"digest      : {mg.policy.digest}")
    print(f"policy pin  : {'PINNED via ' + mg.policy.pin_source if mg.policy.pinned else 'UNPINNED (' + mg.policy.pin_source + ')'}")
    if not mg.policy.pinned:
        print("              to pin it, as root:")
        print(f"              echo {mg.policy.digest} > /etc/mailgate/policy.sha256")
        print("              (an env-var pin is not a pin: the agent's process tree sets it)")
    print(f"mode        : {mg.policy.mode.value}")
    print(f"state dir   : {state}")
    v = mg.audit.verify()
    print(f"audit chain : {v.summary()}")
    for p in v.problems:
        print(f"              ! {p}")
    for b in mg.accounts.values():
        r = b.resolved
        print(f"\naccount {b.name} [{b.resolved.policy.backend}] mailbox={b.mailbox}")
        for fid in sorted(r.move_allow_ids):
            f = r.folders_by_id[fid]
            print(
                f"  destination {f.display_name:<14} id={f.id:<14} "
                f"special_use={sorted(f.special_use) or '[]'} shared={f.is_outside_personal} "
                f"automation={f.has_destructive_automation}"
            )
        for fid in sorted(r.deny_read_ids):
            print(f"  unreadable  {r.folders_by_id[fid].display_name}")
        n = mg.store.count_copy_pending(b.mailbox)
        if n:
            print(f"  ! {n} unreconciled duplicate(s) -- run `mailgate reconcile`")
    if mg.reconciliation:
        print(f"\n! {len(mg.reconciliation)} operation(s) with an unknown outcome; run `mailgate reconcile`")
    print("\nreminder: no-send / no-delete is enforced by mailgate's code and by confining the")
    print("credential -- not by the provider. See docs/HARDENING.md before enabling auto mode.")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="mailgate")
    ap.add_argument("--state-dir", default=None)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("approve", help="review and decide pending approvals")
    p.set_defaults(fn=cmd_approve)

    p = sub.add_parser("log", help="render the audit log")
    p.add_argument("--json", action="store_true")
    p.add_argument("--mutations-only", action="store_true")
    p.add_argument("--op")
    p.set_defaults(fn=cmd_log)

    p = sub.add_parser("verify", help="recompute the audit hash chain")
    p.set_defaults(fn=cmd_verify)

    p = sub.add_parser("undo", help="reverse one mutation")
    p.add_argument("audit_id")
    p.add_argument("--policy", required=True)
    p.add_argument("--force", action="store_true")
    p.add_argument("--enable-live-providers", action="store_true")
    p.set_defaults(fn=cmd_undo)

    p = sub.add_parser("reconcile", help="list and clear unknown outcomes and duplicates")
    p.add_argument("--resolve", nargs=2, metavar=("IDEM_KEY", "applied|not_applied"))
    p.set_defaults(fn=cmd_reconcile)

    p = sub.add_parser("doctor", help="check the policy, the chain and every destination")
    p.add_argument("--policy", required=True)
    p.add_argument("--enable-live-providers", action="store_true")
    p.set_defaults(fn=cmd_doctor)

    args = ap.parse_args(argv)
    try:
        return args.fn(args)
    except MailgateError as exc:
        print(f"{exc.code}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
