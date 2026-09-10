"""Policy: load, fail closed, resolve to provider ids, decide.

Two rules govern this module.

1. **Unknown keys and unresolvable values are both startup failures.**  A typo'd
   ``move_allowlist`` must become neither "allow nothing" nor "allow everything" --
   it becomes a refusal to start.  The original design applied that discipline to
   unknown keys and then reintroduced the fail-open for values that do not resolve.

2. **Allowlists match provider ids, byte-exact.**  Names are resolved once, at
   startup, using the delimiter the server actually reports.  Normalisation exists
   only to detect that two configured names are confusable and refuse.
"""
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import enum
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from ..errors import ConfigError, PolicyDenied
from ..folders import (
    FolderInfo,
    LabelInfo,
    MailboxIdentity,
    is_reserved_label,
)
from .mailstate import canonical_json, sha256_hex
from .secfs import check_secure_path
from .textsafe import fold_for_ambiguity

POLICY_SCHEMA_VERSION = 1
ROOT_PIN_PATH = Path("/etc/mailgate/policy.sha256")


class Mode(str, enum.Enum):
    DRY_RUN = "dry_run"
    TRAINING = "training"
    SUPERVISED = "supervised"
    AUTO = "auto"


@dataclass(frozen=True)
class Limits:
    # Persisted with wall-clock windows keyed on resolved mailbox identity, so a
    # server restart does not hand the agent a fresh budget.
    mutations_per_hour: int = 40
    mutations_per_day: int = 120
    inbox_removals_per_day: int = 60
    get_message_per_hour: int = 120
    get_message_per_run: int = 40
    list_messages_per_hour: int = 200
    #: Denials and errors charge this separate, stricter budget, evaluated BEFORE
    #: validation -- otherwise denied calls are free and unlimited.
    denials_per_hour: int = 20
    approval_prompts_per_hour: int = 25
    max_pending_approvals: int = 2
    max_status_polls: int = 12
    approval_timeout_s: int = 90
    max_body_bytes: int = 262144
    max_mime_parts: int = 64
    max_mime_depth: int = 8
    same_sender_move_brake: int = 8
    max_outstanding_copy_pending: int = 5

    _FIELDS = ()  # populated below


Limits._FIELDS = tuple(Limits.__dataclass_fields__)


@dataclass(frozen=True)
class AccountPolicy:
    name: str
    backend: str
    live: bool = False
    secret_ref: str = ""
    server: str = ""
    username: str = ""
    fixture: str = ""
    move_allowlist: tuple[str, ...] = ()
    label_allowlist: tuple[str, ...] = ()
    protect_folders: tuple[str, ...] = ()   # denies READ and write (see review H11)
    no_write: tuple[str, ...] = ()          # readable, never a source or destination
    deny_read: tuple[str, ...] = ()
    #: Spencer must attest, per destination, that no retention policy or third-party
    #: automation acts on it.  A destination with an MRM tag or a cleanup script is
    #: deferred deletion achieved entirely through allowlisted moves.
    attest_no_retention: tuple[str, ...] = ()
    expose_addresses: bool = False
    expose_full_links: bool = False


@dataclass(frozen=True)
class Policy:
    mode: Mode
    limits: Limits
    accounts: dict[str, AccountPolicy]
    policy_version: int
    digest: str
    path: Path
    pinned: bool
    pin_source: str


_TOP_KEYS = {"mode", "policy_version", "limits", "accounts"}
_ACCOUNT_KEYS = set(AccountPolicy.__dataclass_fields__) - {"name"}


def _reject_unknown(where: str, got, allowed) -> None:
    unknown = sorted(set(got) - set(allowed))
    if unknown:
        raise ConfigError(
            f"unknown key(s) in {where}: {', '.join(unknown)}", code="unknown_config_key"
        )


def _tuple(value, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{where} must be a list of strings", code="bad_config_type")
    return tuple(value)


def load_policy(path: str | Path, *, skip_perm_check: bool = False) -> Policy:
    p = Path(path)
    if not skip_perm_check:
        check_secure_path(p, mode_max=0o600)
    raw_bytes = p.read_bytes()
    digest = sha256_hex(raw_bytes)
    try:
        raw = tomllib.loads(raw_bytes.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - never leak file content
        raise ConfigError(f"could not parse {p}: {type(exc).__name__}", code="bad_config") from exc

    _reject_unknown("policy file", raw, _TOP_KEYS)

    version = raw.get("policy_version", POLICY_SCHEMA_VERSION)
    if version != POLICY_SCHEMA_VERSION:
        raise ConfigError(
            f"policy_version {version} != supported {POLICY_SCHEMA_VERSION}",
            code="policy_version_mismatch",
        )

    try:
        mode = Mode(raw.get("mode", "training"))
    except ValueError as exc:
        raise ConfigError(f"mode must be one of {[m.value for m in Mode]}", code="bad_mode") from exc

    lim_raw = raw.get("limits", {})
    _reject_unknown("[limits]", lim_raw, Limits._FIELDS)
    for k, v in lim_raw.items():
        if not isinstance(v, int) or isinstance(v, bool) or v < 0:
            raise ConfigError(f"limits.{k} must be a non-negative integer", code="bad_config_type")
    limits = Limits(**lim_raw)

    accounts: dict[str, AccountPolicy] = {}
    for name, acc_raw in (raw.get("accounts") or {}).items():
        if not isinstance(acc_raw, dict):
            raise ConfigError(f"accounts.{name} must be a table", code="bad_config_type")
        _reject_unknown(f"accounts.{name}", acc_raw, _ACCOUNT_KEYS)
        if "backend" not in acc_raw:
            raise ConfigError(f"accounts.{name} has no backend", code="bad_config")
        if acc_raw["backend"] not in {"gmail", "graph", "imap", "fake"}:
            raise ConfigError(
                f"accounts.{name}.backend must be gmail|graph|imap|fake", code="bad_config"
            )
        kw: dict = {"name": name}
        for k, v in acc_raw.items():
            fld = AccountPolicy.__dataclass_fields__[k]
            if fld.type.startswith("tuple"):
                kw[k] = _tuple(v, f"accounts.{name}.{k}")
            else:
                kw[k] = v
        acc = AccountPolicy(**kw)
        _validate_account_shape(acc)
        accounts[name] = acc

    if not accounts:
        raise ConfigError("policy defines no accounts", code="bad_config")

    pinned, pin_source = _check_pin(digest)
    return Policy(
        mode=mode,
        limits=limits,
        accounts=accounts,
        policy_version=version,
        digest=digest,
        path=p,
        pinned=pinned,
        pin_source=pin_source,
    )


def _validate_account_shape(acc: AccountPolicy) -> None:
    """Static checks that need no backend connection."""
    # A secret_ref of cmd: was dropped in review: it is arbitrary execution driven
    # by a file the agent's own process tree may be able to write.
    if acc.secret_ref.startswith("cmd:"):
        raise ConfigError(
            f"accounts.{acc.name}.secret_ref uses cmd:, which mailgate does not support",
            code="forbidden_secret_ref",
        )
    if acc.secret_ref and not acc.secret_ref.split(":", 1)[0] in {
        "op",
        "pass",
        "gopass",
        "keyring",
        "env",
        "fixture",
    }:
        raise ConfigError(
            f"accounts.{acc.name}.secret_ref scheme not supported", code="bad_secret_ref"
        )
    for lbl in acc.label_allowlist:
        if is_reserved_label(lbl):
            raise ConfigError(
                f"accounts.{acc.name}.label_allowlist contains reserved id {lbl!r}",
                code="reserved_label_in_allowlist",
            )
    # Confusable / duplicate configured names: detect and REFUSE.  Never fold in
    # order to accept a match.
    for field_name in ("move_allowlist", "label_allowlist", "protect_folders"):
        seen: dict[str, str] = {}
        for name in getattr(acc, field_name):
            folded = fold_for_ambiguity(name)
            if folded in seen and seen[folded] != name:
                raise ConfigError(
                    f"accounts.{acc.name}.{field_name}: {name!r} and {seen[folded]!r} are "
                    "confusable; refusing to start",
                    code="confusable_config",
                )
            seen[folded] = name
    missing = set(acc.move_allowlist) - set(acc.attest_no_retention)
    if missing:
        raise ConfigError(
            f"accounts.{acc.name}: destinations {sorted(missing)} are on move_allowlist but not "
            "attested in attest_no_retention (confirm no retention policy or third-party "
            "automation acts on them)",
            code="unattested_destination",
        )


def _check_pin(digest: str) -> tuple[bool, str]:
    """Policy pinning, honestly.

    Under stdio transport the agent's own process tree spawns mailgate, so it
    controls both the environment and the config file.  An env-var pin therefore
    pins nothing.  Only a root-owned digest -- or a systemd unit the agent cannot
    edit -- is a real pin; everything else is reported as UNPINNED.
    """
    if ROOT_PIN_PATH.exists():
        try:
            st = ROOT_PIN_PATH.stat()
            expected = ROOT_PIN_PATH.read_text().split()[0].strip()
        except OSError as exc:
            raise ConfigError(f"cannot read {ROOT_PIN_PATH}", code="pin_unreadable") from exc
        if st.st_uid != 0:
            raise ConfigError(
                f"{ROOT_PIN_PATH} is not root-owned; it is not a pin", code="fake_pin"
            )
        if expected != digest:
            raise ConfigError(
                "policy digest does not match the root-owned pin; refusing to start",
                code="policy_pin_mismatch",
            )
        return True, str(ROOT_PIN_PATH)
    env = os.environ.get("MAILGATE_POLICY_SHA256")
    if env:
        if env.strip() != digest:
            raise ConfigError(
                "policy digest does not match MAILGATE_POLICY_SHA256; refusing to start",
                code="policy_pin_mismatch",
            )
        # Matched, but the agent could have set both.  Not a pin.
        return False, "env (advisory only -- agent-controllable, not a pin)"
    return False, "none"


# --------------------------------------------------------------------------- #
# Resolution against a live (or fake) backend
# --------------------------------------------------------------------------- #


@dataclass
class ResolvedAccount:
    policy: AccountPolicy
    identity: MailboxIdentity
    folders_by_id: dict[str, FolderInfo]
    labels_by_id: dict[str, LabelInfo]
    move_allow_ids: frozenset[str]
    label_allow_ids: frozenset[str]
    protect_ids: frozenset[str]
    no_write_ids: frozenset[str]
    deny_read_ids: frozenset[str]
    #: name -> id, recorded into the audit header so a reviewer can see exactly what
    #: was protected and what was writable.
    resolution_map: dict[str, str] = field(default_factory=dict)

    def header(self) -> dict:
        return {
            "account": self.policy.name,
            "backend": self.policy.backend,
            "mailbox": self.identity.key,
            "resolution": dict(sorted(self.resolution_map.items())),
            "move_allow_ids": sorted(self.move_allow_ids),
            "label_allow_ids": sorted(self.label_allow_ids),
            "protect_ids": sorted(self.protect_ids),
            "deny_read_ids": sorted(self.deny_read_ids),
        }


def _resolve_one(
    kind: str,
    account: str,
    name: str,
    candidates: dict[str, object],
    name_of,
) -> str:
    """Resolve a configured display name to exactly one provider id, or fail."""
    hits = [cid for cid, obj in candidates.items() if name_of(obj) == name]
    if not hits:
        # try full path for folders, then a folded comparison purely to produce a
        # helpful error -- never to accept
        folded = fold_for_ambiguity(name)
        near = [name_of(o) for o in candidates.values() if fold_for_ambiguity(name_of(o)) == folded]
        hint = f" (did you mean {near[0]!r}? it is not byte-identical)" if near else ""
        raise ConfigError(
            f"accounts.{account}: {kind} {name!r} does not resolve to any {kind}{hint}",
            code="unresolved_config_value",
        )
    if len(hits) > 1:
        raise ConfigError(
            f"accounts.{account}: {kind} {name!r} resolves to {len(hits)} targets; refusing",
            code="ambiguous_config_value",
        )
    return hits[0]


def resolve_account(
    acc: AccountPolicy,
    identity: MailboxIdentity,
    folders: list[FolderInfo],
    labels: list[LabelInfo],
) -> ResolvedAccount:
    fby = {f.id: f for f in folders}
    lby = {l.id: l for l in labels}
    resmap: dict[str, str] = {}

    def resolve_folder(name: str, kind: str) -> str:
        # match on display_name first, then on the server-delimited path, so that a
        # config entry works whatever the server's delimiter is
        try:
            fid = _resolve_one(kind, acc.name, name, fby, lambda f: f.display_name)
        except ConfigError:
            fid = _resolve_one(kind, acc.name, name, fby, lambda f: f.path)
        resmap[f"{kind}:{name}"] = fid
        return fid

    move_ids = set()
    for name in acc.move_allowlist:
        fid = resolve_folder(name, "folder")
        f = fby[fid]
        if f.is_destructive:
            raise ConfigError(
                f"accounts.{acc.name}: destination {name!r} carries {sorted(f.special_use)}; "
                "it is a destructive folder however it is named",
                code="destructive_destination",
            )
        if f.is_outside_personal:
            raise ConfigError(
                f"accounts.{acc.name}: destination {name!r} is in the "
                f"{f.namespace} namespace (shared={f.is_shared}); moving mail there hands it to "
                "a third party",
                code="shared_destination",
            )
        if f.has_destructive_automation:
            raise ConfigError(
                f"accounts.{acc.name}: destination {name!r} is acted on by a server-side rule "
                f"({f.automation_note}); a move there is deferred deletion or forwarding",
                code="destination_automation",
            )
        if not f.selectable:
            raise ConfigError(
                f"accounts.{acc.name}: destination {name!r} is not selectable",
                code="unselectable_destination",
            )
        move_ids.add(fid)

    label_ids = set()
    for name in acc.label_allowlist:
        lid = _resolve_one("label", acc.name, name, lby, lambda l: l.display_name)
        if is_reserved_label(lid) or lby[lid].reserved:
            raise ConfigError(
                f"accounts.{acc.name}: label {name!r} resolves to reserved id {lid!r}",
                code="reserved_label",
            )
        resmap[f"label:{name}"] = lid
        label_ids.add(lid)

    protect_ids = {resolve_folder(n, "folder") for n in acc.protect_folders}
    no_write_ids = {resolve_folder(n, "folder") for n in acc.no_write}
    deny_read_ids = {resolve_folder(n, "folder") for n in acc.deny_read}
    # protect_folders denies reads too: "read-only, never a source or destination"
    # still let the agent read every legal message, and read-then-exfiltrate is the
    # dominant loss against an injected agent.
    deny_read_ids |= protect_ids
    no_write_ids |= protect_ids

    overlap = move_ids & no_write_ids
    if overlap:
        raise ConfigError(
            f"accounts.{acc.name}: {sorted(overlap)} are both a destination and protected",
            code="contradictory_config",
        )

    return ResolvedAccount(
        policy=acc,
        identity=identity,
        folders_by_id=fby,
        labels_by_id=lby,
        move_allow_ids=frozenset(move_ids),
        label_allow_ids=frozenset(label_ids),
        protect_ids=frozenset(protect_ids),
        no_write_ids=frozenset(no_write_ids),
        deny_read_ids=frozenset(deny_read_ids),
        resolution_map=resmap,
    )


# --------------------------------------------------------------------------- #
# Decisions
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    code: str = "ok"

    @staticmethod
    def deny(code: str, reason: str) -> "Decision":
        return Decision(False, reason, code)

    @staticmethod
    def ok(reason: str = "") -> "Decision":
        return Decision(True, reason or "policy ok")


ALLOW_INBOX_REMOVAL_OPS = frozenset({"move_message"})


def check_read(ra: ResolvedAccount, folder_id: str) -> Decision:
    f = ra.folders_by_id.get(folder_id)
    if f is None:
        return Decision.deny("unknown_folder", "folder does not resolve")
    if folder_id in ra.deny_read_ids:
        return Decision.deny(
            "read_denied", f"{f.display_name} is protected from reads by policy"
        )
    return Decision.ok()


def check_move(ra: ResolvedAccount, src_folder_id: str | None, dest_folder_id: str) -> Decision:
    dest = ra.folders_by_id.get(dest_folder_id)
    if dest is None:
        return Decision.deny("unknown_folder", "destination does not resolve to a folder")
    # Attribute check first and unconditionally, even though resolve_account already
    # refused destructive destinations: folder attributes can change between runs.
    if dest.is_destructive:
        return Decision.deny(
            "destructive_destination",
            f"destination carries {sorted(dest.special_use)}",
        )
    if dest.is_outside_personal:
        return Decision.deny("shared_destination", "destination is outside the personal namespace")
    if dest.has_destructive_automation:
        return Decision.deny("destination_automation", dest.automation_note or "rule on destination")
    if dest_folder_id not in ra.move_allow_ids:
        return Decision.deny("destination_not_allowlisted", "destination is not on move_allowlist")
    if src_folder_id is not None:
        src = ra.folders_by_id.get(src_folder_id)
        if src is None:
            return Decision.deny("unknown_folder", "source does not resolve")
        if src_folder_id in ra.no_write_ids:
            return Decision.deny("source_protected", f"{src.display_name} is protected")
        if src_folder_id == dest_folder_id:
            return Decision.deny("no_op", "source and destination are the same folder")
    return Decision.ok()


def check_undo_move(ra: ResolvedAccount, src_folder_id: str, dest_folder_id: str) -> Decision:
    """Move check for `mailgate undo` only.

    The allowlist requirement is lifted, because the destination is provably where
    the message came from: it is read from the audited record's ``from_folder``, and
    the move away from it was itself logged.  Requiring the allowlist here would
    make undo impossible for the common case -- returning mail to INBOX, which is
    never an agent destination.  Every other check still applies, including the
    attribute check, so undo cannot be used to reach a destructive or shared folder.
    """
    dest = ra.folders_by_id.get(dest_folder_id)
    if dest is None:
        return Decision.deny("unknown_folder", "destination does not resolve")
    if dest.is_destructive:
        return Decision.deny(
            "destructive_destination", f"destination carries {sorted(dest.special_use)}"
        )
    if dest.is_outside_personal:
        return Decision.deny("shared_destination", "destination is outside the personal namespace")
    if dest.has_destructive_automation:
        return Decision.deny("destination_automation", dest.automation_note)
    if dest_folder_id in ra.no_write_ids:
        return Decision.deny("destination_protected", "destination is protected by policy")
    if src_folder_id in ra.no_write_ids:
        return Decision.deny("source_protected", "source is protected by policy")
    return Decision.ok()


def check_labels(
    ra: ResolvedAccount, op: str, add: tuple[str, ...], remove: tuple[str, ...]
) -> Decision:
    if not add and not remove:
        return Decision.deny("no_op", "nothing to add or remove")
    for lid in tuple(add) + tuple(remove):
        # `remove` is bound by the same allowlist as `add`.  Unbound removal is the
        # archive-and-hide verb.
        if is_reserved_label(lid):
            if lid == "INBOX" and op in ALLOW_INBOX_REMOVAL_OPS and lid in remove:
                continue
            return Decision.deny(
                "reserved_label",
                f"{lid} is provider-reserved; adding or removing it is not organisation",
            )
        if lid not in ra.label_allow_ids:
            return Decision.deny("label_not_allowlisted", f"{lid} is not on label_allowlist")
    return Decision.ok()
