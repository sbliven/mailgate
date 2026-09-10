"""The approval channel.

This socket grants mutations, so it is the one thing in the process that needs the
same scrutiny as the tool surface:

* it lives under ``$XDG_RUNTIME_DIR``; if that is unset the server **refuses to
  start** rather than falling back to ``/tmp``, where another user can pre-create
  the path
* mode 0600, and every connection's ``SO_PEERCRED`` uid must equal ours
* bounded framing: one line, at most 4 KiB
* a verb allowlist of exactly ``list`` / ``accept`` / ``reject`` against an existing
  request id.  There is no verb that changes mode, policy or limits
"""
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import os
import socket
import struct
import threading
from pathlib import Path

from .errors import ConfigError

MAX_LINE = 4096
VERBS = {"list", "accept", "reject", "ping"}


def runtime_dir() -> Path:
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if not xdg:
        raise ConfigError(
            "XDG_RUNTIME_DIR is not set, so there is no private directory for the approval "
            "socket. Refusing to start rather than using /tmp, where another user could "
            "pre-create the path. Set XDG_RUNTIME_DIR or pass --no-approval-socket and approve "
            "with `mailgate approve --once`.",
            code="no_runtime_dir",
        )
    d = Path(xdg) / "mailgate"
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(d, 0o700)
    return d


class ApprovalSocket:
    def __init__(self, mg):
        self.mg = mg
        self.path = runtime_dir() / "approve.sock"
        self._srv: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        if self.path.exists():
            self.path.unlink()
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old = os.umask(0o177)
        try:
            s.bind(str(self.path))
        finally:
            os.umask(old)
        os.chmod(self.path, 0o600)
        s.listen(4)
        s.settimeout(0.5)
        self._srv = s
        self._thread = threading.Thread(target=self._serve, daemon=True, name="mailgate-approve")
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._srv.accept()
            except socket.timeout:
                self.mg.broker.expire_stale()
                continue
            except OSError:
                return
            with conn:
                try:
                    self._handle(conn)
                except Exception:  # noqa: BLE001 - never let a client kill the server
                    pass

    def _handle(self, conn: socket.socket) -> None:
        creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", creds)
        if uid != os.getuid():
            conn.sendall(b'{"error":"peer uid mismatch"}\n')
            return
        conn.settimeout(10)
        buf = b""
        while b"\n" not in buf:
            chunk = conn.recv(1024)
            if not chunk:
                return
            buf += chunk
            if len(buf) > MAX_LINE:
                conn.sendall(b'{"error":"request too long"}\n')
                return
        try:
            req = json.loads(buf.split(b"\n", 1)[0])
        except ValueError:
            conn.sendall(b'{"error":"malformed request"}\n')
            return
        verb = req.get("verb")
        if verb not in VERBS:
            conn.sendall(b'{"error":"unknown verb"}\n')
            return
        if verb == "ping":
            conn.sendall(b'{"ok":true}\n')
            return
        if verb == "list":
            out = {
                "mode": self.mg.policy.mode.value,
                "pending": [
                    {
                        "id": r.id,
                        "account": r.account,
                        "verification_code": r.verification_code(),
                        "rendered": r.render(),
                        "age_s": round(__import__("time").monotonic() - r.created),
                    }
                    for r in self.mg.broker.pending()
                ],
            }
            conn.sendall((json.dumps(out) + "\n").encode())
            return
        rid = str(req.get("id", ""))[:64]
        outcome = self.mg.broker.decide(rid, verb == "accept", note=str(req.get("note", ""))[:120])
        conn.sendall((json.dumps({"id": rid, "outcome": outcome}) + "\n").encode())

    def stop(self) -> None:
        self._stop.set()
        if self._srv:
            try:
                self._srv.close()
            except OSError:
                pass
        if self.path.exists():
            try:
                self.path.unlink()
            except OSError:
                pass
