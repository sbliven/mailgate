"""The outbound HTTP chokepoint.

"The adapter contains no DELETE verb" is a lint, not a boundary: it is defeated by
string construction, by the generic ``_request(method, path)`` helper every adapter
needs, and by dependencies that issue requests on your behalf.  So every provider
call in mailgate goes through this one function, which allowlists
``(method, host, path-regex)`` triples and raises on anything else.

This is still not egress *confinement* -- that needs a network namespace or nftables
rules, documented in docs/HARDENING.md.  It is a chokepoint that makes an
unintended verb a hard error instead of a silent success.
"""
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import re
from dataclasses import dataclass

from ..errors import BackendError


@dataclass(frozen=True)
class Rule:
    method: str
    host: str
    path_re: str

    def matches(self, method: str, host: str, path: str) -> bool:
        return (
            self.method == method.upper()
            and self.host == host.lower()
            and re.fullmatch(self.path_re, path) is not None
        )


GMAIL_HOST = "gmail.googleapis.com"
OAUTH_HOST = "oauth2.googleapis.com"
GRAPH_HOST = "graph.microsoft.com"

#: Note what is absent and cannot be added at call time: no DELETE anywhere, no
#: /trash, no /send, no /sendMail, no /drafts, no /messages/batchDelete.
ALLOWED: tuple[Rule, ...] = (
    # --- Gmail ---
    Rule("GET", GMAIL_HOST, r"/gmail/v1/users/me/profile"),
    Rule("GET", GMAIL_HOST, r"/gmail/v1/users/me/labels"),
    Rule("GET", GMAIL_HOST, r"/gmail/v1/users/me/messages"),
    Rule("GET", GMAIL_HOST, r"/gmail/v1/users/me/messages/[A-Za-z0-9_-]+"),
    Rule("POST", GMAIL_HOST, r"/gmail/v1/users/me/messages/[A-Za-z0-9_-]+/modify"),
    # read the user's own filters/forwarding so a destination with a delete or
    # forward rule can be refused at startup
    Rule("GET", GMAIL_HOST, r"/gmail/v1/users/me/settings/filters"),
    Rule("GET", GMAIL_HOST, r"/gmail/v1/users/me/settings/autoForwarding"),
    Rule("GET", GMAIL_HOST, r"/gmail/v1/users/me/settings/forwardingAddresses"),
    Rule("POST", OAUTH_HOST, r"/token"),
    # --- Microsoft Graph ---
    Rule("GET", GRAPH_HOST, r"/v1\.0/me"),
    Rule("GET", GRAPH_HOST, r"/v1\.0/me/mailFolders(/.*)?"),
    Rule("GET", GRAPH_HOST, r"/v1\.0/me/messages"),
    Rule("GET", GRAPH_HOST, r"/v1\.0/me/messages/[^/]+"),
    Rule("PATCH", GRAPH_HOST, r"/v1\.0/me/messages/[^/]+"),
    Rule("POST", GRAPH_HOST, r"/v1\.0/me/messages/[^/]+/move"),
    Rule("GET", GRAPH_HOST, r"/v1\.0/me/outlook/masterCategories"),
    Rule("GET", GRAPH_HOST, r"/v1\.0/me/mailFolders/[^/]+/messageRules"),
)


def check_request(method: str, host: str, path: str) -> None:
    """Raise unless this exact (method, host, path) is on the allowlist."""
    if any(r.matches(method, host, path) for r in ALLOWED):
        return
    raise BackendError(
        f"blocked at the mailgate request chokepoint: {method.upper()} {host}{path}",
        code="request_not_allowlisted",
    )
