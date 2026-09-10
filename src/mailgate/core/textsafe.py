"""Text safety primitives.

Two jobs, and they point in OPPOSITE directions -- conflating them was a critical
finding in review:

1. ``sanitize_for_display`` makes attacker-authored text safe to render in a
   terminal (the approval TUI) or hand to an agent.  It strips, it never matches.

2. ``fold_for_ambiguity`` normalises text ONLY to *detect* that two names could be
   confused, so that startup can refuse.  Its output is never used to accept a
   match.  Allowlists match on provider ids, byte-exact.

The original design folded confusables before checking an allowlist, which means
Cyrillic 'Archive' folds onto the Latin allowlist entry and the mail is moved into
the wrong folder.  Normalisation used for acceptance widens the allowlist; used for
refusal it narrows it.
"""
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import re
import unicodedata

# C0 minus nothing (we drop even \t and \n in single-line contexts), C1, DEL.
_C0C1 = "".join(chr(c) for c in list(range(0x00, 0x20)) + [0x7F] + list(range(0x80, 0xA0)))
_CONTROL_RE = re.compile("[" + re.escape(_C0C1) + "]")

# CSI / OSC / DCS / single-shift escape sequences.
_ANSI_RE = re.compile(
    r"\x1B(?:"
    r"[@-Z\\-_]"                      # Fe two-char
    r"|\[[0-?]*[ -/]*[@-~]"           # CSI
    r"|\][^\x07\x1B]*(?:\x07|\x1B\\)" # OSC
    r"|P[^\x1B]*\x1B\\"               # DCS
    r")"
)

# Bidi overrides/embeddings/isolates and zero-width / invisible formatting.
_INVISIBLE = (
    "​‌‍⁠﻿"          # ZWSP ZWNJ ZWJ WJ BOM
    "‪‫‬‭‮"          # LRE RLE PDF LRO RLO
    "⁦⁧⁨⁩"                # LRI RLI FSI PDI
    "؜‎‏"                      # ALM LRM RLM
    "­"                                  # soft hyphen
)
_INVISIBLE_RE = re.compile("[" + re.escape(_INVISIBLE) + "]")
# Tag characters (U+E0000 block) -- invisible, used to smuggle ASCII.
_TAGCHARS_RE = re.compile(r"[\U000E0000-\U000E007F]")


def strip_invisible(text: str) -> tuple[str, int]:
    """Remove zero-width, bidi and tag characters.  Returns (text, n_removed)."""
    out, n = _INVISIBLE_RE.subn("", text)
    out, n2 = _TAGCHARS_RE.subn("", out)
    return out, n + n2


def sanitize_for_display(
    text: str,
    *,
    single_line: bool = True,
    max_len: int = 200,
) -> str:
    """Make attacker-authored text safe to put on a terminal or in a tool result.

    Strips ANSI sequences first (so a stripped control char cannot complete one),
    then control characters, then invisible/bidi formatting.  Never returns a
    string containing CR, LF or ESC.
    """
    if text is None:
        return ""
    t = _ANSI_RE.sub("", str(text))
    t, _ = strip_invisible(t)
    if single_line:
        t = _CONTROL_RE.sub(" ", t)
        t = re.sub(r"\s+", " ", t).strip()
    else:
        # keep newlines, kill everything else including CR (which redraws lines)
        t = t.replace("\r\n", "\n").replace("\r", "\n")
        t = "".join(ch if ch == "\n" else (" " if _CONTROL_RE.match(ch) else ch) for ch in t)
    if len(t) > max_len:
        t = t[: max_len - 1] + "…"
    return t


_SKELETON_MAP = {
    # A deliberately small, auditable confusable table.  Not Unicode's full
    # confusables.txt -- the goal is refusing ambiguous CONFIG, not classifying
    # arbitrary text, and a short table is reviewable.
    "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H",
    "К": "K", "М": "M", "О": "O", "Р": "P", "Т": "T",
    "Х": "X", "а": "a", "е": "e", "о": "o", "р": "p",
    "с": "c", "у": "y", "х": "x", "і": "i", "Ѕ": "S",
    "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Ι": "I",
    "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P",
    "Τ": "T", "Υ": "Y", "Χ": "X", "ο": "o", "α": "a",
    "ı": "i", "İ": "I", "ӏ": "l", "ⅼ": "l", "ⅰ": "i",
    "0": "O", "1": "l", "5": "S", "‐": "-", "‑": "-", "‒": "-",
    "–": "-", "—": "-", "−": "-", "_": "-", " ": "",
}


def fold_for_ambiguity(name: str) -> str:
    """Aggressive fold used ONLY to detect that two configured names collide.

    Never call this on a value you are about to accept.
    """
    t = unicodedata.normalize("NFKC", name)
    t, _ = strip_invisible(t)
    t = "".join(_SKELETON_MAP.get(ch, ch) for ch in t)
    return t.casefold()


def is_ascii_printable(name: str) -> bool:
    return all(0x20 <= ord(c) < 0x7F for c in name)
