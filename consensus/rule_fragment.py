"""Syntax allow-list screen for user rule fragments (Bounty 01, G1 package).

Clean-room implementation. This module was written from the audit
specification (``RIVAL-GAP-AUDIT-2026-11-27.md`` §2 + ``PR190-POSITION-CHECK-
2026-11-26.md`` §0) and from the base codebase's own rule texts -- NOT by
copying any rival PR's code. Where a design choice differs from the rival
entry, the difference is deliberate and documented below.

What it does
------------
``parse_rule_fragment`` parses ONE user rule unit against a fixed allow-list
grammar and returns its measured shape (node count, depth, max width, byte
length, streams read/written). Anything outside the grammar is refused with
``FragmentError`` before the rule is ever evaluated. ``screen_rule_fragment``
is the thin text-only wrapper in the repo's ``screen_*`` convention.

Allowed shape (the allow-list; see also ``docs/rule_fragments.md``)
--------------------------------------------------------------------
- Exactly one unit: ``always ( <expr> )`` with an optional trailing ``.``.
  ``#`` comments are stripped (``#x``/``#b`` literals preserved).
- ``<expr>``: ternary ``c ? a : b``; implication ``->``; ``||``; ``&&``;
  ``=`` / ``!=``; ``<`` / ``<=`` / ``>`` / ``>=``; ``+`` / ``-``;
  ``*`` / ``/`` / ``%``; unary ``!`` / ``-``; parentheses.
- Precedence is resolved by a FIXED TABLE (see ``_parse_*``), NOT by
  demanding parentheses around every mixed operator. Deliberate divergence
  from the rival entry: the genesis consensus rule itself mixes ``=`` and
  ``&&`` unparenthesised (``o6[t]:bv[16] = i10[t]:bv[16] && o7[t]:bv[16] =
  ...``), so a paren-mandate would refuse the chain's own genesis rule.
  The table is: ``?:`` < ``->`` < ``||`` < ``&&`` < ``=``/``!=`` <
  comparisons < ``+``/``-`` < ``*``/``/``/``%`` < unary < atoms.
- Atoms: stream ``i<N>[t]`` / ``o<N>[t]``, optionally typed ``:bv[W]``;
  braced literal ``{ <num> }:bv[W]`` (typing MANDATORY for braced
  literals); bare integer literal ONLY ``0`` or ``1``.
- Limits enforced by the PARSER: max width ``bv[384]``; paren nesting
  max 32; input/token caps (recursion guard 256). Per-rule budget limits
  (nodes / depth / bytes) are NOT enforced here -- they live in
  ``consensus/shared_rule_budget.py``, which reads ``FragmentInfo``.
- ``*`` / ``/`` / ``%`` require one CONSTANT operand (a braced literal or
  a bare 0/1); a product of two streams is refused.
- Steps other than ``[t]`` are refused with code ``TEMPORAL_REFERENCE``
  (same code the old temporal screen uses, so callers keep one meaning).

What this screen deliberately does NOT do
------------------------------------------
- It does NOT re-enforce output-width policy (``o5``/``o8`` typing): that
  stays with the existing ``screen_policy_widths`` screen, whose
  ``WIDTH_MISMATCH`` verdicts are pinned by existing tests. An untyped
  ``o13`` write, for example, is shape-valid here; the width screen (or
  the engine) decides it. The fragment screen governs SHAPE, not width
  policy.
- It does NOT accept quantifiers (``all b1 ...``): engine-generated specs
  use them, user rules do not. A quantified text is refused.
- It does NOT count nodes the way any other implementation counts them:
  the node/depth numbers here are THIS module's definition (each AST node
  = 1, the ``always`` wrapper = 1) and are pinned by
  ``tests/test_rule_fragment.py``.

Stdlib only, no engine import: admission and block apply must be able to
run this screen without a native Tau module loaded.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

RULE_FRAGMENT_CODE = "RULE_FRAGMENT"
TEMPORAL_REFERENCE_CODE = "TEMPORAL_REFERENCE"

MAX_FRAGMENT_WIDTH = 384
MAX_FRAGMENT_NESTING = 32
MAX_FRAGMENT_DEPTH = 256
MAX_FRAGMENT_CHARS = 65536
MAX_FRAGMENT_TOKENS = 2000
MAX_LITERAL_CHARS = 200

# Precedence, loosest first. Each entry is one binding level; operators on
# the same level associate left (except ternary and implication, right).
_PRECEDENCE = [
    ("ternary",),
    ("->",),
    ("||",),
    ("&&",),
    ("=", "!="),
    ("<", "<=", ">", ">="),
    ("+", "-"),
    ("*", "/", "%"),
]


class FragmentError(ValueError):
    """A rule fragment outside the allow-list.

    ``code`` is ``RULE_FRAGMENT`` except for a non-``[t]`` step, which is
    ``TEMPORAL_REFERENCE`` (the code the old temporal screen already uses).
    """

    def __init__(self, message: str, code: str = RULE_FRAGMENT_CODE):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class FragmentInfo:
    """Measured shape of one accepted rule fragment."""

    nodes: int
    depth: int
    max_width: int
    byte_len: int
    streams_read: Tuple[int, ...] = ()
    streams_written: Tuple[int, ...] = ()
    text: str = ""


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(
    r"(?P<ws>\s+)"
    r"|(?P<hex>#x[0-9a-fA-F]+)"
    r"|(?P<bin>#b[01]+)"
    r"|(?P<num>[0-9]+)"
    r"|(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"|(?P<op>->|&&|\|\||!=|<=|>=|[=<>+\-*/%!?:\[\](){}.,])"
)


@dataclass
class _Token:
    kind: str
    text: str


def _strip_comments(text: str) -> str:
    """Drop ``#`` comments while preserving ``#x``/``#b`` literals.

    Mirrors the rule in ``consensus/admission._strip_tau_comments`` (kept
    local so this module stays importable without the admission module).
    """
    out: List[str] = []
    for line in (text or "").splitlines():
        i = 0
        while i < len(line):
            ch = line[i]
            if ch != "#":
                out.append(ch)
                i += 1
                continue
            nxt = line[i + 1] if i + 1 < len(line) else ""
            if nxt in ("x", "b"):
                out.append(ch)
                i += 1
                continue
            break
        out.append("\n")
    return "".join(out)


def _tokenize(text: str) -> List[_Token]:
    if len(text) > MAX_FRAGMENT_CHARS:
        raise FragmentError(
            f"rule fragment exceeds {MAX_FRAGMENT_CHARS} characters"
        )
    tokens: List[_Token] = []
    pos = 0
    for match in _TOKEN_RE.finditer(text):
        if match.start() != pos:
            raise FragmentError(
                f"rule fragment has an unsupported character "
                f"{text[pos]!r} at offset {pos}"
            )
        pos = match.end()
        kind = match.lastgroup
        if kind == "ws":
            continue
        tokens.append(_Token(kind, match.group()))
        if len(tokens) > MAX_FRAGMENT_TOKENS:
            raise FragmentError(
                f"rule fragment exceeds {MAX_FRAGMENT_TOKENS} tokens"
            )
    if pos != len(text):
        raise FragmentError(
            f"rule fragment has an unsupported character {text[pos]!r} "
            f"at offset {pos}"
        )
    return tokens


# ---------------------------------------------------------------------------
# Parser (recursive descent over the precedence table)
# ---------------------------------------------------------------------------
# AST nodes are tuples:
#   ("always", expr) | ("bin", op, l, r) | ("un", op, e)
#   ("tern", cond, then, els) | ("stream", io, index, width|None)
#   ("const", literal_text, width)
# Parentheses create no node. Node count and depth are pure functions of
# the AST, so the budget module can recount them from stored text.

_AST = tuple


def _node_count(node: _AST) -> int:
    kind = node[0]
    if kind in ("stream", "const"):
        return 1
    if kind == "un":
        return 1 + _node_count(node[2])
    if kind == "bin":
        return 1 + _node_count(node[2]) + _node_count(node[3])
    if kind == "tern":
        return (
            1 + _node_count(node[1]) + _node_count(node[2]) + _node_count(node[3])
        )
    if kind == "always":
        return 1 + _node_count(node[1])
    raise AssertionError(f"unknown AST node {kind!r}")


def _node_depth(node: _AST) -> int:
    kind = node[0]
    if kind in ("stream", "const"):
        return 1
    if kind == "un":
        return 1 + _node_depth(node[2])
    if kind == "bin":
        return 1 + max(_node_depth(node[2]), _node_depth(node[3]))
    if kind == "tern":
        return 1 + max(
            _node_depth(node[1]), _node_depth(node[2]), _node_depth(node[3])
        )
    if kind == "always":
        return 1 + _node_depth(node[1])
    raise AssertionError(f"unknown AST node {kind!r}")


def _is_const(node: _AST) -> bool:
    return node[0] == "const"


class _Parser:
    def __init__(self, tokens: List[_Token]):
        self.tokens = tokens
        self.pos = 0
        self.nesting = 0
        self.max_width = 0
        self.reads: List[int] = []
        self.writes: List[int] = []

    # -- token helpers ------------------------------------------------------
    def _peek(self) -> Optional[_Token]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _next(self) -> _Token:
        tok = self._peek()
        if tok is None:
            raise FragmentError("unexpected end of rule fragment")
        self.pos += 1
        return tok

    def _accept(self, text: str) -> bool:
        tok = self._peek()
        if tok is not None and tok.text == text:
            self.pos += 1
            return True
        return False

    def _expect(self, text: str) -> None:
        if not self._accept(text):
            tok = self._peek()
            got = tok.text if tok is not None else "end of input"
            raise FragmentError(
                f"expected {text!r} in rule fragment, found {got!r}"
            )

    # -- entry point --------------------------------------------------------
    def parse_unit(self) -> _AST:
        tok = self._next()
        if tok.kind != "name" or tok.text != "always":
            raise FragmentError(
                "a rule fragment must be exactly one 'always ( ... )' unit"
            )
        self._expect("(")
        self.nesting += 1
        if self.nesting > MAX_FRAGMENT_NESTING:
            raise FragmentError(
                f"rule fragment nests deeper than {MAX_FRAGMENT_NESTING}"
            )
        expr = self._parse_ternary()
        self.nesting -= 1
        self._expect(")")
        self._accept(".")
        if self._peek() is not None:
            raise FragmentError(
                "a rule fragment must be exactly one 'always ( ... )' unit; "
                "trailing input is not allowed"
            )
        return ("always", expr)

    # -- expressions ----------------------------------------------------------
    def _parse_ternary(self) -> _AST:
        cond = self._parse_binary(1)
        if self._accept("?"):
            then = self._parse_ternary()
            self._expect(":")
            els = self._parse_ternary()
            return ("tern", cond, then, els)
        return cond

    def _parse_binary(self, level: int) -> _AST:
        """Parse one precedence level (levels index into _PRECEDENCE)."""
        if level >= len(_PRECEDENCE):
            return self._parse_unary()
        ops = _PRECEDENCE[level]
        if ops == ("ternary",):
            return self._parse_binary(level + 1)
        node = self._parse_binary(level + 1)
        if ops == ("->",):
            # Implication associates right.
            if self._peek() is not None and self._peek().text == "->":
                self._next()
                rhs = self._parse_binary(level)
                return ("bin", "->", node, rhs)
            return node
        while self._peek() is not None and self._peek().text in ops:
            op = self._next().text
            rhs = self._parse_binary(level + 1)
            if op in ("*", "/", "%") and not (
                _is_const(node) or _is_const(rhs)
            ):
                raise FragmentError(
                    f"operator {op!r} requires one constant operand; "
                    "a product/quotient of two streams is not allowed"
                )
            node = ("bin", op, node, rhs)
        return node

    def _parse_unary(self) -> _AST:
        tok = self._peek()
        if tok is not None and tok.text in ("!", "-"):
            self._next()
            return ("un", tok.text, self._parse_unary())
        return self._parse_atom()

    # -- atoms ----------------------------------------------------------------
    def _parse_width(self) -> Optional[int]:
        """Parse an optional ``:bv[W]`` suffix; returns W or None."""
        if not self._accept(":"):
            return None
        tok = self._next()
        if tok.kind != "name" or tok.text != "bv":
            raise FragmentError(
                "a type suffix must be ':bv[W]', e.g. ':bv[24]'"
            )
        self._expect("[")
        num = self._next()
        if num.kind != "num":
            raise FragmentError("a type suffix must be ':bv[W]' with a number width")
        width = int(num.text)
        self._expect("]")
        if width < 1 or width > MAX_FRAGMENT_WIDTH:
            raise FragmentError(
                f"bitvector width bv[{width}] exceeds the maximum "
                f"bv[{MAX_FRAGMENT_WIDTH}]"
            )
        if width > self.max_width:
            self.max_width = width
        return width

    def _parse_stream(self, name: str) -> _AST:
        # name is [io]<digits>; anything else is not a stream at all.
        if not re.fullmatch(r"[io]\d+", name):
            raise FragmentError(
                f"rule references unknown stream '{name}'; only i<N> inputs "
                "and o<N> outputs may be indexed"
            )
        self._expect("[")
        # The step is read as raw tokens up to ']' so '[t-1]' reports as
        # one non-current step (TEMPORAL_REFERENCE), not as a stray '-'.
        step_parts = []
        while True:
            tok = self._next()
            if tok.text == "]":
                break
            step_parts.append(tok.text)
        step = "".join(step_parts)
        if step != "t":
            raise FragmentError(
                f"rule reads a step other than the current one ([{step}]); "
                "user rules may reference [t] only",
                code=TEMPORAL_REFERENCE_CODE,
            )
        width = self._parse_width()
        io, index = name[0], int(name[1:])
        if io == "i":
            if index not in self.reads:
                self.reads.append(index)
        else:
            if index not in self.writes:
                self.writes.append(index)
        return ("stream", io, index, width)

    def _check_literal_fits(self, literal: str, width: int) -> None:
        if len(literal) > MAX_LITERAL_CHARS:
            raise FragmentError("a literal exceeds the maximum length")
        try:
            if literal.startswith("#x"):
                value = int(literal[2:], 16)
            elif literal.startswith("#b"):
                value = int(literal[2:], 2)
            else:
                value = int(literal, 10)
        except ValueError:
            raise FragmentError(f"unsupported literal {literal!r}")
        if value >= (1 << width):
            raise FragmentError(
                f"literal {literal!r} does not fit in bv[{width}]"
            )

    def _parse_braced_literal(self) -> _AST:
        self._expect("{")
        tok = self._next()
        if tok.kind not in ("hex", "bin", "num"):
            raise FragmentError(
                "a braced literal must contain a number, e.g. '{ 1 }' or "
                "'{ #x000001 }'"
            )
        literal = tok.text
        self._expect("}")
        # A braced constant MUST be typed: '{ 100 }' without ':bv[W]' is
        # refused here (the old width screen never saw it as typed either).
        width = self._parse_width()
        if width is None:
            raise FragmentError(
                f"braced literal '{{ {literal} }}' must carry a type, "
                "e.g. '{ 100 }:bv[64]'"
            )
        self._check_literal_fits(literal, width)
        return ("const", literal, width)

    def _parse_atom(self) -> _AST:
        tok = self._next()
        if tok.text == "(":
            self.nesting += 1
            if self.nesting > MAX_FRAGMENT_NESTING:
                raise FragmentError(
                    f"rule fragment nests deeper than {MAX_FRAGMENT_NESTING}"
                )
            node = self._parse_ternary()
            self.nesting -= 1
            self._expect(")")
            return node
        if tok.text == "{":
            self.pos -= 1  # rewind: _parse_braced_literal expects '{'
            return self._parse_braced_literal()
        if tok.kind == "num":
            # Bare integer literals: only 0 and 1 may stand untyped.
            if tok.text not in ("0", "1"):
                raise FragmentError(
                    f"bare integer literal {tok.text!r} must be written "
                    "typed, e.g. '{ 7 }:bv[24]'"
                )
            return ("const", tok.text, None)
        if tok.kind == "name":
            return self._parse_stream(tok.text)
        raise FragmentError(f"unexpected token {tok.text!r} in rule fragment")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_rule_fragment(rule_text: str) -> FragmentInfo:
    """Parse one rule fragment against the allow-list.

    Raises ``FragmentError`` (with ``.code``) on anything outside the
    grammar. On success returns the fragment's measured shape.
    """
    if not isinstance(rule_text, str) or not rule_text.strip():
        raise FragmentError("an empty rule fragment is not allowed")
    cleaned = _strip_comments(rule_text)
    tokens = _tokenize(cleaned)
    if not tokens:
        raise FragmentError("an empty rule fragment is not allowed")
    parser = _Parser(tokens)
    ast = parser.parse_unit()
    nodes = _node_count(ast)
    depth = _node_depth(ast)
    if depth > MAX_FRAGMENT_DEPTH:
        raise FragmentError(
            f"rule fragment depth {depth} exceeds the parser limit "
            f"{MAX_FRAGMENT_DEPTH}"
        )
    return FragmentInfo(
        nodes=nodes,
        depth=depth,
        max_width=parser.max_width,
        byte_len=len(rule_text.encode("utf-8")),
        streams_read=tuple(sorted(parser.reads)),
        streams_written=tuple(sorted(parser.writes)),
        text=rule_text,
    )


def screen_rule_fragment(rule_text: str) -> Optional[str]:
    """Error text when ``rule_text`` is outside the syntax allow-list.

    Returns ``None`` when the fragment is allowed. Thin wrapper over
    :func:`parse_rule_fragment` for callers that only need the text (the
    repo's ``screen_*`` convention); callers that need the rejection code
    should call ``parse_rule_fragment`` and catch ``FragmentError``.
    """
    try:
        parse_rule_fragment(rule_text)
    except FragmentError as exc:
        return str(exc)
    return None
