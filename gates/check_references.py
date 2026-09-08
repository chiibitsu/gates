#!/usr/bin/env python3
# Part of chiibitsu/gates by Angeline S. Viray (Chiibitsu Labs). MIT. https://github.com/chiibitsu/gates
"""Tier 1 gate: every in-repo path cited in the docs must resolve.

This whole OS runs on agents following file references. `docs/04` tells a session to
read `templates/incident.md`; a charter points at `canon/decisions.md`. When one of
those paths goes stale, nothing errors — the agent just reads nothing and carries on
with a quieter, wronger picture of the company. That is the aikiri-garden failure
class (an AGENTS.md nothing opened) in a different costume, and it is invisible to
every other kind of review.

## Scope, deliberately narrow

Two things are checked: **backticked paths** (`templates/incident.md`) and **simple
inline links** (`](path)` with nothing exotic in the destination).

It used to contain a full hand-rolled markdown parser. That was deleted after six
review rounds, on evidence: this repo has ~400 backticked paths against 24 links, and
the parser alone accounted for eight findings — nested labels, quoted titles holding
parentheses, multiline definitions, percent-decoding versus fragment order, quadratic
backtracking on unmatched brackets. It was competing with real CommonMark
implementations and losing.

Deleting it outright went too far, though: the 24 links are real ones — `canon/voice.md`
into `canon/voice/`, `patterns/README.md`, `docs/00-thesis.md` — and renaming a target
would break navigation silently, which is precisely this gate's job. So the simple
form is checked with a regex that makes no claim to parse markdown, and **anything it
cannot parse is reported as UNCHECKED rather than passed**. The run prints how many
of BOTH it validated, so "OK" can never quietly mean "parsed almost nothing" — for
most of this file's life that promise was kept only for the 24 links while the ~400
backticked paths, the surface the gate primarily exists for, were counted nowhere.

If richer link checking is ever needed, the answer is a mature markdown linter, not
more regex here.

.ci-allowed-refs holds deliberate exceptions, one per line, in TWO sections that mean
different things — this paragraph described only the first for the file's whole life.

  Section 1, permanent: paths another repo owns, like `product/specs/`. They will
  never exist here and are expected to stay listed forever.

  Section 2, after the `#!debt` marker: paths this repo has PROMISED and not yet
  built, like `team/auditor.md`. These are tracked debt, not exemptions — the
  retirement check below fails the run when one of them starts existing, so the entry
  gets removed rather than quietly outliving its reason.

Neither section is a silencer. A genuinely broken in-repo path belongs in neither.
"""

import os
import re
import stat
import urllib.parse
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_REAL = os.path.realpath(REPO)

# Top-level directories this repo actually owns. A backticked path is only treated as
# a repo reference if it starts with one of these — otherwise `npm test` and
# `git push` would read as broken paths.
OWNED = (
    # .github joined when tier1.yml landed there and ops/tasks.md began citing it —
    # an owned directory absent from this tuple means renaming its files leaves the
    # documentation stale while the gate still reports success.
    ".github/","canon/", "docs/", "ops/", "patterns/", "product/", "team/", "templates/", "scripts/")

# Not real paths: globs, placeholders, and template variables.
UNRESOLVABLE = re.compile(r"[*?<>{}]|YYYY|MM-DD|\.\.\.|\$")

# Any URI scheme or protocol-relative reference — not a filesystem path.
EXTERNAL_URI = re.compile(r"^(?:[A-Za-z][A-Za-z0-9+.\-]*:|//)")

BACKTICKED = re.compile(r"`([^`\n]+)`")

# The surrogate range Python's surrogateescape handler uses for a byte that would not
# decode. Same two constants and the same predicate as check_secrets.py, deliberately
# duplicated for the same reason SECRETISH is: this file is vendored on its own.
UNDECODABLE_LOW, UNDECODABLE_HIGH = "\udc80", "\udcff"


def _undecodable(ch):
    return UNDECODABLE_LOW <= ch <= UNDECODABLE_HIGH

# Simple inline links only: `](destination)` with no whitespace, quotes or nesting in
# the destination. Deliberately NOT a markdown parser — the hand-rolled CommonMark
# attempt this replaced produced eight review findings and caught nothing. But the
# repo does contain ~24 real local links (canon/voice.md to its voice/ files,
# patterns/README.md, docs/00-thesis.md), and renaming one of those targets would
# break navigation silently, which is exactly this gate's job.
#
# Anything more elaborate is counted as UNCHECKED and reported, never silently
# passed — a link this cannot parse is a link nobody validated, and the run says so.
#
# The two patterns are built from ONE destination class rather than written twice.
# They are exact complements by construction — "simple" and "not simple" — and the
# only way to keep them so is to give the grammar one owner. Written out separately
# they drifted the moment the class changed, which is how a destination could be
# neither simple nor complex and so reach none of the three outcomes.
#
# A BACKSLASH is excluded along with the parens. `[x](foo\)bar)` is a valid link to
# `foo)bar`, but the class stopped at the escaped paren and handed back `foo\` — a
# parsed target that was never the destination, failing the gate on correct markdown.
# Deciding what an escape means requires the CommonMark parser this deliberately is
# not, so an escaped destination is UNCHECKED and reported, which is the honest
# outcome for a link nobody validated.
_SIMPLE_DEST = r"[^()\s\"'\\]+"
SIMPLE_LINK = re.compile(r"\]\((" + _SIMPLE_DEST + r")\)")
COMPLEX_LINK = re.compile(r"\]\((?!" + _SIMPLE_DEST + r"\))")

DOC_SHORTHAND = re.compile(r"^docs/(\d{2})$")

# Case-insensitive, and both spellings. A broken link inside `GUIDE.MD` is exactly as
# broken as one inside `guide.md`, but a case-sensitive filter skipped the file
# entirely while the gate still claimed every reference resolved.
MARKDOWN_SUFFIXES = (".md", ".markdown")

# The allowlist is a short hand-written list; a megabyte is four orders of magnitude
# more than it has ever needed and still bounds a hostile one.
ALLOWLIST_BUDGET = 1 << 20


# Credential shapes, for REDACTION only — this gate does not detect secrets, it just
# must not become the thing that publishes one. A broken link or a stale path can carry
# a key in its text, and this checker runs BEFORE check_secrets.py in CI, so printing
# destinations verbatim copied the leak into the log before the withholding-aware gate
# ever ran. Kept deliberately compact and duplicated rather than imported: this file is
# vendored into consumer repos on its own.
SECRETISH = re.compile(
    r"(sk-ant-[A-Za-z0-9_\-]{20,}|sk-(?:proj-)?[A-Za-z0-9_-]{40,}"
    r"|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,}"
    r"|xox[abposr]-[A-Za-z0-9-]{10,}|xapp-[0-9]-[A-Za-z0-9-]{10,}"
    r"|AIza[0-9A-Za-z_\-]{35}|(?:AKIA|ASIA)[0-9A-Z]{16}"
    r"|(?:sk|rk)_live_[A-Za-z0-9]{20,}|sb_secret_[A-Za-z0-9_\-]{20,}"
    # Postgres URLs were missing from this copy while check_secrets.py had them, so a
    # broken backticked ref carrying a database URL printed its password verbatim. The
    # example that belongs here is omitted deliberately: writing one made check_secrets
    # flag THIS file, which is its documented doctrine working — a credential-shaped
    # literal in a comment is still a credential-shaped literal. A hand-maintained
    # duplicate of a pattern list drifts by default, so keep the two in step by hand.
    r"|(?i:postgres(?:ql)?)://[^\s:]+:[^\s@]+@"
    r"|eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"
    # PEM armor was the SECOND family found missing from this copy in as many
    # rounds. Two drifts is not bad luck, it is what a hand-maintained duplicate
    # does — so `python3 scripts/check_secrets.py --selftest` now compares the two
    # lists and fails if either grows a family the other lacks.
    r"|-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----)")


def _escape_controls(text):
    """Render control characters visibly so printed text cannot forge log structure.

    UNDECODABLE BYTES TOO, which this copy did not do while check_secrets.py's
    identically-named function has since round 74. os.walk and os.fsdecode carry a
    non-UTF-8 filename byte as a lone surrogate, and this file prints filenames — so
    a tracked `docs/caf<0xe9>.md` with any finding in it wrote the raw byte into the
    CI log where the sibling writes `\\xe9`, and, wherever stdout's error handler is
    strict rather than surrogateescape, raised UnicodeEncodeError instead: a required
    gate ending in a traceback where a verdict belongs.

    That second half is latent — every runner locale I could test coerces to
    surrogateescape, so it does not fire today. It is fixed anyway. "The cost of
    closing this was never re-checked after the surface that made it cheap was built"
    is a mistake already recorded twice in the sibling file's header, and the fix is
    four lines that were written there two years of rounds ago.
    """
    out = []
    for ch in text:
        if "\ud800" <= ch <= "\udfff":
            # \udc80-\udcff is a byte that failed to decode, restored as itself.
            # Anything else in the surrogate range reaches print() unencodable too,
            # and a bare `else` that assumes no path produces one is how the first
            # of these got in.
            out.append(f"\\x{ord(ch) - 0xDC00:02x}" if _undecodable(ch)
                       else f"\\u{ord(ch):04x}")
        elif ch >= " " and ch != "\x7f":
            out.append(ch)
        else:
            out.append({"\n": "\\n", "\r": "\\r", "\t": "\\t"}.get(
                ch, f"\\x{ord(ch):02x}"))
    return "".join(out)


def redact(text):
    """Redact credential shapes, then escape control characters.

    This checker prints paths, and a path may contain a newline. Put one before
    `::warning::` and the fragment lands at column zero of the CI log, where the
    runner reads it as a workflow command — repository content forging annotations in
    the job auditing it. check_secrets.py has the same guard in the same place; both
    files print paths, so both need it, and fixing only the one that was reported is
    the habit this PR keeps finding.
    """
    return _escape_controls(SECRETISH.sub("<redacted>", text))


def load_allowlist():
    """Return (permanent, debt) exception sets.

    Section 1 entries are permanent — paths another repo owns, which will never
    resolve here. Section 2 entries are DEBT: things canon promises and the repo
    does not have yet. The difference matters, because a debt entry that starts
    resolving is a silencer: once `team/auditor.md` exists, an unconditional skip
    leaves it permanently unprotected, so a later rename or deletion passes
    unnoticed — the exact failure this gate exists to catch, wearing the gate's
    own allowlist as cover.
    """
    path = os.path.join(REPO, ".ci-allowed-refs")
    permanent, debt = set(), set()
    if not os.path.exists(path):
        return permanent, debt
    # REGULAR, CONTAINED, BOUNDED — and this runs before every guarded reader in the
    # file, which is exactly why it was the one left unguarded. `.ci-allowed-refs ->
    # /dev/zero` passed os.path.exists() and the checker consumed a line that never
    # ends until the runner killed it: no verdict, the same hang the scanner had, in
    # the function that runs first. Every document reader below learned this lesson;
    # the allowlist loader predates them and nobody went back.
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode) or not _inside_repo(path):
            print("references: .ci-allowed-refs is not a contained regular file — "
                  "refusing to read it", file=sys.stderr)
            return permanent, debt
    except OSError:
        return permanent, debt
    bucket, saw_marker = permanent, False
    with open(path, encoding="utf-8", errors="replace") as handle:
        # read() with a cap, not iteration: iterating a pathological file yields one
        # unbounded "line".
        #
        # One character PAST the budget, so the cap can tell "exactly full" from
        # "overflowed" — read(BUDGET) alone cannot. An allowlist that overflowed used
        # its prefix silently, and the quiet half is the dangerous one: a cut through
        # a line leaves a SHORTER path that is still a valid allowance, so
        # `team/auditor.md.bak` truncates to `team/auditor.md` and permanently
        # exempts a file nobody allowed. Dropping later entries only costs false
        # BROKEN reports, which are loud; inventing an allowance is silent, and it
        # disables the gate on exactly the path it invents.
        blob = handle.read(ALLOWLIST_BUDGET + 1)
    if len(blob) > ALLOWLIST_BUDGET:
        raise SystemExit(
            "references: .ci-allowed-refs is larger than "
            f"{ALLOWLIST_BUDGET >> 20} MiB and was not read in full.\n"
            "Refusing to run against a partial allowlist: a line cut by the budget\n"
            "can leave a shorter path that still reads as a valid allowance, which\n"
            "would exempt a file nobody allowed. Shrink the file or raise\n"
            "ALLOWLIST_BUDGET deliberately."
        )
    for line in blob.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            # A machine-readable marker, not the human heading. Rewording the
            # prose heading used to silently reclassify every debt entry as
            # permanent, which disables the retirement check without any sign.
            if stripped == "#!debt":
                bucket, saw_marker = debt, True
            continue
        if stripped:
            bucket.add(stripped)
    if not saw_marker:
        raise SystemExit(
            "references: .ci-allowed-refs has no `#!debt` marker line.\n"
            "Without it, debt entries are indistinguishable from permanent ones and\n"
            "the retirement check silently stops working. Add `#!debt` on its own\n"
            "line above the promised-but-missing paths."
        )
    return permanent, debt


def _inside_repo(path):
    real = os.path.realpath(path)
    return real == REPO_REAL or real.startswith(REPO_REAL + os.sep)


# Same bound the secret scanner applies to its two readers. A generated or
# accidentally committed single-line document would otherwise be materialised whole
# by ordinary iteration, in the FIRST required CI gate.
MD_CHUNK = 65536
MD_LINE_BUDGET = 4 << 20


def _bounded_md_lines(handle, rel, unchecked_links):
    """Yield (lineno, line, truncated). `truncated` means the line was CUT.

    The flag exists because the cut prefix was handed to the ordinary link parser,
    which then classified constructs using syntax the cut had removed: a code span
    opened before the budget and closed after it lost its closing backtick, so a
    demonstration link inside it read as navigation and the gate reported a BROKEN
    reference — on a line the same run had already recorded as NOT validated. A
    blocking failure derived from text the reader admits it did not finish is the
    coverage lie in its most direct form: the two statements contradict each other in
    one report.
    """
    buf, lineno, over = "", 0, False
    while True:
        block = handle.read(MD_CHUNK)
        if not block:
            break
        if over:
            # Discard while over budget rather than appending — the old form let the
            # remainder of a newline-free document accumulate in full, so the stated
            # bound was not a bound. Same defect in all three readers.
            idx = block.find("\n")
            if idx == -1:
                continue
            buf, over = block[idx + 1:], False
            lineno += 1
        else:
            buf += block
        while "\n" in buf:
            line, buf = buf.split("\n", 1)
            lineno += 1
            # The budget has to be enforced HERE, not only on the trailing
            # remainder below. A line longer than the budget whose newline lands in
            # the same chunk never reaches that check: it is split off complete and
            # was yielded as fully validated, so the one document shape the bound
            # exists to refuse — a multi-megabyte single line — was the shape that
            # sailed through it. Being *complete* is not the point; the budget
            # bounds how much text the link parser is asked to scan, and a complete
            # 4 MiB line costs exactly what a cut one does.
            if len(line) > MD_LINE_BUDGET:
                unchecked_links.append(
                    (rel, lineno,
                     f"line over {MD_LINE_BUDGET >> 20} MiB — NOT validated"))
                yield lineno, line[:MD_LINE_BUDGET], True
                continue
            yield lineno, line, False
        if len(buf) > MD_LINE_BUDGET:
            unchecked_links.append(
                (rel, lineno + 1,
                 f"line over {MD_LINE_BUDGET >> 20} MiB — NOT validated"))
            yield lineno + 1, buf, True
            buf, over = "", True
    if buf and not over:
        yield lineno + 1, buf, False


def markdown_files():
    # os.walk's default onerror is to SWALLOW the error and omit the whole subtree, so
    # a directory this process cannot enter took every document under it out of the
    # input set without a word — a checkout with one mode-000 directory printed
    # "references: OK" with zero links checked, which is the maximum possible coverage
    # lie: total silence read as a clean bill.
    #
    # The unreadable directory is yielded as an input like any other, so it lands in
    # the same unchecked reporting the unreadable-FILE branches use. Walking cannot
    # continue into it — that is what the error means — but saying so costs one line
    # and is the difference between "checked nothing" and "claimed everything".
    walk_errors = []

    def drain():
        # Drained at the TOP of each iteration and again after the loop. os.walk
        # reports a failure when it tries to descend, which can be the last thing it
        # does — a top-of-loop drain alone loses the error for the final directory,
        # which is the one case where the whole remaining subtree is unreported.
        while walk_errors:
            err = walk_errors.pop()
            yield (err.filename or REPO), (
                f"directory could not be read ({type(err).__name__}) — "
                "SUBTREE NOT WALKED")

    for root, dirs, files in os.walk(REPO, onerror=walk_errors.append):
        yield from drain()
        # A .md symlink pointing at a DIRECTORY lands in `dirs`, not `files`, so the
        # containment filter below removed it before the reporting branch could see
        # it — an out-of-repo docs/host.md vanished from the input set and the run
        # still claimed OK. Report those before pruning.
        # EVERY directory symlink, not only ones whose own name ends in .md. The
        # suffix test was written for `docs/host.md -> /elsewhere`, and it reported
        # exactly that shape while `manuals -> /external/docs` — the ordinary way
        # anyone actually names a linked directory — was pruned in silence with every
        # document beneath it. A checker that only notices the badly-named case is
        # reporting the example it was written from, not the class.
        #
        # os.walk does not follow directory symlinks at all, so this is not "some
        # were skipped": NO directory symlink's contents are ever read. That is the
        # deliberate choice — following one leaves the checkout and can loop — and it
        # is therefore something to state on every occurrence rather than to detect.
        for d in list(dirs):
            p = os.path.join(root, d)
            if os.path.islink(p):
                yield p, ("directory symlink — target NOT entered"
                          if _inside_repo(p)
                          else "directory symlink resolving outside the repo"
                               " — target NOT entered")
        dirs[:] = [d for d in dirs
                   if d not in (".git", "node_modules")
                   and not os.path.islink(os.path.join(root, d))
                   and _inside_repo(os.path.join(root, d))]
        for name in files:
            if not name.lower().endswith(MARKDOWN_SUFFIXES):
                continue
            path = os.path.join(root, name)
            # A tracked .md that is a symlink out of the checkout would be opened
            # from the runner, not the commit — `docs/host.md -> /dev/zero` hangs the
            # gate outright, and an ordinary host file makes the verdict depend on
            # the machine. check_secrets.py already refused these; this did not.
            if not _inside_repo(path):
                # REPORTED, not dropped. Silently removing the document from the
                # input set made "no broken paths" a claim about a smaller repo than
                # the one on disk — the coverage lie this gate exists to prevent,
                # committed by the gate itself.
                yield path, "symlink resolves outside the repo — NOT read"
                continue
            if os.path.islink(path):
                # An in-repo .md symlink is read through, but relative links inside
                # the TARGET resolve from the LINK's directory — so `alias.md ->
                # docs/real.md` made every relative link in docs/real.md resolve
                # against the repo root and the gate went red on working navigation.
                # The target is itself a tracked document and is validated at its own
                # path, so nothing is lost by declining this one; what is gained is
                # not inventing a source directory the content was never written for.
                yield path, "markdown symlink — validated at its target's own path"
                continue
            yield path, None
    yield from drain()


# CROSS-LINE CONTEXT TRACKING IS GONE. What follows is line-local and stateless.
#
# There were three trackers here — fenced blocks, HTML comments, and code spans —
# added over rounds 50 to 62 so that documentation demonstrating markdown syntax
# would not turn a required gate red. Rounds 63 and 64 then produced SEVEN findings,
# every one of them an interaction BETWEEN the trackers rather than a defect in any
# one: a comment opener inside a code span, a fence inside a comment, a comment
# inside a fence, a quoted fence outliving its quote, a closer at the wrong quote
# depth, a code span crossing lines. Each fix created the next seam.
#
# So I counted. Across every markdown file in this repository there are 27
# link-shaped matches, and ZERO of them are inside a fence, a comment, or a code
# span. The machinery that produced seven findings in two rounds was protecting
# against a case that does not occur once here.
#
# Line-local rules survive — an escaped `\]`, and a match inside a backticked span
# ON THE SAME LINE — because they carry no state and therefore cannot interact. The
# fence and comment trackers are deleted rather than fixed a seventh time.
#
# The cost, stated: a multi-line fenced example containing `](path)` will now be
# validated, and if the path does not exist the gate goes red. That is a false red,
# which this file treats as serious. The mitigation is the one that already exists
# for deliberate exceptions — .ci-allowed-refs — and the fact that it has never been
# needed for this. If that changes, the answer is a real markdown parser, not a
# fourth attempt at half of one.


def _demonstration_context(text, start):
    """Why this `](...)` is not navigation, or None if it is a real link.

    Two contexts, both verified to produce a FALSE RED today: a backslash-escaped
    `]`, and a match inside a code span. Documentation that demonstrates markdown
    syntax hits both, and a required gate going red for a destination markdown never
    renders is the failure that teaches people to merge past it.

    Reported as UNCHECKED rather than dropped. Detecting a code span by reusing
    BACKTICKED is a heuristic — it is line-local, it does not know about fences, and
    this file deleted a hand-rolled markdown parser after six rounds precisely to stop
    making claims like that. So the honest outcome is "this looks like a
    demonstration, nobody validated it", not "this is fine".
    """
    # Odd number of preceding backslashes = the "]" is escaped. Even = the
    # backslashes are themselves escaped and the link is real, which is why this
    # counts rather than testing text[start-1].
    slashes = 0
    i = start - 1
    while i >= 0 and text[i] == "\\":
        slashes += 1
        i -= 1
    if slashes % 2:
        return "escaped `](…)` — demonstration syntax, NOT validated"
    # An escaped OPENING bracket makes the whole thing literal text too, and markdown
    # renders no link at all — so `\[example](missing.md)` was reported broken for a
    # destination nothing navigates to. I checked the escape before `]` and not the
    # one before `[`, which is the same half-a-pair habit this PR keeps finding, in
    # the two characters that bracket the construct.
    opener = text.rfind("[", 0, start)
    if opener > 0:
        slashes = 0
        i = opener - 1
        while i >= 0 and text[i] == "\\":
            slashes += 1
            i -= 1
        if slashes % 2:
            return "escaped `[…](…)` — demonstration syntax, NOT validated"
    for span in BACKTICKED.finditer(text):
        if span.start() < start < span.end():
            return "`](…)` inside a code span — demonstration syntax, NOT validated"
    return None


def link_refs(text):
    """Yield (destination, unparseable_reason) for inline links on one line.

    The second element used to be an is_parseable boolean, which forced every
    non-link into one message. It carries the reason now, for the same reason
    markdown_files() started carrying one: a fixed string is a wrong explanation as
    soon as there is a second way to reach it.
    """
    for match in SIMPLE_LINK.finditer(text):
        demo = _demonstration_context(text, match.start())
        if demo:
            yield None, demo
            continue
        target = match.group(1).strip()
        # Unwrap `<dest>`. Left wrapped, the angle brackets hit UNRESOLVABLE later and
        # the link was dropped in silence — neither resolved nor reported unchecked,
        # so a missing destination could print OK. Silence is the one outcome this
        # gate must never produce.
        if target.startswith("<") and target.endswith(">"):
            target = target[1:-1].strip()
        # Strip query and split off the fragment. A query made `?` reach the glob
        # heuristic, which dropped the link in silence — neither resolved nor
        # reported unchecked, so a missing file could still print OK.
        path_part, _, fragment = target.partition("#")
        path_part = path_part.split("?", 1)[0].strip()
        if not path_part and not fragment:
            # `[view](?view=1)`, `[top](#)` and `[x]()` have neither a path nor a
            # fragment once the query is stripped, so BOTH branches below missed
            # them and they reached none of the three outcomes. The fourth outcome
            # again — reintroduced by the very split that was written to close it,
            # one round after I called the invariant structurally sound. Yield the
            # raw destination so main() can report it.
            yield target, None
            continue
        if not path_part and fragment:
            # Fragment-only link: an anchor into this same document. Discarding it
            # made `target` empty, so it reached none of the three outcomes — a
            # FOURTH, in the very commit that claimed there wasn't one. Rename the
            # heading and the gate still said OK.
            yield "#" + fragment.strip(), None
            continue
        if path_part and not EXTERNAL_URI.match(path_part):
            yield path_part, None
            if fragment:
                # A cross-file anchor is exactly as unvalidated as a same-file one,
                # and discarding it here made the stated policy false for half the
                # cases: `docs/x.md#stale` counted the file as checked and never
                # mentioned the anchor. Symmetry, in the honest direction.
                yield "#" + fragment.strip(), None
    for match in COMPLEX_LINK.finditer(text):
        yield None, (_demonstration_context(text, match.start())
                     or "complex syntax")


def undecoded_reason(target):
    """Why this reference text is not the reference that was written, or None.

    Documents are read with errors="replace", so a byte that did not decode arrives
    as U+FFFD. The line is already recorded as "read with replacement" — and then the
    reference derived from it was resolved anyway, so a CORRECT citation of an
    existing `docs/café.md` from a Latin-1 document was reported BROKEN. The two
    statements sat in one report: the line was NOT validated, and the line failed the
    build.

    That is exactly the contradiction round 79 removed for a truncated line, in the
    neighbouring branch of the same loop, one round later. The fix there was to derive
    no reference from text the reader admits it could not finish; the same rule
    applies to text it admits it could not decode.

    PER-REFERENCE, not per-line — the working-tree judge in check_secrets.py made this
    call already: "an ambiguous match does not make the line unjudgeable, only that
    match." Replacement only ever consumes a non-ASCII byte, so backticks and `](` are
    untouched and a clean ASCII reference beside a mangled one is still fully checked.

    One owner, because both the link branch and the backticked branch need it and this
    file's whole history is fixes that landed on one half of a pair.
    """
    if "\ufffd" in target:
        return ("replacement character in the path — the source line did not decode, "
                "so this is not the text that was written; NOT validated")
    return None


def candidate_refs(text):
    """Yield (path, fragment) for backticked in-repo paths worth resolving.

    The fragment used to be dropped here with `split("#")[0]` and never mentioned
    again, so `docs/04#heading-that-does-not-exist` resolved through the docs/04
    shorthand and counted toward an unqualified OK while the section it named was
    never looked for. Markdown links have reported their anchors as unchecked since
    round 30; the backticked branch quietly did not, which is the same silent fourth
    outcome this file keeps rediscovering in a place it had not looked.
    """
    for match in BACKTICKED.finditer(text):
        target = match.group(1).strip()
        # Strip an explicit relative prefix before the owned-directory test.
        # `./docs/x.md` and `../templates/x.md` are unambiguously in-repo, but
        # neither starts with an OWNED entry, so without this they were skipped
        # in silence — the gate staying green on a genuinely broken path.
        # `./` is stripped; `../` is NOT. Erasing both made traversal meaningless:
        # `docs/page.md` citing `../../templates/incident.md` escapes the checkout
        # when rendered, but stripping the prefixes left `templates/incident.md`,
        # which exists at the root, so the gate reported OK for a path that does not
        # resolve for any reader. `./` is a no-op prefix and normalising it is safe;
        # `..` is an instruction, and the containment test in resolve() is what
        # answers it.
        probe = target
        while probe.startswith("./"):
            probe = probe[2:]
        escaping = probe.startswith("../")
        eligible = probe
        while eligible.startswith("../"):
            eligible = eligible.split("/", 1)[1] if "/" in eligible else ""
        # Only directory-qualified paths. A bare `CLAUDE.md` or `AGENTS.md` is almost
        # always a generic mention ("every repo needs a CLAUDE.md") or a file in a
        # product repo, not a path into this one — matching those made the gate red
        # on 30-odd non-problems, and a gate that cries wolf gets merged past.
        if eligible.startswith(OWNED):
            # Yield the NORMALISED form. The prefix was stripped for the eligibility
            # probe only, so `./docs/04` passed the gate here and then failed both
            # shorthand resolution and the allowlist lookup downstream, which match
            # on repo-rooted text. Normalising in one place and yielding another was
            # the whole bug.
            # Yield the TRAVERSING form untouched so resolve() can reject it; yield
            # the normalised form otherwise, because the allowlist and the docs/NN
            # shorthand are both written repo-rooted.
            path, _, fragment = (probe if escaping else eligible).partition("#")
            yield path, fragment


def resolve(source_file, target, kind="path"):
    """True if the path points at something that exists inside this repo."""
    # `docs/04` is the house shorthand for docs/04-audit-protocol.md — the number is
    # the stable identity, the slug is not. Resolve by prefix so renaming a doc's
    # slug doesn't turn every citation of it red.
    # Shorthand applies to BACKTICKED repo-rooted paths only. A markdown link
    # resolves relative to its own document, so `[audit](docs/04)` written in
    # team/x.md means team/docs/04 — accepting any root-level docs/04-* there
    # marked a genuinely broken navigation link as checked. No link in this repo
    # uses the shorthand, so this narrows the rule without breaking anything.
    shorthand = DOC_SHORTHAND.match(target) if kind != "link" else None
    if shorthand:
        prefix = shorthand.group(1) + "-"
        docs_dir = os.path.join(REPO, "docs")
        # listdir() on a missing docs/ raised and took the gate down instead of
        # reporting the reference broken, and this branch skipped the realpath
        # containment every other one applies — so a docs/ symlinked outside the
        # checkout let a host file satisfy an in-repo citation.
        if not _inside_repo(docs_dir) or not os.path.isdir(docs_dir):
            return False
        try:
            names = os.listdir(docs_dir)
        except OSError:
            return False
        # EXACTLY ONE match, not the first. The shorthand's whole claim is that the
        # number is a stable unique identity; with docs/04-audit-protocol.md and a
        # second docs/04-*.md present it identified neither, and returning on the
        # first entry validated an ambiguous reference that leaves an agent to guess.
        # A MARKDOWN document, not any file with the prefix: deleting the real doc
        # while a stray docs/04-notes.txt remained let the shorthand resolve to the
        # artifact and report OK.
        hits = [n for n in names
                if n.startswith(prefix) and n.lower().endswith(MARKDOWN_SUFFIXES)
                and _inside_repo(os.path.join(docs_dir, n))
                and os.path.isfile(os.path.join(docs_dir, n))]
        return len(hits) == 1

    # Backticked paths are repo-rooted by house convention (`templates/incident.md`
    # means the one at the top level, wherever it is cited from), with the citing
    # document's own directory as a fallback.
    bases = (os.path.dirname(source_file),) if kind == "link" else (REPO, os.path.dirname(source_file))
    # A markdown link to a file whose name contains a space is written
    # `docs/my%20guide.md`. Resolving the literal percent-encoded string looked for
    # a filename containing "%20", so a WORKING link was reported broken — the
    # first false-positive in this gate's history, and the expensive direction to
    # fail in: a gate that goes red on valid input is one people learn to ignore.
    # The raw form is tried first so a filename with a literal % still resolves.
    # LINKS ONLY. Percent-encoding is a URL convention; a backticked path is a
    # filesystem path, so decoding it turned a citation of the real tracked file
    # `docs/my%20guide.md` into a lookup for "docs/my guide.md" and called the
    # working reference broken. Fixing the link case had quietly changed the
    # backtick case in the resolver they share.
    # Decode percent-escapes, and do NOT also try the raw form. `%20` means a
    # space, so `[g](my%20guide.md)` pointing at a literal file named
    # "my%20guide.md" is a broken rendered link — the raw fallback I added last
    # round accepted it, trading the false positive for a false negative. A file
    # whose name really contains "%" is linked as %25, which decodes correctly.
    # unquote_to_bytes + fsdecode, NOT unquote. unquote() decodes the escaped bytes
    # as UTF-8 and replaces anything undecodable with U+FFFD, so a tracked POSIX
    # filename containing a non-UTF-8 byte — linked with the matching escape, which
    # is the only correct way to link it — became a lookup for a DIFFERENT name and
    # the working reference was reported broken. os.walk and every other path in this
    # file already carry those bytes as surrogates via the filesystem encoding; this
    # was the one place that switched representations mid-comparison, which is the
    # same "two conventions for one object" defect the resolver was built to avoid.
    forms = ([os.fsdecode(urllib.parse.unquote_to_bytes(target))]
             if ("%" in target and kind == "link") else [target])
    for base in bases:
        for form in forms:
            # A decoded NUL kills realpath() with ValueError, not OSError, so it
            # escaped every guard in this file and took the whole run down with a
            # traceback — `[x](docs/missing%00.md)` in one document and the gate
            # produces no coverage summary at all. A path cannot contain a NUL on any
            # filesystem this runs on, so this is not a resolution failure to report
            # per-form: the destination is unresolvable, which is the answer.
            if "\x00" in form:
                continue
            candidate = os.path.realpath(os.path.join(base, form))
            # Containment is checked on the REAL path, after symlinks. A lexical
            # check passes a tracked symlink like docs/host.md -> /etc/passwd, and
            # exists() then follows it — so the reference reads valid while its
            # contents live outside the repo and vary by runner. `../` escapes and
            # absolute paths are the same problem in a plainer form. Outside the
            # repo is broken, always.
            if candidate != REPO_REAL and not candidate.startswith(REPO_REAL + os.sep):
                continue
            if os.path.exists(candidate):
                return True
    return False


def main():
    # This checker takes NO arguments, so any argument is a misunderstanding of what
    # it is about to do — and it used to run the ordinary repo-wide scan anyway and
    # exit 0, so a verifier who passed a scope argument read that green as coverage of
    # the scope they asked for. Same silent-interface failure as check_secrets.py, in
    # the file that was not named when I fixed it there.
    #
    # Redacted for the same reason it is redacted there: an argument can carry a
    # credential, and an error path that echoes its input is a print site that forgot
    # it was one. This file redacts everything else it prints; there is no reason for
    # its usage error to be the exception.
    if sys.argv[1:]:
        print("check_references.py: unrecognised argument(s): "
              + ", ".join(redact(a) for a in sys.argv[1:]))
        print("  Usage: check_references.py  (no options; scans the whole repo)")
        return 2

    permanent, debt = load_allowlist()
    allowed = permanent | debt
    broken = []
    retired = []
    checked_links = 0
    # The backticked surface is ~400 paths against 24 links here, and until now only
    # the smaller one was counted. See the `coverage` string below.
    checked_refs = 0
    unchecked_links = []

    for path, unreadable_reason in sorted(
            markdown_files(), key=lambda pair: pair[0]):
        rel = os.path.relpath(path, REPO)
        if unreadable_reason:
            unchecked_links.append((rel, 0, unreadable_reason))
            continue
        if not os.path.isfile(path):
            # A symlink to a MISSING in-repo path is lexically contained, so the
            # containment test passed it through and open() raised
            # FileNotFoundError — the gate dying on a dangling link a PR left
            # behind, instead of reporting the document it could not read.
            #
            # The reason is DERIVED, not assumed. isfile() is also false for a FIFO,
            # a socket and a device node, and this branch told everyone who hit one
            # that they had a dangling symlink. I went looking for a hang here after
            # the scanner had one — there is none, isfile() refuses the FIFO before
            # anything opens it — and found this instead: not a crash, just the gate
            # confidently naming the wrong cause. Same defect as the hardcoded
            # symlink message two rounds ago, in the branch right beside it.
            try:
                mode = os.lstat(path).st_mode
            except OSError as exc:
                why = f"could not be stat'd ({type(exc).__name__})"
            else:
                if stat.S_ISLNK(mode):
                    why = "dangling symlink"
                elif stat.S_ISFIFO(mode):
                    why = "named pipe (FIFO), not a document"
                elif stat.S_ISSOCK(mode):
                    why = "socket, not a document"
                elif stat.S_ISBLK(mode) or stat.S_ISCHR(mode):
                    why = "device node, not a document"
                else:
                    why = "not a regular file"
            unchecked_links.append((rel, 0, f"{why} — NOT read"))
            continue
        # errors="replace", not strict. One Windows-1252 smart quote anywhere in the
        # repo raised UnicodeDecodeError and took down the whole gate with a
        # traceback — an otherwise readable document reported as infrastructure
        # failure. Link destinations are ASCII, so replacement cannot change a
        # verdict; the substitution is reported below rather than hidden, because a
        # file this gate could only partly read is exactly what it should say out
        # loud instead of quietly counting as checked.
        # isfile() answers "does a file exist here", not "can this process read it".
        # A mode-000 document passes the test above and raises PermissionError here,
        # killing the whole gate with a traceback before it prints its coverage
        # summary — so one unreadable file turned a report about every other document
        # into nothing at all. The two neighbouring branches already treat unreadable
        # documents as unchecked inputs; this one crashed instead.
        #
        # The `try` spans the read loop, not just the open, because a read can fail as
        # well as an open — a truncated network mount, an I/O error mid-file. Nothing
        # inside the loop touches the filesystem, so OSError from the body can only
        # mean the handle.
        try:
            handle = open(path, encoding="utf-8", errors="replace")
        except OSError as exc:
            unchecked_links.append(
                (rel, 0, f"unreadable ({type(exc).__name__}) — NOT read"))
            continue
        try:
            # No per-file state here any more. Everything that decides whether a
            # `](…)` is navigation is line-local, so a document cannot put this loop
            # into a mode that outlives the construct that set it.
            for lineno, line, truncated in _bounded_md_lines(handle, rel,
                                                              unchecked_links):
                if truncated:
                    # The line is ALREADY in unchecked_links, which is its outcome.
                    # Parsing the surviving prefix cannot classify what the cut
                    # removed, so anything read out of it is a guess — and a guess
                    # that can only ever fail the build, since a resolvable path
                    # would just be silent. Nothing is dropped: the line-level note
                    # is the report, and it says the line was not validated.
                    continue
                if "\x00" in line:
                    # A BOM-less UTF-16LE document is byte-wise valid UTF-8 control
                    # characters, so errors="replace" produces no U+FFFD and the
                    # existing check never fired: the file read as text, matched no
                    # reference pattern, and counted as fully validated. NUL-bearing
                    # input is reported instead of being decoded — the same call the
                    # secret scanner made after five rounds of decoder churn.
                    unchecked_links.append(
                        (rel, lineno, "NUL-bearing (non-UTF-8?) content — NOT validated"))
                    break
                if "\ufffd" in line:
                    unchecked_links.append(
                        (rel, lineno, "undecodable bytes — line read with replacement"))
                for target, unparseable_reason in link_refs(line):
                    # Reason FIRST. link_refs yields (None, <reason>) for anything
                    # outside the simple grammar, so touching `target` before this
                    # raised AttributeError — the gate crashing instead of reporting,
                    # which is worse than a wrong verdict because it stops the run.
                    if unparseable_reason:
                        unchecked_links.append((rel, lineno, unparseable_reason))
                        continue
                    if target.startswith("?") or not target:
                        unchecked_links.append(
                            (rel, lineno, f"local link with no path: {target or '(empty)'}"))
                        continue
                    if target.startswith("#"):
                        # Same-document anchor. REPORTED, never silently dropped —
                        # that was round 11's finding and it still holds. But not
                        # validated: doing so meant reimplementing GitHub's slug
                        # algorithm, and one round of that produced five findings
                        # (duplicate-heading suffixes, setext headings, fenced code
                        # blocks, underscore handling) against three anchors in this
                        # repo, none of which was ever broken. A wrong slug rule goes
                        # RED on a valid link, which is worse here than not checking.
                        unchecked_links.append((rel, lineno, f"anchor: {target}"))
                        continue
                    # A link destination has exactly THREE outcomes: resolved,
                    # broken, or explicitly reported unchecked. There is no fourth,
                    # and every silent-pass finding in this review was a fourth
                    # sneaking in — angle brackets, then query strings, then glob and
                    # placeholder tokens. Fixing each costume left the shape intact,
                    # so the shape is what changes here.
                    #
                    # UNRESOLVABLE exists for BACKTICKED paths, where
                    # `ops/queue/YYYY-MM-DD--role--slug.md` is a documented naming
                    # convention rather than a file. Markdown links expand no globs
                    # and hold no placeholders: such a destination is broken or
                    # unsupported, never fine. So it is surfaced, not skipped.
                    # Allowlist entries are repo-rooted paths. A markdown link
                    # resolves against its own document, so `[a](product/audits/)`
                    # in team/x.md means team/product/audits/ — matching the raw
                    # text against a root entry skipped a genuinely broken link and
                    # reported zero links checked.
                    link_rooted = os.path.normpath(
                        os.path.join(os.path.dirname(rel), target)).replace(os.sep, "/")
                    if target in allowed and link_rooted.rstrip("/") == target.rstrip("/"):
                        continue
                    if link_rooted in allowed or link_rooted + "/" in allowed:
                        continue
                    if UNRESOLVABLE.search(target):
                        unchecked_links.append((rel, lineno, f"glob/placeholder: {target}"))
                        continue
                    # Beside UNRESOLVABLE, because both answer "this text is not a
                    # path this gate can resolve" and both must report rather than
                    # fail. Before `checked_links` too: counting a destination the
                    # reader could not decode as validated is the coverage lie in
                    # the counter itself.
                    undecoded = undecoded_reason(target)
                    if undecoded:
                        unchecked_links.append((rel, lineno, undecoded))
                        continue
                    checked_links += 1
                    if not resolve(path, target, "link"):
                        broken.append((rel, lineno, target))
                for target, fragment in candidate_refs(line):
                    if not target:
                        continue
                    if UNRESOLVABLE.search(target):
                        # Reported, not skipped. The link branch above has said this
                        # out loud since round 30 while this one dropped it, so a
                        # backticked glob was the one input that could vanish between
                        # the two branches of the same rule.
                        unchecked_links.append(
                            (rel, lineno, f"glob/placeholder: {target}"))
                        continue
                    # The OTHER half of the pair. A rule applied in the link branch
                    # and not this one is how a backticked glob became the single
                    # input that could vanish between two branches of one policy,
                    # three comment-lines above.
                    #
                    # The PATH only, matching that branch. A fragment is validated by
                    # neither, so a mangled one is already covered by the anchor note
                    # below — folding it in here would withhold a perfectly decodable
                    # path from resolution to say something about the part nobody was
                    # going to check.
                    undecoded = undecoded_reason(target)
                    if undecoded:
                        unchecked_links.append((rel, lineno, undecoded))
                        continue
                    # Backticked refs ARE repo-rooted by house convention, so the raw
                    # entry is the right key here. The relative-resolution rule above
                    # applies to links only — a blanket edit put it in both branches
                    # and turned nineteen valid citations red in one run.
                    if target in allowed:
                        continue
                    # Counted where the resolution happens, so the number can only
                    # ever be the number of paths this run actually resolved.
                    checked_refs += 1
                    if not resolve(path, target):
                        broken.append((rel, lineno, target))
                        continue
                    # The file resolved; the section named after "#" did not, because
                    # nothing here parses headings. Say so rather than let the file's
                    # existence stand in for the anchor's.
                    if fragment:
                        unchecked_links.append(
                            (rel, lineno, f"anchor: {target}#{fragment}"))
            # close() INSIDE the guard. A `finally: handle.close()` sits outside the
            # handler, so a close that raises — a failing network or FUSE-backed file
            # — killed the run after the document had been read successfully, which
            # is the same crash-instead-of-report this guard was added to remove, one
            # line further down. Fixing the read path and leaving the close path is
            # how a guard ends up covering most of a lifecycle.
            handle.close()
        except OSError as exc:
            unchecked_links.append(
                (rel, 0, f"read failed ({type(exc).__name__}) — PARTIALLY read"))
            try:
                handle.close()
            except OSError:
                # Already reporting this document as unread; a second failure while
                # letting go of it adds nothing a reader can act on.
                pass

    # A debt entry whose target now exists must be removed, not left in place.
    for entry in sorted(debt):
        candidate = os.path.normpath(os.path.join(REPO, entry))
        if os.path.exists(candidate):
            retired.append(entry)

    # EVERY section is printed, and the verdict is computed from all of them at the
    # end. This block used to `return 1` on the spot, which threw away a coverage list
    # and a broken-reference list the run had already computed: a checkout with one
    # retired debt entry and two genuinely broken paths reported the debt entry alone,
    # so the reader deleted the line, re-ran, and only then met the broken paths. An
    # allowlist-hygiene item is not a reason to stop reporting the thing the gate is
    # for — "finding something is not evidence of having read everything", which is
    # the sentence check_secrets.py has now been made to say three separate times.
    if retired:
        print(f"references: {len(retired)} debt allowance(s) now resolve and must be removed:\n")
        for entry in retired:
            print(f"  {redact(entry)}")
        print("\nThese were listed in .ci-allowed-refs section 2 as promised-but-missing.\n"
              "They exist now, so the exception is silencing a real file: delete the line\n"
              "and let the gate protect it like any other reference.\n")

    # Report coverage, not just the verdict. A count makes it visible how much this
    # gate actually looked at, so "OK" cannot quietly mean "parsed almost nothing".
    if unchecked_links:
        print(f"references: {len(unchecked_links)} input(s) NOT validated:")
        for rel, lineno, why in unchecked_links[:10]:
            print(f"  {redact(rel)}:{lineno}  ({redact(why)})")
        # Say that the list is cut, and by how much. The cap was invisible while the
        # count was three; reporting backticked globs and anchors pushed it to
        # eighteen, and ten lines under a heading saying eighteen reads as a display
        # that lost track rather than one that chose a limit.
        if len(unchecked_links) > 10:
            print(f"  … and {len(unchecked_links) - 10} more not shown.")
        print("  (reasons vary: unvalidated anchors, complex link syntax, unreadable or\n"
              "   oversized documents. Each line states its own — they are not all parse\n"
              "   failures, and the old heading sent readers to fix syntax that parsed fine.)\n")

    # BOTH surfaces counted. This file's header promises that "the run prints how many
    # links it validated, so OK can never quietly mean parsed almost nothing" — and it
    # printed that number for the 24 links while saying nothing at all about the ~400
    # backticked paths, which is the surface the gate primarily exists for. Silencing
    # candidate_refs entirely left the output BYTE-IDENTICAL on a repo without
    # backticked globs or anchors, under a sentence asserting that every backticked
    # in-repo path resolves. A claim about a set nobody counted is the coverage lie
    # this gate was written to refuse, made by the gate about itself.
    coverage = f"{checked_refs} backticked path(s), {checked_links} link(s) checked"

    if not broken:
        # The summary must not read as all-clear while something went unvalidated.
        # "OK" on its own line is exactly the looks-complete failure this gate keeps
        # finding in other people's code, so the unchecked count rides along with it.
        if retired:
            # Never the word "OK" above a non-zero exit.
            print(f"references: no broken paths ({coverage}), but "
                  f"{len(retired)} debt allowance(s) must be removed — see above")
            return 1
        if unchecked_links:
            print(f"references: no broken paths ({coverage}), "
                  f"but {len(unchecked_links)} input(s) NOT validated — see above")
        else:
            print(f"references: OK — every backticked in-repo path resolves "
                  f"({coverage})")
        return 0

    print(f"references: {len(broken)} broken reference(s) ({coverage})\n")
    for rel, lineno, target in broken:
        print(f"  {redact(rel)}:{lineno}  ->  {redact(target)}")
    print(
        "\nEach line above is a path an agent was told to read that does not exist.\n"
        "Fix the path, create the file, or — if it genuinely lives in another repo —\n"
        "add it to .ci-allowed-refs with a comment saying which repo owns it."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
