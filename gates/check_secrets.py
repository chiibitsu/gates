#!/usr/bin/env python3
# Part of chiibitsu/gates by Angeline S. Viray (Chiibitsu Labs). MIT. https://github.com/chiibitsu/gates
"""Tier 1 gate: a fast smoke check for credentials in the working tree.

## What this is, precisely

A **diff-time smoke check**: the working tree, plus a bounded scan of the pushed range
covering added lines, commit messages, commit author and committer identities, added
and renamed filenames, and — when CI passes it in via `TIER1_EXTRA_TEXT` — the pushed
ref name. It catches the common mistake — a key pasted into a file, into a commit
message, or into a name — before it lands. That is all it is, and the limitation is
deliberate. (Those metadata surfaces were added one at a time between rounds 16 and
27 while this paragraph still described only the first two; it understated the gate's
own scope for eleven rounds.)

Earlier versions also opened committed archives and recursed into nested ones. That
machinery is gone. Six review rounds found bypass after bypass in it — uppercase
`.ZIP`, text entries beginning `PK`, resource bounds that silently skipped the
remainder, no cumulative inflation budget — and while every finding was real and every
fix correct, the rate never fell. Exhaustive credential detection is a specialist
product and this was reimplementing it badly. So archives are **not** inspected, and
that gap is stated rather than papered over.

**Where native scanning is available, it is the authoritative layer** — vendor
patterns, continuous history coverage, push protection that blocks the credential
before it reaches the remote. Free on public repositories.

**This repository is private, and native secret scanning on private repositories
requires paid Advanced Security.** So here there is no vendor layer behind this
script, and "the platform covers history" would be false. A bounded history scan is
therefore kept below — added lines and commit messages across the pushed range, so a
credential added in one commit and deleted in the next cannot pass on a clean tree.
Archives and nested archives stay removed: that is where the bypasses actually lived,
and their absence is documented rather than pretended away.

**Skipping is qualified for shared surfaces and FATAL for sole ones.** A binary blob or
an oversized line is skipped by a scope decision, and every one of those inputs is also
visible in a tree, a diff or a review — so the run says what it did not read and passes.
An annotated tag object appears in no tree, no diff and no commit message: this file's
tag pass is its only reader, so an unread one is not out of scope, it is unexamined, and
the gate fails INDETERMINATE exactly as it does when the history range will not walk.
The 1 MiB tag budget is attacker-chosen — pad the annotation, put the key after the cut —
and no legitimate annotated tag approaches it, so failing closed there costs nothing.

**This gate does NOT defend against a hostile pull request, and last round it briefly
pretended to.** Round 17 added machinery to run the base branch's copy of this scanner
on pull requests, on the reasoning that a PR editing the scanner that judges it goes
green while leaking. The reasoning was right and the fix was theatre: on `pull_request`
GitHub runs the **workflow definition itself** from the proposed tree, so a PR can
replace the job body with `true`, keep the check name, and satisfy branch protection
without ever reaching this file. **Ordering, as it actually stands today:** the
portable template runs this scan FIRST, before Setup Node, `npm ci`, tests and the
build — changed in round 22 so a repo that commits generated bundles could not have
its build rewrite a tracked file into a reported credential. This repo's own workflow
still runs `check_references.py` before it, so on a pull request one piece of
contributor-controlled code does execute first here. Neither ordering rescues the
trust boundary, because the workflow definition itself comes from the proposed tree;
the ordering is stated precisely because a reader should not have to infer it.
The round-17 machinery was removed rather than deepened; it also made the v13→v14
upgrade unmergeable for any consumer, since the PR performing the upgrade was the one
it rejected.
**What actually closes this:** GitHub **push protection**, which blocks the credential
before the remote accepts it and runs on GitHub's side of the trust boundary, plus
org-level required workflows whose definition does not come from the PR. This script is
a pre-flight for the honest contributor, on a repo whose contributors are trusted. On
`chiibitsu/*` today that is one person, so the gap is theoretical here — but any
consumer repo taking outside contributions must not read this check as a defence
against them.

**Known environment dependency: the Unicode tables come from the running CPython.**
`_continues_identifier` asks `str.isidentifier()` and `unicodedata.category`, both of
which track the Unicode version compiled into the interpreter — so a character that is
unassigned under one CPython minor and an identifier continuation under the next can
change this gate's verdict between runners. The proper fix is to pin the interpreter in
CI. It is NOT done here: this repo pins every action by commit SHA and never by tag, and
adding `setup-python` would mean committing a SHA I cannot verify from this environment.
So the dependency is recorded instead, and `--selftest` prints the interpreter and
Unicode versions it ran under, which makes drift visible in the log rather than silent.
Pin the interpreter when you can verify the pin.

**Known unclosed gap: non-UTF-8 content in HISTORY hunks.** A UTF-16 or UTF-32 file
forced through git's text diff driver by `.gitattributes` arrives as a `+` line whose
framing git has already mangled, and such hunks are now reported as NOT scanned rather
than decoded. A decoder lived here for five rounds and every fix to it produced the
next finding — UTF-16, then attribute-forced text, then a density heuristic, then byte
alignment across newline splits, then a printability threshold that binary could game.
That is the archives lesson a fourth time, after archives themselves, the base-scanner
machinery, and chunked reading. Files present in the WORKING TREE are still decoded
properly from their byte-order mark; only history hunks fall back to the honest answer.

**Known unclosed gap: LFS objects in history.** `lfs: true` materialises only the
checked-out tree, so an LFS-tracked credential added and deleted inside one pushed range
is a pointer in the patch and absent from the tree. Same family as the tag gap below and
the same answer.

**Annotated tag objects: CLOSED, by the workflow rather than by this file.** An
annotated tag stores its message and tagger identity in a tag object, not in the commit
it points at, so `git log` over a commit range never sees it — a credential in
`git tag -a -m "..."` was fetchable while this gate reported clean, and worse, pushing
that tag at a commit already on the default branch makes the range legitimately empty,
so nothing else looked either.

This paragraph spent seventeen rounds arguing the gap was not worth closing, on the
grounds that each new git surface costs more than it returns for a smoke check. That
was a reasonable trade to state and a bad one to keep: the closing turned out to be
three lines of shell, because the scanner already accepts arbitrary metadata through
`TIER1_EXTRA_TEXT` and reports it through the same redacting choke point as everything
else. The cost estimate was never re-checked after the surface that made it cheap was
built. `.github/workflows/tier1.yml` now passes the pushed tag object; a consumer who
vendors only this script and writes their own workflow does not get it, which is the
part that remains true and is why this paragraph still exists.

If this file is ever the only thing between a key and a *public* repository, that is a
gap in the setup, not a feature of the script.

## Why the patterns look the way they do

It matches credential *values*, never names. This repo discusses `VAULT_GITHUB_TOKEN`,
`OAUTH_SIGNING_SECRET`, `ACCESS_PASSWORD` and `SESSION_SECRET` constantly — that is
the audit protocol working, not a leak. A gate that fired on the word "SECRET" would
be red permanently, and a permanently-red gate is one everybody learns to merge past,
which is worse than no gate at all. Where a shape is shared by a public value and a
privileged one (Supabase JWTs), the payload is decoded rather than guessed at.
"""

import base64
import binascii
import collections
import hashlib
import json
import os
import re
import select
import stat
import subprocess
import sys
import time
import warnings
import unicodedata

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_REAL = os.path.realpath(REPO)

# Bump on any change to detection behaviour. Repos that vendor this file assert a
# minimum against it, so a stale copy fails loudly instead of quietly keeping a
# defect this repo already fixed.
SCANNER_VERSION = 80

# Any PEM private-key armor. Enumerating header words is how two earlier drafts missed
# things: `RSA|EC|OPENSSH|PGP` skipped `BEGIN ENCRYPTED PRIVATE KEY` (standard
# password-protected PKCS#8), and requiring `PRIVATE KEY` immediately before the
# dashes skipped `BEGIN PGP PRIVATE KEY BLOCK`, which is what `gpg
# --export-secret-keys` actually emits. Match the family, not a list someone recalled.
# Token BOUNDARIES, rounds 29-35, because the shape of that mistake is worth keeping.
# Each trailing `\b` became `(?![\w-])`: the alphabets contain "-", which is not a word
# character, so a key ENDING in a hyphen had no boundary to match, and at exactly the
# minimum length the quantifier cannot give a character back to find one. That fix then
# failed four more times — on "_", on non-ASCII letters, on combining marks and joiners,
# on grapheme extenders — because each attempt ENUMERATED the characters that continue a
# token instead of stating the property. `_continues_identifier` below is the version
# that holds: it delegates to `str.isidentifier()` and Unicode categories, and names only
# ranges that are genuinely closed. The lesson, stated once: when replacing a built-in
# abstraction, restate the property it encoded rather than listing the cases it covered.
# "PRIVATE KEY" must be a whole phrase, not a prefix. `[A-Z0-9 ]*` on either side
# accepted PRIVATE KEYBOARD and PRIVATE KEYRING as armor, which is the failure that
# actually costs a consumer something: a false RED on a required gate teaches everyone
# to merge past it, and an ignored gate protects nothing. The optional groups now
# begin and end at a space, so a word may PRECEDE the phrase (RSA, ENCRYPTED, OPENSSH)
# or FOLLOW it (BLOCK), but nothing may be glued to it.
PEM_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:[A-Z0-9 ]*[A-Z0-9] )?PRIVATE KEY(?: [A-Z0-9][A-Z0-9 ]*)?-----")

# PDF is deliberately NOT in the magic-byte list. Four rounds of narrowing a
# substring search — the marker anywhere in a kilobyte, at the start, with a version,
# with a version terminating its line — and prose defeated every one of them, because
# a text file can simply quote the complete header line. That is not a bug in the
# fourth attempt; it is proof that no test on the first bytes can separate a container
# from a document that quotes one.
#
# So this follows the fallback the third attempt wrote down for itself: SCAN. A PDF
# read as text still yields any plaintext credential in it, and a NUL-bearing one is
# still classified binary by the test at the end of _is_binary, which is how most real
# PDFs are caught. Text that quotes the header is now scanned instead of skipped.
#
# What this gives up, stated rather than buried: a NUL-free PDF whose credential lives
# in a compressed stream is now read as text, finds nothing, and is reported as
# SCANNED. That is a silent miss where the old behaviour produced an honest "NOT
# scanned". It is the better trade only because the failure it replaces was also a
# miss — of a plaintext credential, in an ordinary text file, which is the case this
# smoke check exists for and the rarer case is not.

JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.(eyJ[A-Za-z0-9_\-]{10,})\.[A-Za-z0-9_\-]{10,}(?![\w-])")

PATTERNS = [
    ("pem", "private key block", PEM_PRIVATE_KEY),
    ("aws", "AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("gh_token", "GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("gh_pat", "GitHub fine-grained PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("anthropic", "Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}(?![\w-])")),
    # Project keys use the URL-safe alphabet, so `_` and `-` appear inside them.
    # Restricting to [A-Za-z0-9] stopped counting at the first such character and
    # never reached the length floor, so a real key scanned clean.
    ("openai", "OpenAI API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}")),
    # `xox*` is the user/bot/workspace family; `xapp-` is the app-level family,
    # which grants Socket Mode and app-config access. Matching only the first
    # was an enumeration gap of exactly the kind the PEM pattern already taught.
    # "_" is in the REJECTED set although it is not in the token alphabet: the
    # boundary these replaced also rejected it, and dropping it made
    # `xoxb-ABCDEFGHIJ_suffix` — an ordinary placeholder — a credential. The
    # lookahead must reject every character that could continue an identifier,
    # not only the ones the token itself may contain.
    ("slack", "Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}(?![\w-])")),
    ("slack_app", "Slack app-level token", re.compile(r"\bxapp-[0-9]-[A-Za-z0-9-]{10,}(?![\w-])")),
    # No trailing \b. The alphabet includes "-", which is a non-word character, so a
    # key whose 35th character is a hyphen has no word boundary after it — and unlike
    # the variable-length patterns this one cannot backtrack to find one, so a real
    # key returned None. A negative lookahead states the intent directly.
    ("google", "Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}(?![\w-])")),
    ("stripe", "Stripe live key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b")),
    # Current-format Supabase secret key. `sb_publishable_` is deliberately absent —
    # that one is meant to be public.
    ("sb_secret", "Supabase secret key", re.compile(r"\bsb_secret_[A-Za-z0-9_\-]{20,}(?![\w-])")),
    ("postgres", "Postgres URL with password",
     re.compile(r"\b(?i:postgres(?:ql)?)://[^\s:]+:[^\s@]+@")),
]

PRIVILEGED_JWT_ROLES = {"service_role", "supabase_admin"}

# A fingerprint of every matcher's pattern SOURCE, checked by --selftest.
#
# Owning "a probe for this matcher" is not the same as owning "a probe for every
# shape this matcher accepts": extending `openai` with a second alternative left the
# existing sk- probes satisfying the check while the new shape went unredacted. I
# cannot ask a regex what shapes it accepts without parsing it, and parsing it would
# be the specialist machinery this file has removed four times. So the honest
# property is narrower and conservative: this pattern is UNCHANGED since a human last
# paired it with probes. Any edit — a new alternative, a widened class, a lowered
# floor — fails the test until the fingerprint is updated deliberately, which is the
# moment to add the probe.
def _fingerprint(pattern, extra=""):
    """Hash of a compiled pattern's SOURCE AND FLAGS.

    `extra` carries whatever else determines the family's behaviour. The JWT family
    is gated by PRIVILEGED_JWT_ROLES as well as by its regex, so adding "anon" to
    that set turned a key this file exists to NOT flag into a hit while the pattern
    and flags were untouched. Source and flags were never the whole input; they were
    the whole input I had thought of.

    Flags were missing, so adding re.IGNORECASE to the AWS matcher changed what it
    accepts — lowercase akia... values the reference redactor does not cover — while
    `pattern.pattern` stayed byte-identical and the check stayed green. A fingerprint
    over half the inputs to a behaviour is a fingerprint of nothing in particular.
    """
    return hashlib.sha256(
        f"{pattern.pattern}\x00{pattern.flags}\x00{extra}".encode()).hexdigest()[:12]


# Grapheme extenders that are NOT marks, and the two joiners. These ranges are
# CLOSED — five emoji modifiers, sixteen variation selectors, 240 in the supplement —
# so naming them is a bounded fact, not the open-ended enumeration that failed five
# times elsewhere in this file. Python exposes no grapheme-break property to delegate
# to; if it ever does, _extends_grapheme should be replaced by it rather than extended.
#
# These were four inline comparisons until a range could be deleted with every check
# still green: removing the emoji modifiers turned a token followed by U+1F3FB from
# suppressed into an "OpenAI API key" hit, and nothing noticed, because this policy is
# shared by all thirteen families and _policy_extra only covered per-family tables.
# Shared policy needs a shared fingerprint component, and a table can be enumerated by
# the probe generator while a chain of `or` cannot.
GRAPHEME_JOINERS = ("‌", "‍")   # ZWNJ, ZWJ
GRAPHEME_EXTENDER_RANGES = (
    (0x1F3FB, 0x1F3FF, "emoji skin-tone modifiers"),
    (0xFE00, 0xFE0F, "variation selectors"),
    (0xE0020, 0xE007F, "tag characters"),
    (0xE0100, 0xE01EF, "variation selectors supplement"),
)


# Literal codepoints that must stay suppressed, written out rather than derived.
#
# The generated probes walk GRAPHEME_EXTENDER_RANGES, so deleting a row deletes its
# own probe — and an author who deletes the row and refreshes the fingerprints passes.
# I checked; that mutation went green. These literals are read by nothing else, so
# the deletion leaves them behind and they fail: U+1F3FB stops being suppressed and
# the probe naming it fires.
#
# Generated and hand-written cover opposite gaps. Generation follows the table into
# ranges nobody thought to probe, including ones added later. Literals do not follow
# the table out. Neither alone is enough, and the pair costs four lines.
SUPPRESSED_CODEPOINTS = (
    0x1F3FB,    # emoji skin-tone modifier, first
    0xFE0F,     # variation selector-16
    0xE0020,    # tag space
    0xE0100,    # variation selector-17
    0x200D,     # ZWJ
    0x0301,     # combining acute accent (category Mn, via unicodedata)
)


def _boundary_policy():
    """The boundary rules every family shares, as a fingerprintable string."""
    return "|".join(
        [f"j{ord(c):x}" for c in GRAPHEME_JOINERS]
        + [f"{lo:x}-{hi:x}" for lo, hi, _ in GRAPHEME_EXTENDER_RANGES])


def _policy_extra(mid, label):
    """Every behaviour-determining input keyed by matcher id, other than the regex.

    The first version of `extra` was passed at the call site: the JWT role set for
    one family, the empty string for twelve. That is a list of the tables I happened
    to remember wearing a general-looking parameter, and the one it forgot was
    NON_TOKEN_IDS — adding a family there exempts it from the continuation filter, so
    a token followed by a combining mark or a connector goes from ignored to reported
    with the regex, the flags, and the old `extra` all unchanged.

    Deriving it from the id instead means a new policy table is added HERE, in the
    one place whose job is to enumerate them. That does not make forgetting
    impossible. It makes forgetting a visible omission from a list rather than the
    absence of an argument nobody was looking for.

    Two additions since, both from checking only the per-family half:

    The LABEL is behaviour, not decoration. A finding deliberately withholds the
    matched value, so the label is the only thing telling someone WHICH credential to
    rotate; swapping the AWS and Google labels passed all 46 probes while reporting
    AWS keys as Google keys. Every self-test asked whether scan_line returned some
    truthy label, which is a different question from whether it returned the right
    one.

    The shared BOUNDARY policy is in here too, identical for all thirteen families.
    A per-family table cannot notice a rule that belongs to none of them: deleting the
    emoji-modifier range changed what every family reports and moved no per-family
    input at all. Shared policy trips all thirteen fingerprints, which is the correct
    blast radius — the edit did change all thirteen behaviours.
    """
    return "\x00".join((
        f"non_token={mid in NON_TOKEN_IDS}",
        "roles=" + ("|".join(sorted(PRIVILEGED_JWT_ROLES)) if mid == "jwt" else ""),
        f"label={label}",
        f"boundary={_boundary_policy()}",
    ))


# One canary per matcher ID: a value that family's pattern MUST match, and which the
# whole scan pipeline MUST flag.
#
# The key-set check compares two sets, and two sets stay equal when a deleted
# family's id is reassigned to a survivor — delete AWS, rename Google's matcher to
# "aws", move its fingerprint under that key, and everything balanced while the
# scanner stopped detecting AWS keys. An id is only an identity if something outside
# the tables pins it to a shape.
#
# What this closes, precisely, and what it does not. The reassignment above now fails:
# the surviving pattern is Google's and the canary under "aws" is an AKIA value. An
# author who also rewrites the canary passes — no table can outvote an edit to every
# table — but the passing diff then contains the line `"aws": "AIza..."`, which states
# in one reviewable place that the AWS family matches Google keys. That is the honest
# boundary: this turns a silent coverage loss into a written claim, not into an
# impossibility.
#
# Each canary is also run through scan_line, not just `pattern.search`. A family can
# keep a matching regex and stop firing anyway — the continuation filter, the
# non-token exemptions, and the JWT role gate all sit between the match and the
# report, and each one has suppressed a real credential at least once in this file's
# history. Asserting on the regex alone tests the half that never broke.
#
# Each entry declares the LABEL the pipeline must report as well as the shape. The
# first version of that check read the expected label out of the matcher table it was
# checking, so swapping two labels satisfied it: both sides moved together and the
# comparison compared a thing with itself. I verified the swap passed before writing
# this, which is the only reason the circularity was caught rather than shipped as a
# second check that tests nothing. A pin has to be written somewhere the edit under
# test does not reach.
CANARIES = {
    "pem": ("-----BEGIN OPENSSH " + "PRIVATE KEY-----", "private key block"),
    "aws": ("AKIA" + "H" * 16, "AWS access key id"),
    "gh_token": ("ghp_" + "C" * 38, "GitHub token"),
    "gh_pat": ("github_pat_" + "D" * 62, "GitHub fine-grained PAT"),
    "anthropic": ("sk-ant-" + "A" * 24, "Anthropic API key"),
    "openai": ("sk-" + "B" * 44, "OpenAI API key"),
    "slack": ("xoxb-" + "E" * 14, "Slack token"),
    "slack_app": ("xapp-1-" + "F" * 14, "Slack app-level token"),
    "google": ("AIza" + "G" * 35, "Google API key"),
    "stripe": ("sk_live_" + "I" * 24, "Stripe live key"),
    "sb_secret": ("sb_secret_" + "J" * 24, "Supabase secret key"),
    "postgres": ("postgres" + "://u:p@h", "Postgres URL with password"),
}


# Nothing is exempt today. The JWT family used to be, on the grounds that its probes
# build a token and decode it — but that reasoning covered its SHAPE, not its label,
# and the string scan_line prints for a privileged JWT was a literal at the report
# site that no table referenced. Its canary has to be constructed rather than written
# down, so it is added in the selftest where _selftest_jwt is in scope; the exemption
# set stays as the declared way to say "pinned some other way", empty and still
# enforced, because an optional check is one a new family opts out of by existing.
CANARY_EXEMPT = set()


PATTERN_FINGERPRINTS = {
    "pem": "81118a085172",
    "aws": "ab7d11d16286",
    "gh_token": "9adec4cd37c0",
    "gh_pat": "832bed50c130",
    "anthropic": "2087ebd37bbf",
    "openai": "5348f6096607",
    "slack": "0e9e754f4f55",
    "slack_app": "7caa8d8b874d",
    "google": "4d78719179f1",
    "stripe": "87b7191d6aab",
    "sb_secret": "de944c2f838d",
    "postgres": "62a5abadb982",
    "jwt": "dde339ec124d",
}

# Keyed by matcher ID, not display label. Allowing duplicate labels last round made
# the label a proxy again three lines later: any matcher sharing the name "private key
# block" would have inherited this exemption. The eighth instance of that class, and
# the second I created while fixing the seventh.
# The continuation filter applies only to families whose match ENDS at a token
# boundary. These two do not: the Postgres pattern deliberately stops at "@" with the
# host still to come, and PEM armor stops at "-----". Applying an
# identifier-continuation test to them rejected every Postgres URL whose host began
# with a letter — a false NEGATIVE created by the fix for a false positive, caught by
# the self-test rather than by me.
NON_TOKEN_IDS = {"pem", "postgres"}

# A tag object is a message and an identity; a megabyte is far more than any real
# one and still bounds a hostile file.
TAG_OBJECT_BUDGET = 1 << 20

# Exactly what str.splitlines() treats as a line boundary. Derived rather than
# retyped: a hand-copied list is the drift this file has been punished for twice.
SPLITLINES_BOUNDARIES = "".join(
    ch for ch in map(chr, list(range(0x20)) + [0x85, 0x2028, 0x2029])
    if len((ch + "x").splitlines()) > 1)

# Undecodable bytes are preserved AS THEMSELVES, not collapsed to U+FFFD.
#
# Every reader here used errors="replace", and the boundary rules then read U+FFFD as
# "a byte we could not decode, so the token boundary beside this match is unknowable".
# But U+FFFD is an ordinary character that a perfectly valid UTF-8 file may simply
# CONTAIN. Appending one after a credential therefore turned a RED into a coverage
# note and an exit 0 — the value suppressed from the report by a character anyone can
# type, in the gate whose entire job is to refuse to be quiet.
#
# errors="surrogateescape" maps each undecodable byte to U+DC80–U+DCFF. Those code
# points cannot arise from decoding valid UTF-8 — Python's decoder rejects encoded
# surrogates — so their presence is PROOF of a decoding failure rather than an
# inference from the result. Provenance is carried in the text instead of guessed
# from it, which is the same move as reading `deleted file mode` instead of parsing
# "Binary files … differ".
#
# Every output path goes through _escape_controls, which renders these visibly and
# keeps a lone surrogate out of print(), where it would raise UnicodeEncodeError.
UNDECODABLE_LOW, UNDECODABLE_HIGH = "\udc80", "\udcff"


def decode_text(raw, encoding="utf-8"):
    """The ONE decoder. Preserves which bytes failed; see UNDECODABLE_LOW."""
    return raw.decode(encoding, "surrogateescape")


def _undecodable(ch):
    return UNDECODABLE_LOW <= ch <= UNDECODABLE_HIGH


SKIP_DIRS = {".git", "node_modules", ".venv"}
SKIP_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".pdf", ".ico", ".woff", ".woff2")
# Archives are out of scope by the decision recorded in this file's header — the
# machinery to open them was deleted after six rounds of bypasses. But they were
# still being READ as replacement-decoded text and then counted as scanned, so a
# tracked .zip whose compressed entry held a key produced a clean pass. Out of scope
# has to mean REPORTED as out of scope, or it is just a silent miss with a rationale.
ARCHIVE_SUFFIXES = (".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar",
                    ".war", ".whl", ".tar", ".zst", ".lz4", ".cab", ".dmg", ".iso")


def _text_lines(handle, rel, unscanned):
    """Yield (lineno, line), never materialising more than LINE_BUDGET at once.

    The budget added last round guarded the git-log stream only, so a committed
    minified bundle with no newline was still read whole into memory by ordinary
    line iteration in the working-tree pass. Same defect, other half of the file.
    """
    buf, lineno, over = "", 0, False
    truncated = False
    consumed = 0
    while True:
        block = handle.read(CHUNK)
        if not block:
            break
        consumed += len(block)
        if over:
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
            yield lineno, line, False
        if len(buf) > LINE_BUDGET:
            unscanned.append(f"{rel}: line over {LINE_BUDGET >> 20} MiB — NOT scanned")
            truncated = True
            # No increment here. The discarded remainder is counted when its
            # newline finally arrives, so incrementing at both points reported
            # every later credential one line too high — and with values withheld,
            # the line number is the only locator the reader gets.
            yield lineno + 1, buf, True
            buf, over, truncated = "", True, False
        # A WHOLE-FILE cap, not just a per-line one. LINE_BUDGET bounds how much is
        # held at once; it does not bound how much is read, so a multi-gigabyte log
        # of short newline-delimited lines never trips it and this loop reads and
        # regex-scans every byte. The history pass has had a 300s deadline since it
        # was written — the working-tree pass was the half without one, which is this
        # PR's most repeated shape: a bound applied to one member of a pair.
        # The remainder is REPORTED, never silently dropped: an unread tail that does
        # not reach `unscanned` is the coverage lie this file keeps failing on.
        if consumed > TREE_FILE_BUDGET:
            unscanned.append(f"{rel}: over {TREE_FILE_BUDGET >> 20} MiB — remainder"
                             " NOT scanned")
            # `buf` holds a PARTIAL line here. Yielding it would present an
            # arbitrary cut as a complete one, which is exactly the false-RED the
            # line cap keeps one extra character to avoid.
            return
    if buf and not over:
        yield lineno + 1, buf, False


def report_metadata_line(text, lineno, where, hits, unscanned, commit="",
                         truncated=False):
    """Record a metadata hit, or say why it could not be judged.

    ONE function for every metadata surface — ref names, tag objects, commit headers,
    commit messages. It exists because the raw-commit path got a line counter and an
    undecodable-boundary guard in round 66 and the tag path, fifteen lines away, got
    neither: hits at line 0 that no reader could tell apart, and an undecodable byte
    read as a
    token boundary. That is the seventh time in this PR a defence landed on one
    member of a pair, and the sixth time the answer was to give the pair one owner
    rather than to copy the fix.

    The undecodable case is the third outcome, not a hit and not silence: reading
    stored bytes means a non-UTF-8 letter arrives as an undecodable marker, which the
    boundary rules read as a separator, so a substring inside a longer token would be
    reported as a
    credential. Decoding by the declared encoding is the obvious fix and the wrong
    one — attacker-chosen, and this file has deleted encoding machinery five times.
    """
    found, ambiguous = judge_line(text, truncated)
    if ambiguous:
        unscanned.append(
            f"{commit or where}:{lineno}: undecodable byte beside a "
            f"credential-shaped value — boundary unknowable, NOT scanned")
    # The value is NEVER echoed: this file names the shape and the location only.
    #
    # The exact key carries the COMMIT. Without it, the same value in two commit
    # messages produced one key and the older commit vanished from the report — so
    # rewriting the named commit merely revealed the next occurrence on the following
    # run, which is the report-is-not-exhaustive defect for the fourth time in this
    # PR. Metadata has no overlap key: a commit message is not a file on disk, so it
    # never participates in the tree-versus-history reconciliation.
    for label, identity in found:
        hits.append((commit or f"{where} (value withheld)", lineno,
                     f"{label} ({where})",
                     (commit or "tree", where, lineno, identity), None))


def reconcile(tree, past):
    """Merge the ONE deliberate overlap and nothing else. Returns display triples.

    Every hit carries two keys. The EXACT key names its stored location — for history
    that includes the commit — and two hits with different exact keys are two things
    a reader must deal with separately. The OVERLAP key is (path, line, identity),
    present only for surfaces that can exist both on disk and in history, and it
    exists for exactly one purpose: a credential added inside the pushed range and
    still present in the working tree is seen by both passes, and is one thing to
    rotate, not two.

    Reconciling on the overlap key GLOBALLY, which is what this did, collapsed
    genuinely distinct stored locations: the same value in two commit messages
    produced one entry, so rewriting the commit the report named simply revealed the
    other on the next run. That is the same "the list looked exhaustive" defect as
    round 66's value-blind dedupe and round 72's first-match-only judge — a narrow,
    justified merge that quietly widened into every surface it could reach.

    So: history yields to the tree only when the tree already holds those exact bytes
    at that exact path and line. Otherwise every distinct location survives.

    Identity is a hash of the MATCHED BYTES, never the displayed label — two different
    keys of the same family on one line have different hashes and both survive, which
    is the property value-blind deduplication destroyed. The hash is never printed.

    ONE history hit per tree hit, not every history hit that matches it. A range that
    adds a credential, deletes it, and re-adds the same value at the same path and
    line produces two distinct stored locations, and both shared the tree hit's
    overlap key — so the presence of the working-tree copy discarded BOTH commits and
    the report named a single line with no commit to rewrite. Deleting the file from
    the working tree made both reappear, which is the tell: coverage that improves
    when you remove evidence was never coverage.

    So the merge is budgeted. Each tree hit cancels exactly the one history hit that
    IS it — the most recent, since git walks newest first and that is the add whose
    content is on disk — and every older stored location survives. The fifth time in
    this PR that a justified merge quietly consumed more than the thing it was
    written to merge.
    """
    budget = collections.Counter(
        overlap for *_rest, overlap in tree if overlap is not None)
    seen, unique = set(), []
    for source in (tree, past):
        for where, lineno, label, key, overlap in source:
            if source is past and overlap is not None and budget[overlap]:
                budget[overlap] -= 1
                continue
            if key in seen:
                continue
            seen.add(key)
            unique.append((where, lineno, label))
    return unique


def report_filename(name, kind, hits, unscanned, commit=""):
    """Record EVERY credential stored in one tracked path. Returns True if any was.

    ONE owner for all five filename surfaces — the working tree, and history's copy,
    rename, `+++` and `new file mode` branches. They were five copies of the same
    three lines, and all five carried the same two defects, which is what a copy
    guarantees and this PR has now paid for nine times.

    The defects: `scan_line` returned the FIRST match, so a path holding an AWS-shaped
    value and a GitHub-shaped value was reported as one credential labelled AWS — the
    reader rotates that one, reruns, and finds the second still there. And the key
    hashed the WHOLE PATH rather than the matched bytes, so it could not reconcile
    against any other surface's key and two paths differing only outside the
    credential looked like two separate leaks.

    Line 0 is deliberate and means "not in the contents". A path has no lines.
    """
    found, ambiguous = judge_line(name)
    if ambiguous:
        unscanned.append(
            f"{redact(name)}: undecodable byte beside a credential-shaped value in "
            f"the {kind} — boundary unknowable, NOT scanned")
    # The PATH is in the displayed location even for history hits. `commit or name`
    # dropped it whenever a commit was known, and when the file was added and then
    # deleted or renamed away inside the range there is no working-tree hit to supply
    # it — so a commit touching several paths printed `history <sha>:0` and the reader
    # had no way to know which filename to remove. The value is withheld on purpose;
    # the locator is the entire remaining content of the finding, and this is the
    # fourth time in this PR it has been the thing that was wrong. Redaction happens
    # at the print site, so the raw name is safe to carry here and nowhere else.
    where = f"{commit} {name}" if commit else name
    for label, identity in found:
        hits.append((where, 0, f"{label} (in {kind})",
                     (commit or "tree", "name", name, identity),
                     ("name", name, identity)))
    return bool(found) or ambiguous


def _refuses_to_open(path):
    """True if opening this path could BLOCK rather than fail.

    open() on a FIFO waits for a writer, forever, with no timeout — the gate does
    not fail, it hangs until the runner kills the job. main() already refuses
    non-regular files before either reader below is called, so this is a backstop
    and not the fix. It exists because that guard is caller-side: the property
    belongs to the act of opening, and a second call site added later would
    reintroduce the hang with nothing to catch it. This PR has produced four
    separate "fixed in one branch of a pair" findings; a rule enforced only by its
    callers is the same shape, waiting.
    """
    try:
        return not stat.S_ISREG(os.lstat(path).st_mode)
    except OSError:
        return True


def _is_binary(path):
    """True if the file's first block looks like binary content.

    Classifying by SUFFIX let a rename suppress the scan: moving a tracked
    plaintext file to notes.zip turned a credential failure into a qualified pass,
    because the extension alone decided the file would not be read. The extension
    now only labels the report; the bytes decide.

    A byte-order mark wins over the NUL test, since UTF-16 text is full of NULs and
    is exactly the case the working-tree decoder exists to read.
    """
    if _refuses_to_open(path):
        # Conservative: unreadable-as-text. The caller reports it either way; what
        # matters here is that nothing waits on a pipe that will never be written.
        return True
    try:
        with open(path, "rb") as handle:
            head = handle.read(8192)
    except OSError:
        return False
    # UTF-32BE begins 00 00 FE FF, so the NUL test below classified it binary and it
    # never reached _encoding_of, which already supports utf-32. UTF-32LE starts
    # FF FE 00 00 and was accidentally covered by the UTF-16LE prefix.
    saw_bom = False
    while True:
        # Consecutive BOM-like prefixes, all of them. Stripping only the first let
        # two UTF-8 BOMs followed by %PDF- reach the "genuine text" verdict.
        for bom in (b"\x00\x00\xfe\xff", b"\xff\xfe\x00\x00", b"\xef\xbb\xbf",
                    b"\xff\xfe", b"\xfe\xff"):
            if head.startswith(bom):
            # STRIP and keep checking, do not return. Returning here meant a BOM
            # placed before a container header — EF BB BF then %PDF- — skipped the
            # magic test entirely, and since the suffix no longer decides anything
            # the encoded streams were then read as UTF-8 text and counted scanned.
                head, saw_bom = head[len(bom):], True
                break
        else:
            break
    # Magic bytes, not parsing. A PDF whose ASCII85/Flate stream holds a key can be
    # entirely NUL-free, so a byte test alone called it text and claimed to have
    # scanned it. This is a fixed list of container headers — deliberately not a
    # format decoder, which is the machinery this file has now removed four times.
    # LEADING WHITESPACE ONLY, not a 1024-byte window.
    #
    # The window existed because requiring offset zero let one stray leading newline
    # reclassify an opaque container as text. It bought that at a price nobody
    # priced: a plain .txt whose first line MENTIONS the marker was classified
    # binary, so a real credential on its second line got a qualified skip and the
    # run exited 0. A missed credential is the one error this file exists to prevent,
    # and it was paying for a newline.
    #
    # The paragraph two comments up already recorded this exact defect for %!PS and
    # moved that marker to the anchored set. %PDF- was left in the window in the same
    # edit. Same bug, one line apart, fixed for one marker and not the other — the
    # fifth instance in this PR of a fix applied to one half of a pair.
    #
    # Whitespace tolerance keeps the newline case working: a real PDF begins with the
    # header, optionally behind a BOM (already stripped) or blank lines. Prose that
    # discusses the header has words before it.
    # %!PS is GONE, for the reason PDF was: it is an ASCII signature, so a text file
    # can begin by quoting it and every such file was skipped with its credentials
    # unread. Anchoring at offset zero does not help — quoting a marker at the start
    # of a document is exactly how one writes about it.
    #
    # The signatures that remain all contain control or high bytes that ordinary text
    # cannot open with, so the ambiguity does not reach them. That distinction is the
    # rule now: a signature made of printable ASCII cannot classify, because printable
    # ASCII is what documents are made of.
    # BZh and Rar! are GONE too. Last round I stated the rule — a signature made of
    # printable ASCII cannot classify — removed %!PS, and then left two more printable
    # signatures sitting in the same tuple I was editing. Stating a rule and applying
    # it to one member of the list it governs is the fifth time in this PR that a
    # class was named and one instance fixed.
    #
    # Every signature that remains contains a control or high byte, which is the
    # property that makes it a signature rather than a word.
    if head.startswith((b"PK\x03\x04", b"\x1f\x8b",
                        b"\xfd7zXZ", b"7z\xbc\xaf\x27\x1c",
                        b"\x04\x22\x4d\x18", b"(\xb5/\xfd")):
        return True
    if saw_bom:
        return False   # a real BOM and no container magic: genuine text
    return b"\x00" in head


def _encoding_of(path):
    """Pick a decoder from the byte-order mark, defaulting to UTF-8.

    A UTF-16 file is perfectly ordinary text, but read as UTF-8 every ASCII
    character is separated by a NUL, so no pattern here can match and the file
    scanned clean. Assuming "textual credential" means "ASCII-compatible" was an
    unstated premise under every pattern in this file.
    """
    if _refuses_to_open(path):
        return "utf-8"
    try:
        with open(path, "rb") as handle:
            head = handle.read(4)
    except OSError:
        return "utf-8"
    if head.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        return "utf-32"
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "utf-16"
    if head.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    return "utf-8"


_C_ESCAPES = {"a": 7, "b": 8, "f": 12, "n": 10, "r": 13, "t": 9, "v": 11,
              "\\": 92, '"': 34}


def _unquote_c(text):
    """Decode git's C-quoted path form to a str.

    NOT json.loads. With core.quotePath at its default, git emits non-ASCII bytes as
    OCTAL escapes — \\360\\237... for an emoji — which JSON rejects, so the whole
    decode fell through to a raw fallback and the escape sequences were scanned
    instead of the filename. A backslash-digit run also swallows a following pattern
    boundary, which is how a credential-shaped name survived intact.
    """
    if not (text.startswith('"') and text.endswith('"')):
        return text
    # surrogateescape on the way back out, matching decode_text. `text` reaches here
    # already decoded, so it may carry an undecodable byte as a lone surrogate, and a
    # plain .encode() raises on one — a traceback where a filename belongs. This also
    # restores the original byte rather than the three bytes of a replacement glyph.
    body, out, i = text[1:-1], bytearray(), 0
    while i < len(body):
        ch = body[i]
        if ch != "\\":
            out.extend(ch.encode("utf-8", "surrogateescape"))
            i += 1
            continue
        nxt = body[i + 1] if i + 1 < len(body) else ""
        if nxt in _C_ESCAPES:
            out.append(_C_ESCAPES[nxt])
            i += 2
        elif nxt.isdigit():
            octal = body[i + 1:i + 4]
            try:
                out.append(int(octal, 8))
            except ValueError:
                out.extend(body[i:i + 2].encode("utf-8", "surrogateescape"))
            i += 1 + len(octal)
        else:
            out.extend(body[i:i + 2].encode("utf-8", "surrogateescape"))
            i += 2
    return decode_text(bytes(out))


def _diff_new_path(line):
    """New-side path from a `diff --git` header, C-quoting decoded.

    Git wraps a path containing a tab, quote, backslash or non-ASCII byte in double
    quotes and escapes it, so the literal " b/" this used to search for is absent —
    and a credential-shaped filename with a tab in it produced no candidate at all.
    """
    marker = line.rfind(' "b/')
    if marker != -1:
        return _unquote_c(line[marker + 1:].strip())[2:]
    # SOLVE the header; do not search it. `find(" b/")` takes the FIRST such
    # substring, which sits inside the OLD path when a filename contains " b/" —
    # git does not quote a path for a space alone. A file with CONTENT survived that
    # because the `+++ b/<path>` header overwrote the guess, but an EMPTY added file
    # has no `+++` line, so the hit kept a malformed locator, failed to reconcile
    # with the working-tree hit, and one credential was reported twice.
    #
    # `--no-renames` is pinned on both log invocations, so the two sides of this
    # header are always the SAME path — which determines the split point exactly,
    # for every filename, with no search. (Pinning it also widens coverage: a rename
    # shows as delete + add, so a credential-bearing file renamed into place has its
    # content scanned instead of being summarised as a similarity index.)
    prefix = "diff --git a/"
    if line.startswith(prefix):
        rest = line[len(prefix):]
        if len(rest) >= 3 and (len(rest) - 3) % 2 == 0:
            half = (len(rest) - 3) // 2
            if rest[half:half + 3] == " b/" and rest[:half] == rest[half + 3:]:
                return rest[half + 3:]
    # A header this cannot solve is a rename that slipped the pin, or a shape not
    # produced by the pinned options. Fall back rather than drop the file: a guessed
    # locator on a real hit is still a hit, and the reconciliation defect above is
    # about the empty-file path, which the exact solve now owns.
    marker = line.find(" b/")
    return line[marker + 3:] if marker != -1 else ""


def _selftest_jwt(role="service_role", tail="a" * 24):
    """A syntactically valid privileged JWT, built rather than written."""
    def seg(obj):
        raw = json.dumps(obj).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")
    return f"{seg({'alg': 'HS256'})}.{seg({'role': role})}.{tail}"


def redact(text):
    """Strip credential-shaped substrings from anything about to be printed.

    Applied at the PRINT site, not at each call that records a hit. Twice now a new
    pass has been added that stored a raw credential-bearing location — the ref-name
    pass last round, the filename pass this round — and each was fixed where it was
    found while the next one shipped with the same defect. A choke point cannot be
    forgotten by code written later, which is the only property that actually holds.

    CONTROL CHARACTERS ARE ESCAPED TOO, in the same choke point and for the same
    reason. A tracked filename may contain a newline, and this file prints filenames.
    `<key>\n::warning::forged` put that second fragment at column zero of the CI log,
    where a GitHub Actions runner reads it as a WORKFLOW COMMAND — repository metadata
    forging annotations in the job that is auditing it. The same trick can truncate or
    reflow the diagnostic with a carriage return, and the value is withheld on purpose,
    so the location text is all a reader has and it must arrive intact.

    Escaping happens AFTER redaction: a control character inside a credential-shaped
    run must not break the pattern before the redactor sees it.
    """
    for _, _label, pattern in PATTERNS:
        text = pattern.sub("<redacted>", text)
    text = JWT.sub("<redacted-jwt>", text)
    return _escape_controls(text)


def _escape_controls(text):
    """Render control characters visibly so printed text cannot forge log structure.

    UNDECODABLE BYTES TOO. They now survive decoding as lone surrogates rather than
    as U+FFFD (see UNDECODABLE_LOW), and a lone surrogate raises UnicodeEncodeError
    on print — turning a diagnostic into a traceback, which for a required gate is a
    crash where a verdict belongs. Rendered as the raw byte they stand for, which is
    also more use to a reader than one replacement glyph per corrupted byte.
    """
    out = []
    for ch in text:
        if _undecodable(ch):
            out.append(f"\\x{ord(ch) - 0xDC00:02x}")
        elif "\ud800" <= ch <= "\udfff":
            # Not from our decoder, and still unprintable. No path produces one
            # today; a bare `else` that assumes so is how the last one got in.
            out.append(f"\\u{ord(ch):04x}")
        elif ch >= " " and ch != "\x7f":
            out.append(ch)
        else:
            out.append({"\n": "\\n", "\r": "\\r", "\t": "\\t"}.get(
                ch, f"\\x{ord(ch):02x}"))
    return "".join(out)


def _inside_repo(path):
    real = os.path.realpath(path)
    return real == REPO_REAL or real.startswith(REPO_REAL + os.sep)


def privileged_jwt(line):
    """True only for JWTs whose decoded payload claims a privileged role.

    Legacy Supabase `anon` and `service_role` keys share one three-segment shape. A
    shape-only match therefore fails Tier 1 on an anon key, which is *designed* to be
    client-visible under RLS — the false-positive rot this file's header warns about.
    Undecodable payloads are not flagged: a gate should not fail on what it cannot read.
    """
    for match in JWT.finditer(line):
        if _embedded(line, match):
            # The JWT family decodes rather than pattern-matches, so it walked its
            # own regex and never reached scan_line's continuation filter — the same
            # false RED survived here for one more round.
            continue
        if _privileged_payload(match.group(1)):
            return True
    return False


def _privileged_payload(payload):
    """True if this JWT payload decodes to a claim of a privileged role.

    Split out so scan_detail and privileged_jwt ask ONE question rather than two
    implementations of it.
    """
    try:
        raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        claims = json.loads(raw)
        # The payload is attacker-shaped: it may decode to a list, or carry a `role`
        # that is a dict. `{"role": []}` made the set test raise TypeError on an
        # unhashable value, aborting the whole gate over one public fixture. Check
        # the types before trusting them.
        if not isinstance(claims, dict):
            return False
        role = claims.get("role")
        return isinstance(role, str) and role in PRIVILEGED_JWT_ROLES
    except (binascii.Error, UnicodeDecodeError, ValueError, RecursionError):
        # RecursionError joins the list because json.loads raises it on a deeply
        # nested payload — ~100k nested arrays in one token — and it does NOT inherit
        # from ValueError, so it escaped and took the whole gate down. Same shape as
        # every other crash in this review: one hostile value ending the run instead
        # of being reported as one undecodable token.
        return False


def _env_note():
    """Interpreter and Unicode versions, for the drift this gate depends on.

    Printed on BOTH selftest exits. It was only on the full one, so the consumers
    who copy just this file — the installation the portable template advertises —
    got no diagnostic at all, which is precisely the population the note exists for.
    """
    return (f"(python {sys.version_info.major}.{sys.version_info.minor}, "
            f"unicode {unicodedata.unidata_version})")


def _continues_identifier(line, end):
    r"""True if the character at `end` continues the preceding token.

    RAW docstring. The regex quoted below contains a backslash escape that Python
    does not recognise in a normal string, so this emitted a SyntaxWarning on every
    CI run — visible in the Tier 1 log for rounds without anyone reading it. That is
    cosmetic today and a hard failure later: invalid escape sequences are scheduled
    to become SyntaxError, and this file is vendored into consumer repos, where a
    newer interpreter would stop the gate from running at all rather than make it
    report something wrong. Found by reading the job log of a green run instead of
    trusting the tick.

    By Unicode CATEGORY, not by an enumerated class. `(?![\w-])` still admitted a
    combining mark or a zero-width joiner, so a placeholder followed by one read as
    a credential — the third false RED from the same edit. Enumerating the offenders
    is what produced the first two, so this asks what the character IS. Note the
    contract narrowed again in round 33: an identifier continuation per Python, a
    combining mark (Mn/Mc/Me), or one of the two JOIN CONTROLS — NOT the whole Cf
    category, which wrongly swallowed separators like U+200B and suppressed real
    credentials. Do not widen it back to Cf.
    """
    if end >= len(line):
        return False
    ch = line[end]
    # Python's OWN identifier property first — it is the built-in that encodes
    # "continues an identifier", including connector punctuation like U+203F which
    # my category list missed. Then grapheme extension: combining marks, and the two
    # join controls. NOT the whole Cf category: that rejected U+200B ZERO WIDTH
    # SPACE, which is a separator, and suppressed a real credential.
    #
    # Too broad and too narrow at once, which is what an enumeration does. This is
    # the fifth failure of one edit, and the version that finally holds is the one
    # that asks the language and the standard instead of listing cases.
    if ("A" + ch).isidentifier():
        return True
    return _extends_grapheme(ch)


def _extends_grapheme(ch):
    """True for characters that EXTEND the preceding grapheme but cannot stand alone.

    Split out from _continues_identifier because the leading-boundary walk needs
    exactly this and not the identifier half.
    """
    if ch in GRAPHEME_JOINERS:
        return True
    if unicodedata.category(ch) in ("Mn", "Mc", "Me"):
        return True
    cp = ord(ch)
    return any(lo <= cp <= hi for lo, hi, _ in GRAPHEME_EXTENDER_RANGES)


def _matched_span(line):
    """(start, end) of the first REPORTABLE credential, or None.

    Delegates to scan_detail so the span always belongs to the match that produced
    the label. It used to re-search independently and could return a different one.
    """
    return scan_detail(line)[1]


def judge_line(text, truncated=False):
    """('hit', [(label, identity), ...]) | ('unknown-boundary', []) | (None, []).

    EVERY unambiguous match, not the first. scan_matches already enumerates them and
    this function used to discard the rest, so a line holding two distinct keys was
    reported as one credential — a reader rotates what the report names, reruns, and
    finds the next one. An incomplete failure list is the same defect as an
    unqualified pass, in the branch that fails.

    `identity` is a short hash of the MATCHED TEXT. It never reaches the output — the
    value stays withheld — and exists so two reports of the same stored bytes can be
    reconciled without comparing the displayed label, which is what merged two real
    credentials in round 66.

    Both kinds of uncertainty are per-MATCH and both live here: a match touching
    an undecodable byte, and a match ending at a truncation boundary. Callers pass
    what they know.
    """
    found, ambiguous = [], False
    for label, span, leading, trailing in scan_matches(text):
        # THE WHOLE LEADING CONTEXT the embedding logic reads, not the one adjacent
        # character. _preceded_by_identifier walks left across combining marks and
        # join controls and then across the identifier run they attach to, so an
        # undecodable byte two characters back still decides the answer: put one
        # before a combining mark before a credential and the embedding test says
        # "not embedded" and reports a RED, while the same position holding a letter
        # makes the whole sequence embedded and reports nothing. The uncertainty was
        # real and unstated — which is the outcome this judge exists to prevent.
        #
        # Derived from the same predicate the walk uses rather than a second copy of
        # its rule. Eleventh instance in this PR of a defence that knew less than the
        # code it was defending.
        # INSIDE the match always counts: an undecodable byte there means the value
        # itself is not known. The two SIDES count only if _embedded reads them.
        touches = any(_undecodable(ch) for ch in text[span[0]:span[1]])
        if leading:
            touches = touches or _undecodable_in_leading_context(text, span[0])
        if trailing:
            touches = touches or (span[1] < len(text)
                                  and _undecodable(text[span[1]]))
            if truncated and span[1] >= len(text):
                # The discarded next byte may continue the identifier, which would
                # embed this match — the cut would otherwise manufacture a credential.
                # Only where a trailing character could embed anything: for a family
                # that deliberately stops short, the cut hides nothing that matters
                # and dropping the hit under-reported a definite credential.
                touches = True
        if touches:
            ambiguous = True
            continue
        found.append((label, _identity(text[span[0]:span[1]])))
    # BOTH, always. Returning the hits and dropping `ambiguous` meant a line holding
    # a clean credential AND an unjudgeable one reported only the first — so after
    # rotating what the report named, a rerun revealed a coverage gap that had been
    # there all along, and the original failure list had looked exhaustive.
    #
    # Third time this exact shape has appeared: the NUL-bearing hunk stopped
    # reporting its gap once a hit was found (round 70), the failing path printed no
    # unscanned list at all (round 62), and now the per-line judge. Finding something
    # is not evidence of having read everything, and the two facts are independent
    # everywhere they meet.
    return found, ambiguous


def _undecodable_in_leading_context(line, start):
    """True if any byte the leading-boundary walk would read failed to decode.

    The walk in _preceded_by_identifier consumes extenders, then the identifier run
    those extenders attach to. Both are covered by one predicate here — "could this
    character take part in an identifier" — so this cannot drift from the walk the
    way a hand-copied stopping rule would.

    An undecodable byte inside that run is not a boundary and not a letter; it is a
    byte whose identity decides whether the match is embedded, and nobody knows it.
    """
    i = start - 1
    while i >= 0 and (("A" + line[i]).isidentifier()
                      or _extends_grapheme(line[i])
                      or _undecodable(line[i])):
        if _undecodable(line[i]):
            return True
        i -= 1
    return False


def _identity(value):
    """Stable short hash of a matched credential, for reconciliation only.

    NEVER printed. The working-tree pass and the history pass both see a credential
    added in the range and still present on disk, and reporting it twice inflates the
    count of things a reader must rotate. Reconciling on the displayed label instead
    would merge two DIFFERENT keys of the same family — the failure this file shipped
    in round 66 and must not repeat.
    """
    # surrogateescape, matching decode_text — the same stored bytes must hash the
    # same on every surface, and errors="replace" collapsed every undecodable byte to
    # "?" so two different values could share an identity. Matches containing one are
    # judged ambiguous and never arrive here; that is a caller-side property, and this
    # file has been bitten four times by a rule only its callers enforced.
    return hashlib.sha256(
        value.encode("utf-8", "surrogateescape")).hexdigest()[:16]


def _preceded_by_identifier(line, start):
    """True if a real identifier ends immediately before `start`.

    Walks LEFT past continuation characters to find something they could attach to.
    Reusing the single-character trailing predicate here was wrong in the direction
    I keep failing in: a stray combining mark at the start of a line, or after a
    space, has no identifier to continue, and treating it as one suppressed a real
    credential outright.
    """
    # Walk left over EXTENDERS ONLY. Using the trailing predicate here consumed the
    # identifier as well — letters are continuations too — so the walk ran off the
    # start of the line and every embedded match reported "not embedded". The two
    # questions are different: "may this character continue a token" is not "is this
    # character something a mark could be attached to".
    i = start - 1
    while i >= 0 and _extends_grapheme(line[i]):
        i -= 1
    if i < 0:
        return False
    # Read the ACTUAL left context, not a fictitious one. `("A" + ch).isidentifier()`
    # asked whether the character could continue an imaginary identifier, so U+203F
    # UNDERTIE at a line start — which continues an identifier but cannot start one —
    # suppressed a real credential. Collect the run that genuinely precedes the match
    # and ask whether IT is an identifier. `_xoxb-...` still suppresses, because "_"
    # can start one; `‿xoxb-...` no longer does, because "‿" cannot.
    j = i
    while j >= 0 and (("A" + line[j]).isidentifier() or _extends_grapheme(line[j])):
        j -= 1
    return line[j + 1:i + 1].isidentifier()


def _embedded(line, m, mid=None):
    """True if this match sits inside a larger identifier, at either end.

    The TRAILING check is skipped for families whose match deliberately stops short
    of the surrounding text — Postgres ends at "@" with the host still to come. The
    LEADING check applies to every family: nothing about ending early makes it fine
    for the scheme to be glued to a preceding identifier.

    Except when the match OPENS with a character that cannot be part of an identifier.
    PEM armor starts with five hyphens, so armor glued to a preceding word (write it
    as `prefix` immediately followed by a BEGIN PRIVATE KEY header — spelled out here
    it would trip this scanner, which is the fourth time a comment in this file has
    had to be de-literalised rather than exempted) was suppressed as an embedded
    identifier — a real private key, in exactly the kind of
    concatenated or generated text where one shows up unquoted, invisible to both the
    working-tree and history scans. A preceding letter cannot absorb a match that
    begins with a delimiter; the delimiter is already the boundary.

    Asked as a property of the matched text, not as another id-keyed table. "Which
    families start with a delimiter" is a list that goes stale the moment someone adds
    a family; "does this match start with a character that can continue an identifier"
    is the actual question, and it answers itself for families that do not exist yet.
    """
    if mid not in NON_TOKEN_IDS and _continues_identifier(line, m.end()):
        return True
    opener = line[m.start():m.start() + 1]
    if opener and not (("A" + opener).isidentifier() or _extends_grapheme(opener)):
        return False
    return _preceded_by_identifier(line, m.start())


def scan_detail(line):
    """(label, span) of the first REPORTABLE credential in this line, or (None, None).

    One function, because there were two. scan_line() returned a label and
    _matched_span() independently re-searched for a span, and they did not agree:
    _matched_span returned the first JWT it saw without checking the role or the
    embedding, while scan_line skips both. A line holding an embedded or anon JWT and
    then a real service-role one produced a label from the second and a span from the
    first — so the boundary guard judged the wrong match and discarded the real hit as
    unscanned.

    Two implementations of "find the first reportable credential" is the same
    duplicate-logic failure this PR has found in tables, in passes, and in file pairs.
    Callers that need only the label call scan_line, which now delegates here, so the
    two answers cannot drift apart again.
    """
    # scan_matches now carries the two boundary flags judge_line needs; a plain
    # report needs only the label and span, so they are dropped HERE rather than by
    # every caller — the same "one function, not two" rule this docstring is about.
    for label, span, _leading, _trailing in scan_matches(line):
        return label, span
    return None, None


def _boundaries_read(line, m, mid=None):
    """(leading, trailing) — which sides _embedded ACTUALLY consults for this match.

    Derived by mirroring _embedded's own two conditions, and it exists because
    judge_line was asking about boundaries the embedding logic never looks at. A
    Postgres URL deliberately ends at "@" with the host still to come, and PEM armor
    ends at five hyphens: for those families a trailing character cannot embed
    anything, so an undecodable byte there decides nothing. PEM armor also OPENS with
    a delimiter, and _embedded returns False on that without ever reading leftward.

    Treating those as uncertainty discarded DEFINITE credentials into a qualified
    pass — an under-report, which is the worse direction, and it came from the
    round-75 fix that widened the leading check. Widening a guard is the same class
    of error as narrowing one when the guard is not asking the code's own question.
    """
    trailing = mid not in NON_TOKEN_IDS
    opener = line[m.start():m.start() + 1]
    leading = bool(opener) and (("A" + opener).isidentifier() or _extends_grapheme(opener))
    return leading, trailing


def scan_matches(line):
    """Yield (label, span, leading, trailing) for every reportable credential, in order.

    scan_detail returns the first, which is all a plain report needs. judge_line
    needs them all: an ambiguous match does not make the line unjudgeable, only that
    match. Returning one match made a real credential after an undecodable-adjacent
    one disappear into a warning.

    The two booleans travel WITH the match because `mid` is known here and nowhere
    downstream. judge_line re-deriving them would be a second copy of _embedded's
    rules, which is the drift this file has been punished for repeatedly.
    """
    for mid, label, pattern in PATTERNS:
        for m in pattern.finditer(line):
            if not _embedded(line, m, mid):
                yield (label, m.span()) + _boundaries_read(line, m, mid)
    for m in JWT.finditer(line):
        if _embedded(line, m):
            continue
        if _privileged_payload(m.group(1)):
            yield ("Supabase service-role JWT", m.span()) + _boundaries_read(line, m)


def scan_line(line):
    """Return the label of the first credential shape in this line, or None."""
    return scan_detail(line)[0]


def files(unscanned):
    """Yield (path, scan_contents) for every path GIT TRACKS.

    `git ls-files`, not `os.walk`. The walk enumerated the filesystem, so in the
    portable template — where this step ran after `npm ci`, tests and `npm run
    build` UNTIL round 22 moved it ahead of them — generated bundles and fixtures
    were scanned and reported as credentials "committed" by the PR. A required gate that goes permanently red on build output
    is one every consumer learns to ignore, which is worse than not shipping it.

    Tracked enumeration also fixes two symlink holes for free: a symlink to a
    directory landed in os.walk's `dirs` and was never yielded at all, and the
    containment test below used to run *before* anything was scanned, so a link
    pointing outside the checkout was discarded name and all.

    No self-exclusion. An earlier draft skipped every file named check_secrets.py
    anywhere in the tree, which would also have skipped `tools/check_secrets.py`
    while still reporting a complete scan.
    """
    try:
        # BYTES, not text=True. Git tracks any byte sequence but the NUL-delimited
        # output was decoded strictly, so one non-UTF-8 filename raised
        # UnicodeDecodeError and aborted the gate — the same crash class as the file
        # contents fix two rounds ago, in the enumeration that replaced it.
        out = subprocess.run(["git", "ls-files", "-z"], cwd=REPO,
                             capture_output=True, timeout=120)
        tracked = ([os.fsdecode(b) for b in out.stdout.split(b"\0")]
                   if out.returncode == 0 else None)
    except (OSError, subprocess.SubprocessError):
        tracked = None

    if tracked is None:
        # Not a git checkout (local ad-hoc run). Fall back to the walk and say so —
        # a fallback that silently changes what "complete scan" means is the exact
        # shape this review keeps finding.
        print("secrets: note — not a git checkout, walking the filesystem instead "
              "of tracked paths; untracked build output may be included.",
              file=sys.stderr)
        # onerror, because os.walk's default is to SWALLOW the failure and omit the
        # whole subtree — so one directory this process cannot enter removed every
        # file under it from the scan and the run still printed an unqualified OK.
        # Same defect the reference checker had; fixed there last round and not here,
        # which is what happens when two files share a bug and only one is named.
        walk_errors = []
        for root, dirs, names in os.walk(REPO, onerror=walk_errors.append):
            while walk_errors:
                err = walk_errors.pop()
                unscanned.append(
                    f"{os.path.relpath(err.filename or REPO, REPO)}: directory could"
                    f" not be read ({type(err).__name__}) — SUBTREE NOT SCANNED")
            # A symlink to a DIRECTORY lands in `dirs`, never in `names`, and
            # os.walk does not follow it. So it was yielded by neither branch of
            # this loop and vanished from the scan entirely — while the tracked
            # branch yields it and scans its link TEXT, which is where
            # `innocuous -> sk-ant-<key>` hides. The fallback was strictly weaker
            # than the branch it stands in for, silently.
            #
            # Yielded, not followed. Following would leave the repo and can loop;
            # the tracked branch does not follow either, because containment
            # protects contents. What changes is that the link's own text is now
            # read, and the subtree it points at is REPORTED as not entered rather
            # than being absent from the accounting.
            for d in list(dirs):
                p = os.path.join(root, d)
                if os.path.islink(p):
                    rel_link = os.path.relpath(p, REPO)
                    yield rel_link, False
                    unscanned.append(
                        f"{rel_link}: directory symlink — target NOT entered")
            dirs[:] = [d for d in dirs
                       if d not in SKIP_DIRS
                       and not os.path.islink(os.path.join(root, d))]
            for name in names:
                tracked_path = os.path.relpath(os.path.join(root, name), REPO)
                yield tracked_path, not name.lower().endswith(SKIP_SUFFIXES)
        # Drained again after the loop: os.walk can report a failure as the last
        # thing it does, and a top-of-loop drain loses exactly that case.
        while walk_errors:
            err = walk_errors.pop()
            unscanned.append(
                f"{os.path.relpath(err.filename or REPO, REPO)}: directory could"
                f" not be read ({type(err).__name__}) — SUBTREE NOT SCANNED")
        return

    for rel in tracked:
        if not rel:
            continue
        # Suffix gates CONTENTS ONLY — it used to skip the whole entry, so
        # `sk-ant-<key>.png` was a tracked path holding a live credential nothing
        # ever looked at.
        yield rel, not rel.lower().endswith(SKIP_SUFFIXES + ARCHIVE_SUFFIXES)


# Header detection is STRUCTURAL, not textual. Three rounds of this review found
# three different ways for file content to impersonate a `+++` header: `++x` became
# `+++x`, then `++ x` became `+++ x`, then `++ b/sk-ant-...` became `+++ b/sk-ant-...`
# — which matches any plausible header pattern exactly. There is no regex that
# separates them, because a patch line's meaning depends on where it sits, not what
# it says.
#
# So: file headers appear BEFORE the first `@@` hunk marker of a file section; every
# `+` line AFTER one is content. Tracking that boundary ends the whole class.
HUNK_START = re.compile(r"^@@ ")
# The new-side start line, so a history hit can name a file and a line instead of
# just a commit. With values withheld, "history <sha>:0" left the reader grepping a
# whole patch for something they were deliberately not shown.
HUNK_NEW = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)")


class HistoryUnavailable(Exception):
    """The range scan could not run. Never treat this as 'found nothing'."""


# Chunked reads with select(), so a stalled git cannot hold the gate: plain
# read(CHUNK) blocks until the chunk fills or the process exits, so a child that
# wrote one byte and slept never returned to the deadline check.
CHUNK = 65536
# A NUL-free file with no newline arrives as ONE ordinary hunk line even without
# --text, so removing --text bounded the binary case and left this one unbounded: a
# large minified bundle was accumulated whole before anything was yielded. Past the
# budget the rest of that line is dropped and REPORTED, never silently truncated.
LINE_BUDGET = 4 << 20
# Whole-file cap for the working-tree pass. Generous enough that no ordinary tracked
# source or document reaches it, so the qualification it prints stays rare enough to
# mean something.
TREE_FILE_BUDGET = 64 << 20


def _bounded_lines(proc, deadline, rng, unscanned, every_line_in_scope=False):
    """Yield decoded lines, never blocking past the deadline.

    `every_line_in_scope` because the in-scope test below is a SHAPE test written for
    the main diff pass, and the raw-header pass reuses this reader. Header lines start
    with neither "+" nor a space nor "Author:", so an oversized unknown header was
    truncated and recorded as omitted coverage by nobody: the credential after the cut
    vanished and the run reported an unqualified pass. A reader cannot infer its
    caller's scope, and guessing it from the first byte is the same enumeration
    mistake as the magic-byte list — so the caller declares it.
    """
    buf = bytearray()   # bytearray, not bytes: `buf += block` on bytes recopied the
    over = False        # whole buffer every 64 KiB, which is quadratic on a big line
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            proc.kill()
            raise HistoryUnavailable(f"git log timed out on range {redact(rng)!r}")
        if select.select([proc.stdout], [], [], min(remaining, 5.0))[0]:
            block = proc.stdout.read1(CHUNK)
            if not block:
                break
            if over:
                # DISCARD while over budget. Appending and relying on the newline
                # loop to clear the flag meant the remainder of a huge newline-free
                # line accumulated in full — so the three readers advertising a
                # memory bound did not have one. Drop bytes until the line ends.
                idx = block.find(b"\n")
                if idx == -1:
                    continue
                buf, over = bytearray(block[idx + 1:]), False
            else:
                buf += block
            while b"\n" in buf:
                idx = buf.index(b"\n")
                line, buf = bytes(buf[:idx]), buf[idx + 1:]
                yield line, False
            if len(buf) > LINE_BUDGET:
                # Only `+` lines and commit-message text are in scan scope, so an
                # oversized `-` line is not omitted coverage — it was never a
                # candidate. The first byte is enough to tell.
                if (every_line_in_scope
                        or buf[:1] in (b"+", b" ")
                        or buf.startswith((b"Author:", b"Commit:"))):
                    # Identity lines are scanned too, so an oversized one drops real
                    # coverage — but they begin with neither "+" nor a space, so the
                    # first-byte test alone let a 4 MiB author name swallow a
                    # credential and still report an unqualified pass.
                    unscanned.append(f"line over {LINE_BUDGET >> 20} MiB — NOT scanned")
                # TRUNCATED flag, so a match ending at the cut can be suppressed. The
                # discarded next byte may continue the identifier, which would make
                # the match embedded — so the cut itself manufactured a credential.
                # _text_lines has carried this flag since round 61; this reader, the
                # other half of the same pair, never did.
                yield bytes(buf), True
                buf, over = bytearray(), True
        elif proc.poll() is not None:
            break
    if buf and not over:
        yield bytes(buf), False


def history_hits():
    """Scan added lines and commit messages across the pushed range.

    Bounded on purpose: text only, no archives, no recursion. The archive machinery
    is where six review rounds found bypass after bypass, so it is gone. What remains
    covers the case that actually bites on a private repo with no vendor scanner
    behind it — a credential added in one commit and deleted in the next, invisible to
    a clean working tree but still fetchable by anyone who cloned the branch.

    Raises rather than returning empty when it cannot run: a scan that did not happen
    is not a scan that found nothing.
    """
    rng = os.environ.get("TIER1_DIFF_RANGE", "").strip()
    if not rng:
        return [], False, []

    # Whitespace-SPLIT, because the scope is no longer always one `A..B` token. A push
    # that CREATES a ref has to exclude every other already-published remote ref, not
    # just the default branch, and `HEAD ^<sha> ^<sha>` is how git spells that.
    # Splitting cannot cut a ref name in half: git-check-ref-format(1) forbids ASCII
    # space in a ref name. The workflow puts only resolved SHAs and `^`-prefixed SHAs
    # here — never ref TEXT, which can itself be credential-shaped.
    rng_args = rng.split()

    # STREAMED, not buffered. capture_output=True held the entire forced-text log
    # in memory before scanning a line, and --text (added last round to stop one NUL
    # byte hiding a file) makes every binary blob part of that log — a single 16 MiB
    # asset becomes a 16 MiB patch, and several revisions can exhaust a runner. My
    # own fix created that exposure; reading line by line removes it, and the
    # deadline below still bounds the time.
    deadline = time.monotonic() + 300
    try:
        proc = subprocess.Popen(
            # --pretty=fuller emits Author: and Commit: identity lines. A credential
            # placed in an author or committer name is stored in the commit object
            # forever, and the default format does not even print the committer.
            #
            # --no-use-mailmap, because .mailmap rewrites those identity lines before
            # this parser sees them. A commit whose raw author name is a credential,
            # plus one pre-existing mailmap rule matching its email, printed a benign
            # name and the gate reported an unqualified OK — while the credential sat
            # in the commit object, which is what anyone who fetched the branch has.
            # The gate must read what git STORED, not what git renders for humans.
            #
            # --diff-merges=first-parent, not -m. With -m, git emits a merge's diff
            # against EVERY parent, so merging a long-lived branch reported the target
            # branch's own pre-existing lines as additions: a credential-shaped line
            # that had been on main for weeks failed the gate for a push that did not
            # introduce it. Verified both ways on a two-parent merge. First-parent
            # merge diffs still show everything the merge brought onto this branch,
            # and the newly reachable non-merge commits are still walked individually,
            # so nothing stops being scanned — only the double-counting stops.
            # --src-prefix/--dst-prefix FORCED. With diff.noprefix=true in local or
            # global config — a setting people really do set — git emits `+++ <path>`
            # instead of `+++ b/<path>`, and the parser below strips two characters
            # unconditionally. A file named with a credential lost its first two
            # characters and stopped matching, so the scan exited 0. The parser reads
            # a format this command now guarantees rather than one the ambient
            # environment gets a vote in.
            # --no-textconv: a configured textconv driver makes `git log -p` print a
            # HUMAN rendering instead of the stored bytes, so `*.dat diff=hide` with a
            # driver emitting anything harmless replaced the credential in the patch
            # while the blob kept it. The gate must read what git STORED — the same
            # rule that --no-use-mailmap enforces for identities, in the surface where
            # the substitution is fully attacker-chosen.
            #
            # --root: with log.showRoot=false the initial commit is emitted without a
            # patch, so a credential added in the root commit and deleted later was
            # invisible to the HEAD fallback that exists precisely to walk everything.
            #
            # Both are ambient-configuration defences, and they are the third and
            # fourth in three rounds after .mailmap and diff.noprefix. The pattern is
            # the point: every default this command does not pin is a setting the
            # repository under test gets to choose.
            # Every option here pins a default the repository under test could
            # otherwise choose. Six exploitable ones have been found in four rounds
            # (.mailmap, diff.noprefix, textconv, log.showRoot, replace refs,
            # logOutputEncoding, ignoreSubmodules), so the rule is now: this command
            # states what it wants and inherits nothing.
            #
            # --no-replace-objects is a GIT-level option and must precede `log`: a
            # refs/replace/<sha> entry substitutes a harmless commit for the stored
            # one, so the gate audited an object the branch does not contain.
            # --encoding=UTF-8 because i18n.logOutputEncoding=UTF-16 made git drop the
            # identities and message entirely while exiting 0.
            # --ignore-submodules=none because diff.ignoreSubmodules=all removes
            # gitlink sections, and a submodule path is a filename like any other.
            ["git", "--no-replace-objects", "log", "-p",
             "--diff-merges=first-parent", "--no-use-mailmap",
             "--no-textconv", "--root", "--encoding=UTF-8", "--no-renames",
             "--ignore-submodules=none",
             "--src-prefix=a/", "--dst-prefix=b/",
             "--no-color", "--unified=0", "--pretty=fuller", *rng_args],
            cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise HistoryUnavailable(f"could not run git log: {exc}")

    hits, commit, in_hunk = [], "?", False
    cur_file, new_lineno, hit_at = "?", 0, 0
    pending_new = ""
    reported_new = ""
    deleted_section = False
    binary_skipped = []
    unscanned = []
    for raw, truncated in _bounded_lines(proc, deadline, rng, unscanned):
        line = decode_text(raw)
        # Identity lines are NOT scanned here. This pass owns diff content; the raw
        # pass owns everything the commit object stores, identities included.
        #
        # They used to be scanned in both, deduplicated afterwards. That produced two
        # findings for one credential whenever the wordings differed, and — worse —
        # collapsed two DIFFERENT credentials in one message into one finding when
        # they matched, because the displayed tuple carries no way to tell them apart.
        # Overlap plus reconciliation was the wrong shape: disjoint ownership needs no
        # reconciliation and cannot under-report.
        #
        # The raw pass is the right owner because it reads with --encoding=none and so
        # cannot be suppressed by a commit-declared encoding, which is exactly how the
        # formatted pass was defeated last round.
        if line.startswith("Author:") or line.startswith("Commit:"):
            continue
        if line.startswith("commit "):
            commit, in_hunk = line.split()[1][:10], False
            # Reset the locator too: a message is emitted BEFORE its own diff, so a
            # credential in an older commit's message was being reported against the
            # last file seen in a newer commit.
            cur_file, new_lineno, hit_at = "?", 0, 0
            continue
        if line.startswith("Binary files ") and line.endswith(" differ"):
            # A pure DELETION has /dev/null on the new side: nothing was added, so
            # nothing was omitted from an added-lines scan. Recording it turned an
            # ordinary "remove the big file" push into a qualified pass, which is
            # noise that teaches people to ignore the qualification.
            # STRUCTURE, not string shape. `Binary files <A> and <B> differ` cannot
            # be split reliably, because a path may itself contain " and " and may end
            # in "/dev/null" — so both the suffix test and the prefix test I added
            # last round classify a MODIFICATION of `foo and /dev/null` as a deletion
            # and drop its coverage note.
            #
            # git states the answer separately: a deletion carries `deleted file mode`
            # in the same section, an addition carries `new file mode`, a modification
            # carries neither. That flag is set below and reset at each `diff --git`,
            # so this asks the diff what happened rather than parsing a sentence that
            # was never designed to be parsed.
            if not deleted_section:
                binary_skipped.append(f"history {commit}: {redact(line)}")
            continue
        if not in_hunk and line.startswith("copy to "):
            # `copy to` is `rename to`'s twin and was not handled. With
            # diff.renames=copies configured, adding an identical copy under a
            # credential-shaped name emits copy metadata and NO +++ or `new file
            # mode` line, so the destination name reached no branch of this parser.
            copied = _unquote_c(line[len("copy to "):].strip())
            if report_filename(copied, "copied filename", hits, unscanned,
                               commit=f"history {commit}"):
                # A MODIFIED copy emits both this metadata AND a `+++` header, so the
                # destination was reported twice for one filename. Remembered here
                # rather than deduplicated globally: value-blind dedupe on the
                # displayed tuple is exactly what merged two real credentials last
                # round, and the same shape must not come back as a convenience.
                reported_new = copied
            continue
        if not in_hunk and line.startswith("rename to "):
            # A 100%-similarity rename carries NO `+++` header at all, so renaming
            # a file TO an unsafe name and away again inside one range left nothing
            # for either pass to see.
            renamed = _unquote_c(line[len("rename to "):].strip())
            if report_filename(renamed, "renamed filename", hits, unscanned,
                               commit=f"history {commit}"):
                # A MODIFIED rename emits both this metadata AND a `+++` header, so the
                # destination was reported twice for one filename. Remembered here
                # rather than deduplicated globally: value-blind dedupe on the
                # displayed tuple is exactly what merged two real credentials last
                # round, and the same shape must not come back as a convenience.
                reported_new = renamed
            continue
        if not in_hunk and line.startswith("+++ "):
            # NEW-side path only. The filename scan used to read the `diff --git`
            # line, which names both sides, so DELETING a credential-shaped filename
            # was reported as newly committing one — the gate blocking the cleanup
            # it should have been asking for. `+++ /dev/null` is a deletion and
            # carries no new name at all.
            if line == "+++ /dev/null":
                cur_file, new_lineno = "?", 0
                continue
            cur_file, new_lineno = _unquote_c(line[4:].strip())[2:], 0
            # A newly added non-empty file appears TWICE: once via `new file mode`
            # (held in pending_new, so an empty addition with no +++ header is still
            # seen) and again here. Reporting both produced two indistinguishable
            # findings for one filename, and since the value is withheld the reader
            # had no way to tell they were the same leak — they would go looking for
            # a second one that does not exist.
            already = bool(reported_new) and reported_new == cur_file
            reported_new = ""
            if not already:
                report_filename(cur_file, "changed filename", hits, unscanned,
                                commit=f"history {commit}")
            continue
            # `not in_hunk` is load-bearing. An added line reading `++ b/<key>` is
            # emitted as `+++ b/<key>`, so an unconditional check read content as
            # metadata and skipped it. This file's HUNK_START comment documents
            # exactly this class — three earlier variants of it — and I reintroduced
            # it last round by adding a header check without the state guard.

        if line.startswith("new file mode ") and pending_new:
            # An EMPTY new file has no `+++` header and no hunk at all — git emits
            # only `diff --git` and `new file mode`. The two-sided `diff --git` line
            # is not safe to scan directly (it names the old path too, which is how
            # deletions were once misreported), so its new-side path is held until
            # this line proves the section is an addition.
            if report_filename(pending_new, "new filename", hits, unscanned,
                               commit=f"history {commit}"):
                # REMEMBER it, do not merely clear it. The first version of this fix
                # compared the +++ path against pending_new — which this branch had
                # already emptied, so the comparison was always false and the dedupe
                # did nothing. The test caught that; reading the diff did not.
                reported_new = pending_new
            pending_new = ""
            continue
        if line.startswith("deleted file mode "):
            deleted_section = True
            continue
        if line.startswith("diff --git "):
            pending_new = _diff_new_path(line)
            reported_new = ""
            deleted_section = False
            in_hunk = False
            continue
        if HUNK_START.match(line):
            in_hunk = True
            m = HUNK_NEW.match(line)
            new_lineno = int(m.group(1)) if m else 0
            continue
        if in_hunk and line.startswith("+"):
            body, raw_body = line[1:], raw[1:]
            hit_at, new_lineno = new_lineno, new_lineno + 1
        elif not in_hunk and line.startswith("    "):
            # Commit-message body: `git log` indents it four spaces. A credential
            # pasted into a message sits in no file at all, yet anyone who fetches
            # the branch can read it straight out of `git log`.
            # Message body owned by the raw pass too — same reason. Skipped here.
            continue
        else:
            continue
        label = scan_line(body)
        # REGARDLESS of a hit. This used to read `if not label`, so finding one
        # credential in a mangled hunk suppressed the note saying the rest of it was
        # outside coverage — and the failure output then presented a partial finding
        # list as exhaustive, which is the same defect as reporting `unscanned` only
        # on clean runs (fixed in round 62). Finding something is not evidence of
        # having read everything.
        if b"\x00" in raw_body:
            # NUL-bearing hunks are REPORTED, not decoded. This is the fourth time
            # in this review that a subsystem I added to close one finding became
            # the source of the next: archives (round 6), the base-scanner (18),
            # chunked reading (19), and now this decoder. It cost five consecutive
            # rounds — UTF-16, then .gitattributes-forced text, then a density
            # heuristic, then byte alignment, then a printability threshold — and
            # round 26 found the alignment still wrong for UTF-32 and the threshold
            # gameable by binary that renders as printable CJK.
            #
            # A smoke check does not need an encoding-detection subsystem. It needs
            # to say what it could not read. The working-tree pass still decodes
            # BOM-marked UTF-16/32 properly, because there the bytes are on disk and
            # the BOM is right there; only history hunks, where git has already
            # mangled the framing, fall back to this honest outcome.
            unscanned.append(
                f"history {commit} {cur_file}: NUL-bearing hunk — NOT scanned "
                f"(non-UTF-8 history content is out of scope)")

        where = (f"history {commit} {cur_file}" if cur_file != "?"
                 else f"history {commit}")
        # Same JUDGE as the working-tree and metadata readers. A non-UTF-8 byte
        # beside a credential-shaped substring makes the token boundary unknowable,
        # and the boundary rules would otherwise read it as a separator — a false RED
        # that blocks an acceptable push. Ninth pair failure; the guard existed in two
        # readers and not the third.
        found, ambiguous = judge_line(body, truncated)
        if ambiguous:
            unscanned.append(
                f"{where}:{hit_at}: undecodable byte beside a credential-shaped "
                f"value — boundary unknowable, NOT scanned")
        for label, identity in found:
            # The identity key names the FILE and line, not the commit, so the
            # working-tree pass sees the same key for the same stored bytes and the
            # two surfaces reconcile. A credential still on disk is one thing to
            # rotate, not two.
            hits.append((where, hit_at, label,
                         (commit, cur_file, hit_at, identity),
                         (cur_file, hit_at, identity)))

    proc.stdout.close()
    if proc.wait() != 0:
        raise HistoryUnavailable(
            f"git could not read range {redact(rng)!r} — a shallow clone cannot walk it. "
            f"Set `fetch-depth: 0` on actions/checkout."
        )
    # SECOND PASS over the RAW commit headers.
    #
    # This was a targeted read of %e, because the `encoding` header was the one
    # --pretty=fuller omitted that anybody had noticed. A commit object can carry ANY
    # header — `git hash-object -t commit` will write one, `git fsck --strict` accepts
    # it, `git cat-file -p` shows it — and every preset format drops the ones it does
    # not know. So a targeted read of the known-missing field was the same mistake as
    # a magic-byte list: an enumeration standing in for a property.
    #
    # --pretty=raw prints the object's headers verbatim, so the property is "every
    # header this parser does not already cover", which needs no list of which ones
    # exist. tree/parent/author/committer are skipped because the main pass above
    # already scans identities and would double-report them.
    try:
        raw_proc = subprocess.Popen(
            # --encoding=none, NOT UTF-8. --encoding=UTF-8 asks git to recode from
            # whatever the commit DECLARES, and the declaration is part of the object
            # under audit: a commit claiming `encoding UTF-16` while storing ASCII had
            # its headers destroyed by the recode, so the pass added to read every
            # header read none of them. The main pass keeps --encoding=UTF-8 because
            # it needs a stable rendering of the message; this pass wants the bytes.
            ["git", "--no-replace-objects", "log", "--no-use-mailmap", "--no-color",
             "--encoding=none", "--pretty=raw", "--no-renames", *rng_args],
            cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise HistoryUnavailable(f"could not run git log for commit headers: {exc}")
    # "commit " is NOT in this list. The delimiter case is handled above by POSITION;
    # a `commit ` line that reaches here is a stored header of that name and must be
    # scanned. Leaving it in KNOWN meant the position fix changed nothing — the line
    # fell straight through to the skip-list one branch later, which is why the first
    # version of this fix tested green and did nothing.
    # NOTHING is skipped as "already covered". The raw pass used to skip author,
    # committer and the message on the grounds that the formatted pass scans them —
    # a division of labour that assumed the formatted pass SUCCEEDS. It does not
    # always: a commit declaring an encoding that does not match its stored bytes can
    # make --encoding=UTF-8 emit nothing but the `commit` line, so both halves of a
    # split responsibility went missing at once and the run reported OK.
    #
    # Two passes that each assume the other covered something is the same structure
    # as a table that assumes another table is right. This pass reads what git STORED
    # and scans all of it; duplicates are removed at the end, which costs nothing and
    # cannot go wrong the way an assumption can.
    KNOWN = ("tree ", "parent ")
    raw_commit = "?"
    # STATE, not a shape test. Header CONTINUATION lines are indented, exactly like
    # message lines, so treating every indented line as message text skipped the
    # continuation of an unknown header — put the credential on the second line of
    # `x-note` and nothing read it. The blank line is what separates headers from the
    # message in a commit object, so track that rather than guessing from indentation.
    in_headers = False
    # Line number WITHIN the object, reset per commit. Every hit from this pass used
    # to report `:0`, so two distinct credentials — two message lines, or an author
    # and a committer both carrying one — printed as two identical lines and a reader
    # could not tell whether that was one leak reported twice or two leaks. The value
    # is withheld on purpose; the locator is the entire remaining content of the
    # finding, and it was constant.
    obj_line = 0

    for raw, truncated in _bounded_lines(raw_proc, deadline, rng, unscanned,
                                         every_line_in_scope=True):
        text = decode_text(raw)
        # A `commit ` line is the record DELIMITER only when we are not already
        # inside a header block. A commit object may carry a stored header literally
        # named `commit` — fsck --strict accepts it — and treating that as a new
        # record skipped its value, so the one pass written to read arbitrary headers
        # could be bypassed by naming the header after the delimiter. Position in the
        # record decides, not the word.
        obj_line += 1
        if text.startswith("commit ") and not in_headers:
            # ZERO, not one. `commit <sha>` is git's synthetic record delimiter and is
            # NOT stored in the object, so counting it made every locator one higher
            # than the same line in `git cat-file -p` — an off-by-one in the only
            # thing a reader has, since the value is withheld.
            raw_commit, obj_line = text[7:].strip()[:10], 0
            in_headers = True
            continue
        # An EMPTY line ends the header block — not a blank-looking one. A header
        # continuation may be a single space, and strip() called that the separator,
        # so everything after a whitespace-only continuation was dropped, including
        # the next continuation carrying the credential.
        if text == "":
            in_headers = False
            continue
        if not in_headers:
            # Message body, indented four spaces in raw format. Scanned here too now:
            # see above — the formatted pass can lose it entirely.
            report_metadata_line(text, obj_line, "in commit message", hits,
                                 unscanned, commit=f"history {raw_commit}",
                                 truncated=truncated)
            continue
        if text.startswith(KNOWN):
            continue
        # Identity headers keep the wording a reader already knows from the working
        # tree and the ref passes. "commit header" is accurate and unhelpful when the
        # header is the author line.
        where_kind = ("in commit identity"
                      if text.startswith(("author ", "committer "))
                      else "in commit header")
        report_metadata_line(text, obj_line, where_kind, hits, unscanned,
                             commit=f"history {raw_commit}",
                             truncated=truncated)
    if raw_proc.wait() not in (0, None):
        raise HistoryUnavailable(
            f"git could not read commit headers for range {redact(rng)!r}")

    unscanned.extend(binary_skipped)
    for note in binary_skipped:
        print(f"secrets: NOT scanned (binary diff) — {note}", file=sys.stderr)
    if binary_skipped:
        print(f"secrets: {len(binary_skipped)} binary diff(s) in range were not "
              f"scanned; see stderr. Contents of binary blobs are out of scope.",
              file=sys.stderr)
    return hits, True, unscanned


UNSCANNED_SHOWN = 10


def print_unscanned(notes, indent):
    """Print a coverage list and SAY when it was cut.

    ONE owner for both displays. The failing path said "… and N more not shown" and
    the qualified-pass path — the one almost every green run prints — did not: a
    heading reading "14 input(s) were NOT scanned" over exactly ten lines, four of
    them gone with no sign. check_references.py added that sentence in round 71 for
    the same reason, and its wording holds here: ten lines under a heading saying
    fourteen reads as a display that lost track rather than one that chose a limit.

    The eleventh time in this PR a defence landed on one member of a pair, and the
    answer is the same one it has been every time — give the pair one owner rather
    than copy the fix into the half that was reported.
    """
    for note in notes[:UNSCANNED_SHOWN]:
        print(f"{indent}{redact(note)}")
    if len(notes) > UNSCANNED_SHOWN:
        print(f"{indent}… and {len(notes) - UNSCANNED_SHOWN} more not shown.")


KNOWN_FLAGS = ("--version", "--selftest")


def main():
    # An unrecognised flag is an ERROR, not a no-op. The range comes from the
    # TIER1_DIFF_RANGE environment variable, so `check_secrets.py --range A..B` —
    # which is what the interface looks like it should be, and what I typed at myself
    # for several rounds — quietly scanned the working tree and printed a pass. Every
    # "OK" I read that way was an answer to a question I had not asked. A tool whose
    # whole argument is that silence must never read as coverage cannot accept an
    # argument it ignores.
    unknown = [a for a in sys.argv[1:] if a not in KNOWN_FLAGS]
    if unknown:
        # REDACTED, like every other print site. The argument that made me add this
        # check was `--range <ref>..HEAD`, and a ref can carry a credential — a branch
        # named with a key is a shape this scanner already looks for elsewhere. An
        # error path that echoes its input verbatim is a print site that forgot it was
        # one, and it would have copied the value into the CI log at exactly the
        # moment someone was debugging an invocation.
        print("check_secrets.py: unrecognised argument(s): "
              + ", ".join(redact(a) for a in unknown))
        print(f"  Usage: [{'|'.join(KNOWN_FLAGS)}]")
        print("  The commit range is passed as TIER1_DIFF_RANGE=<rev>..<rev>, not as"
              " a flag.")
        return 2

    # Both operation flags is a MISTAKE, not a preference order. `--version
    # --selftest` printed 51 and exited 0 without running the self-test, so a consumer
    # combining the version assertion with the required redaction drift check got a
    # green tick and no validation — a gate silenced by asking it to do more.
    ops = [a for a in sys.argv[1:] if a in KNOWN_FLAGS]
    if len(set(ops)) > 1:
        print("check_secrets.py: " + " and ".join(sorted(set(ops)))
              + " are alternatives, not a sequence; run them as separate commands.")
        print("  Passing both used to print the version and skip the self-test.")
        return 2

    if "--version" in sys.argv:
        print(SCANNER_VERSION)
        return 0

    if "--selftest" in sys.argv:
        # check_references.py keeps a compact COPY of these shapes so it can redact
        # what it prints. Two rounds running, that copy was found missing a family
        # this list already had — Postgres URLs, then PEM armor. A hand-maintained
        # duplicate drifts by default, so the drift is now a test rather than a
        # thing someone remembers.
        # The portable template tells consumers to copy check_secrets.py and says
        # nothing about check_references.py, so requiring it here made the advertised
        # workflow fail permanently on its FIRST step for anyone who followed the
        # instructions.
        #
        # Fixing that by returning early skipped EVERY check, not just the one that
        # needed the second file. A portable installation could add "anon" to
        # PRIVILEGED_JWT_ROLES and still print "selftest OK", because the canary,
        # fingerprint, and negative-probe checks all sat behind a gate about a file
        # they never touch. Optional inputs make optional checks only for the checks
        # that read them: what follows is scanner-internal and runs everywhere, and
        # the single cross-file comparison is deferred to the end.
        ref = os.path.join(REPO, "scripts", "check_references.py")
        probes = [
            ("anthropic", "Anthropic", "sk-ant-" + "A" * 24),
            ("openai", "OpenAI", "sk-" + "B" * 44),
            ("gh_token", "GitHub token", "ghp_" + "C" * 38),
            ("gh_pat", "GitHub PAT", "github_pat_" + "D" * 62),
            ("slack", "Slack", "xoxb-" + "E" * 14),
            ("slack_app", "Slack app", "xapp-1-" + "F" * 14),
            ("google", "Google", "AIza" + "G" * 35),
            ("aws", "AWS", "AKIA" + "H" * 16),
            ("stripe", "Stripe", "sk_live_" + "I" * 24),
            ("sb_secret", "Supabase secret", "sb_secret_" + "J" * 24),
            # Split so this probe is not itself a matching literal — the same
            # doctrine that caught the Postgres example in check_references.py.
            ("pem", "PEM", "-----BEGIN OPENSSH " + "PRIVATE KEY-----"),
            ("postgres", "Postgres", "postgres" + "://u:p@h"),
            # One probe per independently duplicated ALTERNATIVE. A single
            # representative let half a family drift unnoticed — dropping ASIA from
            # the reference copy left the AKIA probe green while a temporary AWS key
            # in a broken reference would still be printed.
            ("aws", "AWS temporary", "ASIA" + "H" * 16),
            ("stripe", "Stripe restricted", "rk_live_" + "I" * 24),
            ("postgres", "Postgres (postgresql)", "postgres" + "ql://u:p@h"),
            # Mixed case, independently. Both copies were made case-insensitive last
            # round and every probe stayed lowercase, so removing (?i:) from one of
            # them left all 45 green.
            ("postgres", "Postgres mixed case", "PostGres" + "://u:p@h"),
            ("openai", "OpenAI project", "sk-proj-" + "B" * 44),
            ("gh_token", "GitHub oauth", "gho_" + "C" * 38),
            ("gh_token", "GitHub server", "ghs_" + "C" * 38),
            ("gh_token", "GitHub refresh", "ghr_" + "C" * 38),
            ("gh_token", "GitHub user", "ghu_" + "C" * 38),
            ("slack", "Slack user", "xoxp-" + "E" * 14),
            ("slack_app", "Slack app", "xoxa-" + "E" * 14),
            ("slack", "Slack refresh", "xoxr-" + "E" * 14),
            ("slack", "Slack xoxo", "xoxo-" + "E" * 14),
            ("slack", "Slack xoxs", "xoxs-" + "E" * 14),
            # The privileged-JWT family is detected by payload decode, not by
            # PATTERNS, so it sat outside every probe while check_references.py
            # carried a duplicated JWT clause that could be narrowed unnoticed.
            ("jwt", "privileged JWT (service_role)", _selftest_jwt()),
            # Both roles, independently. PRIVILEGED_JWT_ROLES has two entries and
            # only one was probed, so dropping supabase_admin left all probes green
            # while the scanner silently lost half the family.
            ("jwt", "privileged JWT (supabase_admin)", _selftest_jwt("supabase_admin")),
            # A Google key whose last character is a hyphen — the exact shape the
            # trailing word boundary used to reject.
            ("google", "Google trailing hyphen", "AIza" + "G" * 34 + "-"),
            # MINIMUM lengths, TRAILING HYPHENS and URL-SAFE characters. Every probe
            # above is comfortably longer than the declared floor and uses a bare
            # alphanumeric run, so raising a floor or narrowing an alphabet in the
            # duplicated redactor left them all green while real keys of those exact
            # shapes went unredacted.
            ("anthropic", "Anthropic min+hyphen", "sk-ant-" + "A" * 19 + "-"),
            ("anthropic", "Anthropic underscore", "sk-ant-" + "A_" + "A" * 18),
            ("slack", "Slack min+hyphen", "xoxb-" + "E" * 9 + "-"),
            ("sb_secret", "Supabase min+hyphen", "sb_secret_" + "J" * 19 + "-"),
            ("sb_secret", "Supabase underscore", "sb_secret_" + "J_" + "J" * 18),
            ("gh_token", "GitHub token min", "ghp_" + "C" * 36),
            ("gh_pat", "GitHub PAT min", "github_pat_" + "D" * 60),
            ("openai", "OpenAI min", "sk-" + "B" * 40),
            ("stripe", "Stripe min", "sk_live_" + "I" * 20),
            ("slack_app", "Slack app min+hyphen", "xapp-1-" + "F" * 9 + "-"),
            # Armor with words AFTER "PRIVATE KEY" — what gpg --export-secret-keys
            # actually emits, and the case the scanner's pattern was widened for.
            ("pem", "PEM trailing words", "-----BEGIN PGP " + "PRIVATE KEY BLOCK-----"),
            # Armor glued to a preceding identifier. The leading-boundary check
            # suppressed this as an embedded token until round 47, because the rule
            # asked about the character BEFORE the match without asking what the
            # match itself starts with — and five hyphens are a boundary already.
            ("pem", "PEM after identifier", "prefix-----BEGIN " + "PRIVATE KEY-----"),
            # Declared-alphabet probes for the families still exercised only by bare
            # alphanumeric runs. Narrowing any of these classes in the duplicated
            # redactor left all 39 probes green.
            ("jwt", "JWT min tail + hyphen", _selftest_jwt(tail="a" * 9 + "-")),
            ("jwt", "JWT underscore tail", _selftest_jwt(tail="_" + "a" * 11)),
            ("openai", "OpenAI underscore", "sk-" + "B_" + "B" * 39),
            ("openai", "OpenAI hyphen end", "sk-" + "B" * 39 + "-"),
            ("google", "Google underscore", "AIza" + "G_" + "G" * 33),
            ("gh_pat", "GitHub PAT underscore", "github_pat_" + "D_" + "D" * 59),
        ]
        # Two INDEPENDENT assertions. The old filter only reported a family when the
        # scanner still detected it, so narrowing the scanner's own regex removed the
        # probe from consideration and the test reported all families healthy — the
        # drift test could be silenced by the very regression it exists to catch.
        # INVENTORY first. The probe list is hand-written, so adding a family to
        # PATTERNS and forgetting both its probe and its SECRETISH alternative left
        # this test examining only the old list and reporting success — the drift it
        # exists to catch, in the direction of growth rather than narrowing.
        # EXCLUSIVE attribution. A set of observed labels was satisfiable by an
        # overlapping family borrowing another's probe — inserting an invented
        # sk-proj- family before OpenAI passed, because the existing project probe
        # supplied the new label while other probes still supplied the old one. Each
        # family must own a probe that no other family matches.
        # JWT competes too. It is detected by DECODING rather than by a PATTERNS
        # entry, so it sat outside this contest entirely — and a new family shaped
        # like the JWT prefix could then claim a JWT probe as its own "exclusive"
        # one, because nothing else in PATTERNS matched it. Every matcher that can
        # claim a probe has to be in the competition, decoded families included.
        # SOURCE HYGIENE, before anything about credentials. An invalid escape
        # sequence in a string literal is a SyntaxWarning today and a SyntaxError on
        # a future interpreter, and this file is vendored into consumer repos — there
        # the failure is not a wrong verdict but no verdict, the gate refusing to
        # start. One had been printing on every CI run for rounds; I found it by
        # reading the log of a GREEN run rather than trusting the tick, which is the
        # same thing this file asks of everyone else.
        bad_escapes = []
        for src_path in [os.path.abspath(__file__)] + (
                [ref] if os.path.isfile(ref) else []):
            try:
                with open(src_path, encoding="utf-8") as handle:
                    source = handle.read()
            except OSError as exc:
                bad_escapes.append(f"{os.path.basename(src_path)}: unreadable "
                                   f"({type(exc).__name__})")
                continue
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                try:
                    compile(source, src_path, "exec")
                except SyntaxError as exc:
                    bad_escapes.append(f"{os.path.basename(src_path)}: {exc}")
                    continue
            for entry in caught:
                if "escape" in str(entry.message):
                    bad_escapes.append(
                        f"{os.path.basename(src_path)}:{entry.lineno}: "
                        f"{entry.message}")
        if bad_escapes:
            print("selftest FAILED — source will not compile cleanly on a future "
                  "interpreter: " + "; ".join(bad_escapes))
            print("  Make the literal raw (r\"\"\") or escape the backslash.")
            return 1

        matchers = list(PATTERNS) + [("jwt", "privileged JWT (decoded)", JWT)]

        # DECLARED ownership. Four versions of this check inferred identity from
        # something else — a set of observed labels, then a label string, then a
        # non-overlapping match domain — and each was defeated by a matcher that
        # shared the proxy. Exclusivity was the worst of them: a legitimate SUBSET
        # family can never own a probe its superset does not also match, so the test
        # rejected correct code. Every probe now names the matcher it is for, and the
        # only question asked is whether that matcher exists and claims it.
        mids = [mid for mid, _, _ in matchers]
        dupes = sorted({m for m in mids if mids.count(m) > 1})
        if dupes:
            print("selftest FAILED — duplicate matcher ids: " + ", ".join(dupes))
            return 1

        by_id = {mid: pattern for mid, _, pattern in matchers}
        orphans = sorted({owner for owner, _, _ in probes if owner not in by_id})
        if orphans:
            print("selftest FAILED — probes name unknown matchers: " + ", ".join(orphans))
            return 1

        # The KEY SET must match too. Deleting a matcher and its probes together left
        # its fingerprint behind and nothing noticed, so removing an entire credential
        # family — AWS keys, say — passed silently. A fingerprint table that outlives
        # what it fingerprints is a record of the past presented as a check.
        stale = sorted(set(PATTERN_FINGERPRINTS) - {mid for mid, _, _ in matchers})
        absent = sorted({mid for mid, _, _ in matchers} - set(PATTERN_FINGERPRINTS))
        if stale or absent:
            if stale:
                print("selftest FAILED — fingerprints for matchers that no longer "
                      "exist: " + ", ".join(stale))
            if absent:
                print("selftest FAILED — matchers with no fingerprint: "
                      + ", ".join(absent))
            return 1

        # Canaries first: they are what stops an id being a name rather than an
        # identity.
        #
        # The JWT canary is built, not written: its value is a signed-shaped token
        # rather than a literal, so it joins here where _selftest_jwt is in scope.
        canaries = dict(CANARIES)
        canaries["jwt"] = (_selftest_jwt(), "Supabase service-role JWT")

        uncanaried = sorted({mid for mid, _, _ in matchers}
                            - set(canaries) - CANARY_EXEMPT)
        if uncanaried:
            print("selftest FAILED — matchers with no canary and no declared "
                  "exemption: " + ", ".join(uncanaried))
            print("  Add a value its pattern must match to CANARIES, or say in "
                  "CANARY_EXEMPT why its id is pinned some other way.")
            return 1
        # Both tables are checked for strays, not just the one holding values. A
        # subtraction that only rejects leftover CANARIES accepts a leftover
        # CANARY_EXEMPT: delete the JWT matcher, its fingerprint, its probes and its
        # dispatch, leave `CANARY_EXEMPT = {"jwt"}` behind, and every remaining probe
        # reports OK while privileged JWT detection is simply gone. An exemption that
        # outlives the thing it exempts is a claim about nothing, so it has to pin
        # that family's continued existence the way a canary does.
        stray = sorted((set(canaries) | CANARY_EXEMPT)
                       - {mid for mid, _, _ in matchers})
        if stray:
            print("selftest FAILED — canaries or exemptions for matchers that no "
                  "longer exist: " + ", ".join(stray))
            return 1

        miscast = [mid for mid, _label, pattern in matchers
                   if mid in canaries and not pattern.search(canaries[mid][0])]
        if miscast:
            print("selftest FAILED — matcher ids no longer match their canary shape: "
                  + ", ".join(sorted(miscast)))
            return 1

        # Not "does scan_line return something" but "does it return THIS family's
        # label". The weaker question passed while AWS keys were reported as Google
        # keys, and since a finding withholds the matched value on purpose, a wrong
        # label sends someone to rotate the wrong credential.
        unflagged, mislabelled = [], []
        for mid, (canary, want_label) in canaries.items():
            got = scan_line(canary)
            if not got:
                unflagged.append(mid)
            elif got != want_label:
                mislabelled.append(f"{mid} (reported {got!r}, declared {want_label!r})")
        if unflagged:
            print("selftest FAILED — canary shapes their own pattern matches are not "
                  "reported by scan_line: " + ", ".join(unflagged))
            print("  Something between the match and the report is suppressing them.")
            return 1
        if mislabelled:
            print("selftest FAILED — canaries reported under another family's label: "
                  + ", ".join(mislabelled))
            return 1

        drifted = []
        for mid, label, pattern in matchers:
            want = PATTERN_FINGERPRINTS.get(mid)
            got = _fingerprint(pattern, _policy_extra(mid, label))
            if want != got:
                drifted.append(f"{mid} (expected {want}, got {got})")
        if drifted:
            print("selftest FAILED — matcher patterns changed since their probes were "
                  "written: " + ", ".join(drifted))
            print("  Add or update the probe for the new shape, then update "
                  "PATTERN_FINGERPRINTS.")
            return 1

        uncovered = []
        for mid, label, pattern in matchers:
            owned = [pr for owner, _, pr in probes
                     if owner == mid and pattern.search(pr)]
            if not owned:
                uncovered.append(f"{label} [{mid}]")
        if uncovered:
            print("selftest FAILED — scanner families with no redaction probe: "
                  + ", ".join(uncovered))
            return 1

        # NEGATIVE probes. "Does not fire on a public value" is a property this file
        # was built around — the anon key is client-visible by design — and nothing
        # tested it, so widening the privileged-role set would have turned it into a
        # hit silently.
        #
        # The boundary cases are here for the same reason. A token whose match is
        # extended by a combining mark or a zero-width joiner is a fragment of some
        # longer identifier, not a credential, and the continuation filter drops it —
        # unless the family is listed in NON_TOKEN_IDS, which exempts it from that
        # filter entirely. Nothing tested the suppressed side, so adding a family to
        # that table changed what gets reported with no probe, no fingerprint input,
        # and no failure. (A trailing connector or letter is NOT here: those are
        # inside the family's own character class, so the regex absorbs them and the
        # filter never runs. Probing them would test the wrong mechanism.)
        # One probe per enumerated extender, GENERATED from the table rather than
        # hand-listed. Two hand-written cases covered two of six branches, so deleting
        # the emoji-modifier range left every check green while a token followed by
        # U+1F3FB became a reported hit. A hand-written probe list tests the branches
        # someone thought of on the day; a generated one tests the branches that
        # exist. Deleting a row still deletes its probe — no table outvotes an edit to
        # itself — but the row is now also a fingerprint input, so the deletion fails
        # all thirteen matchers instead of passing silently.
        token = "sk-" + "B" * 44
        negatives = [("anon JWT", _selftest_jwt(role="anon")),
                     ("no-role JWT", _selftest_jwt(role="authenticated")),
                     ("token + combining mark", token + "́")]
        negatives += [(f"token + ZWNJ/ZWJ U+{ord(c):04X}", token + c)
                      for c in GRAPHEME_JOINERS]
        negatives += [(f"token + {name} U+{lo:04X}", token + chr(lo))
                      for lo, _hi, name in GRAPHEME_EXTENDER_RANGES]
        negatives += [(f"token + {name} U+{hi:04X}", token + chr(hi))
                      for _lo, hi, name in GRAPHEME_EXTENDER_RANGES]
        negatives += [(f"token + literal U+{cp:04X}", token + chr(cp))
                      for cp in SUPPRESSED_CODEPOINTS]
        # PEM armor is a PHRASE, not a prefix. These read as armor to a pattern that
        # lets any uppercase run touch "PRIVATE KEY" on either side, and a false RED
        # on a required gate is the failure that actually costs a consumer something:
        # everyone learns to merge past it, and an ignored gate protects nothing.
        negatives += [("PEM keyboard", "-----BEGIN PRIVATE " + "KEYBOARD-----"),
                      ("PEM keyring", "-----BEGIN NOT A PRIVATE " + "KEYRING-----"),
                      ("PEM glued prefix", "-----BEGIN MYPRIVATE " + "KEY-----")]
        false_reds = [n for n, value in negatives if scan_line(value)]
        if false_reds:
            print("selftest FAILED — public values now reported as credentials: "
                  + ", ".join(false_reds))
            return 1

        undetected = [n for _, n, probe in probes if not scan_line(probe)]
        if undetected:
            print("selftest FAILED — check_secrets.py no longer detects: "
                  + ", ".join(undetected))
            return 1

        # Everything above is scanner-internal and has now run. Only the redaction
        # comparison needs the second file.
        if not os.path.isfile(ref):
            print(f"selftest OK — {len(probes)} probes, {len(matchers)} matchers "
                  "checked; check_references.py not present, redaction comparison "
                  "SKIPPED " + _env_note())
            return 0
        import importlib.util
        spec = importlib.util.spec_from_file_location("cr", ref)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        # The matched SPAN must be absent from the redacted output. Comparing
        # redact(probe) != probe only proved *something* changed, so narrowing the
        # reference Postgres alternative to match the scheme alone still printed the
        # reusable username and password and the test called it healthy.
        # SPAN COVERAGE, not substring absence. My first version asked whether the
        # scanner's matched text survived redaction — but a redactor matching only
        # `postgres` removes part of that text, so the whole span is absent while the
        # username and password remain, and the test passed. The real property is
        # that the reference redactor's match must COVER the scanner's match.
        unredacted = []
        for _, n, probe in probes:
            mine = _matched_span(probe)
            theirs = mod.SECRETISH.search(probe)
            if not mine:
                continue
            if not theirs or theirs.start() > mine[0] or theirs.end() < mine[1]:
                unredacted.append(n)
        if unredacted:
            print("selftest FAILED — check_references.py cannot redact: "
                  + ", ".join(unredacted))
            return 1
        print(f"selftest OK — {len(probes)} credential families redactable in both files "
              + _env_note())
        return 0

    hits = []
    unscanned = []
    for rel, scan_contents in sorted(files(unscanned)):
        path = os.path.join(REPO, rel)
        # The FILENAME is scanned too. A credential committed as a file name leaks
        # through git metadata while the file's contents may be empty, so both the
        # tree pass (which reads contents) and the history pass (which reads added
        # lines, not diff headers) missed it entirely.
        report_filename(rel, "filename", hits, unscanned)
        # A tracked symlink stores its TARGET TEXT as the blob. `innocuous ->
        # sk-ant-<key>` puts a credential in git while open() follows the link and
        # reads something else entirely — or raises OSError on a dangling target,
        # which this loop used to swallow as a clean result.
        # Symlinks are resolved BEFORE the containment test, not after. The old
        # order ran _inside_repo() first, which follows the link — so
        # `innocuous -> /tmp/sk-ant-<key>` was discarded entirely, name, target and
        # all, by the very check meant to stop the gate reading runner-local files.
        # Containment protects CONTENTS. The link's own text is a committed blob and
        # is always safe to read.
        if os.path.islink(path):
            try:
                target = os.readlink(path)
            except OSError:
                target = ""
            # SAME key shape AND SAME LINE NUMBERING as the history pass, so the two
            # surfaces reconcile. The first version of this key was ("link", rel,
            # hash-of-the-whole-target) against history's (rel, N, hash-of-the-matched
            # -bytes) — keys that could never match, so one symlink reported twice.
            # The second version fixed the shape and hardcoded line 1, which is right
            # only while the target holds no newline. A symlink's blob is its target
            # TEXT, and git stores and diffs that text like any other blob: `ln -s
            # $'harmless\nAKIA…'` is a two-line blob, history numbered the credential
            # 2, and the duplicate came straight back. Splitting the target is not a
            # refinement of the convention — it IS the convention git already uses.
            # split("\n"), not splitlines(): git ends a line at LF and nothing
            # else, and this numbering exists solely to agree with the history
            # pass. splitlines() honours nine boundaries, so a CR in the target
            # reintroduced the disagreement this split was added to remove.
            for lineno, chunk in enumerate(target.split("\n"), 1):
                found, ambiguous = judge_line(chunk)
                if ambiguous:
                    unscanned.append(
                        f"{redact(rel)}:{lineno}: undecodable byte beside a "
                        f"credential-shaped value in the symlink target — boundary "
                        f"unknowable, NOT scanned")
                for label, identity in found:
                    hits.append((rel, lineno, f"{label} (in symlink target)",
                                 ("tree", rel, lineno, identity),
                                 (rel, lineno, identity)))
            continue
        # REGULAR FILES ONLY, and the test does not follow anything. `mkfifo
        # notes.txt` in a portable checkout made _is_binary block forever on open —
        # the gate did not fail, it HUNG until the runner's own timeout killed the
        # job, which is the worst outcome available to a required check: no verdict,
        # no coverage report, and a wasted runner. A device node or a socket does the
        # same or worse.
        #
        # Guarded HERE rather than in the fallback walk, though that is where a FIFO
        # realistically appears, because a tracked path can be replaced by a special
        # file in the working tree too. One choke point covers both branches; the
        # last three rounds were all fixes applied to one branch of a pair.
        try:
            mode = os.lstat(path).st_mode
        except OSError as exc:
            unscanned.append(f"{rel}: could not be stat'd ({type(exc).__name__})"
                             " — NOT scanned")
            continue
        if not stat.S_ISREG(mode):
            unscanned.append(f"{rel}: not a regular file — NOT scanned")
            continue
        # The SUFFIX only labels the report; the BYTES decide whether to read it.
        # Classifying on the extension alone meant renaming a tracked plaintext file
        # to notes.zip turned a credential failure into a qualified pass. Binary
        # contents stay out of scope, but omitting them silently let the summary
        # claim a complete working-tree scan, so they are reported either way.
        if _is_binary(path):
            kind = ("archive" if rel.lower().endswith(ARCHIVE_SUFFIXES)
                    else "binary content")
            unscanned.append(f"{rel}: {kind} — contents NOT scanned")
            continue
        # The suffix cannot SKIP the read — that was the rename bypass, and it stays
        # fixed. But it still decides COVERAGE, and discarding it entirely was the
        # other half of that trade: `_is_binary` classifies on NULs and a fixed list
        # of container magics, and %PDF- was deliberately removed from that list
        # because a printable-ASCII signature cannot classify a text file. A PDF with
        # no NUL in its first 8 KiB therefore reaches here as "genuine text", its
        # ASCIIHex/Flate streams are read as opaque characters no pattern matches,
        # and the run prints an UNQUALIFIED `secrets: OK` over a file whose encoded
        # content nothing decoded.
        #
        # So: keep scanning the bytes (a plaintext credential in a mislabelled file
        # is still found), and record the file as not fully read. The literal text of
        # an encoded container is not its contents, and only the suffix knows the
        # difference once the magic test has been correctly disarmed.
        if not scan_contents:
            container = ("archive" if rel.lower().endswith(ARCHIVE_SUFFIXES)
                         else "encoded container")
            unscanned.append(f"{rel}: {container} by suffix — encoded streams NOT"
                             " decoded; only literal text was scanned")
        # Containment on the REAL path, after symlinks — a tracked link like
        # docs/host.md -> /etc/passwd would otherwise have its runner-local contents
        # read, making the verdict depend on the machine rather than the commit.
        if not _inside_repo(path):
            continue
        try:
            # errors="replace", not a skip. One invalid byte used to discard the
            # WHOLE file — so a 0xff followed by an ASCII key scanned clean, and
            # the history pass does not cover it when the credential predates the
            # range. This is the same defect I fixed in check_references.py last
            # round; I fixed the instance and left the class, and it was still
            # here. Credentials are ASCII, so replacement cannot hide one.
            # newline="\n": NO translation, and LF is the only line boundary —
            # exactly git's rule. Universal-newline mode turned every CR into a line
            # break, so a CR-only file numbered its credential on a later line than
            # git's patch stream did, the overlap key never matched, and one stored
            # credential was reported twice. The tree pass has to count lines the way
            # the thing it reconciles against counts them; anything else is a second
            # convention for the same object, which is the symlink defect from last
            # round in a different reader.
            with open(path, encoding=_encoding_of(path),
                      errors="surrogateescape", newline="\n") as handle:
                for lineno, line, truncated in _text_lines(handle, rel, unscanned):
                    if "\x00" in line:
                        # _is_binary sniffs only the first 8 KiB, so a file that
                        # opens with clean ASCII and turns binary later was read as
                        # text to the end and counted as fully scanned. Detection
                        # has to continue while reading, not stop at the header.
                        #
                        # SCAN THE PREFIX FIRST. The text before that first NUL was
                        # already decoded and in hand, and discarding it threw away
                        # the one part of the line this scanner could read — a
                        # credential sitting just before the NUL went unreported while
                        # the run printed a qualified pass. "Cannot read the rest" is
                        # not a reason to un-read the beginning.
                        prefix, _, _rest = line.partition("\x00")
                        found, ambiguous = judge_line(prefix)
                        if ambiguous:
                            unscanned.append(
                                f"{rel}:{lineno}: undecodable byte beside a "
                                f"credential-shaped value — boundary unknowable, "
                                f"NOT scanned")
                        for label, identity in found:
                            hits.append((rel, lineno, label,
                                         ("tree", rel, lineno, identity),
                                         (rel, lineno, identity)))
                        unscanned.append(
                            f"{rel}: binary content from line {lineno} — "
                            f"remainder NOT scanned")
                        break
                    # SAME judge as the metadata path. A Latin-1 letter beside a
                    # credential-shaped substring leaves the token boundary
                    # unknowable, and reading it as a separator was a false RED here
                    # while the identical bytes produced an honest non-scan in
                    # metadata.
                    found, ambiguous = judge_line(line, truncated)
                    if ambiguous:
                        unscanned.append(
                            f"{rel}:{lineno}: undecodable byte beside a "
                            f"credential-shaped value — boundary unknowable, "
                            f"NOT scanned")
                    for label, identity in found:
                        hits.append((rel, lineno, label,
                                     ("tree", rel, lineno, identity),
                                     (rel, lineno, identity)))
        except (OSError, UnicodeError) as exc:
            # UnicodeError TOO. errors="surrogateescape" cannot rescue every decoder:
            # the multibyte UTF-16/32 codecs still raise on a truncated code unit, so
            # a three-byte `FF FE 41` file ended the whole required gate in a
            # traceback — every later file unread, no verdict, no coverage list. A
            # gate that dies mid-scan is worse than one that fails, because it does
            # not say what it did not look at.
            #
            # NOT silent. A tracked file the scanner could not open — mode 000, a
            # permission change, a vanished symlink target — was skipped and the run
            # still reported a clean working tree. An input that was never read is
            # not an input without credentials.
            unscanned.append(f"{rel}: could not be read ({exc.__class__.__name__}) "
                             f"— NOT scanned")
            continue

    # Ref names are repository metadata: a branch or tag can itself be named with a
    # credential, and that name is visible on the remote while every commit and file
    # under it is clean. It appears in no tree, no patch and no commit message, so CI
    # passes it in explicitly.
    # PROVENANCE, one variable per surface. A single blob labelled every hit "(in ref
    # name)", so a credential in an annotated tag's message told the reader to go
    # inspect a harmless branch name — and because the value is withheld on purpose,
    # that label was the only pointer they had. A report that withholds the value has
    # to be right about the location; it is the entire remaining content of the
    # finding.
    #
    # Separate variables rather than markers inside one: a tag message is attacker-
    # controlled text, and any in-band convention it could contain would let it
    # relabel its own provenance.
    # The tag object arrives by FILE, not by environment variable. Bash command
    # substitution silently DROPS NUL bytes, so a tag message holding a credential
    # followed by NUL and a letter arrived with those joined — and the boundary rule
    # then read the letter as a continuation and suppressed the credential. The shell
    # warned that it ignored a null byte; the workflow carried on and reported OK.
    #
    # A transport that alters the bytes it carries cannot be part of an audit path.
    # The file keeps them, and the reader below is the same bounded one everything
    # else uses.
    #
    # SOLE COVERAGE. Everything else this gate skips is skipped by a scope decision
    # recorded in the header — a binary blob, an oversized line — and every one of
    # those inputs is ALSO visible somewhere a human reads: the tree pass, the diff,
    # the review. A tag object appears in no tree, no patch and no commit message.
    # This reader is the only reader it will ever have, so an unread one is not out of
    # scope, it is unexamined, and a qualified pass over it is the same unearned pass
    # the history scan already refuses to print when its range will not walk.
    #
    # And the budget is attacker-chosen. Padding an annotation to 1 MiB and putting
    # the key after the cut is a one-line recipe, whereas a legitimate annotated tag
    # over a megabyte does not exist — so failing closed here costs nothing real and
    # removes an evasion. Notes recorded in BOTH lists: `unscanned` keeps the coverage
    # report complete, `metadata_unread` is what makes the gate fail.
    tag_file = os.environ.get("TIER1_TAG_OBJECT_FILE", "")
    tag_text = ""
    tag_truncated = False
    metadata_unread = []
    if tag_file:
        try:
            if stat.S_ISREG(os.lstat(tag_file).st_mode):
                with open(tag_file, encoding="utf-8",
                          errors="surrogateescape") as handle:
                    # ONE BYTE PAST the budget, so the cap can be detected instead of
                    # assumed absent. Reading exactly the budget makes a truncated
                    # file indistinguishable from a file that happens to end there,
                    # and a credential past the cut was reported clean.
                    tag_text = handle.read(TAG_OBJECT_BUDGET + 1)
                # If the lookahead character IS a newline, the retained text ends at
                # a real boundary and nothing about the last line is uncertain —
                # splitlines() removes that newline, so marking the line truncated
                # discarded a complete, correctly-bounded credential. A lookahead
                # that establishes the boundary is the opposite of a lookahead that
                # hides it.
                over_budget = len(tag_text) > TAG_OBJECT_BUDGET
                # Two different questions. The REMAINDER is unread either way and is
                # always reported. The last retained line's BOUNDARY is uncertain only
                # when the lookahead does not itself establish one — a newline there
                # ends the line properly, and splitlines() removes it, so treating
                # that as truncation discarded a complete, correctly-bounded value.
                # EVERY separator splitlines() consumes, not just CR and LF. Python
                # also splits on \v \f \x1c \x1d \x1e \x85 \u2028 \u2029, and any of
                # them at the cut ends the retained line properly — so treating them
                # as unknown discarded a complete, correctly-bounded credential. The
                # test has to use the same set as the function whose output it is
                # reasoning about; naming two of nine was a guess wearing a rule.
                tag_truncated = (over_budget
                                 and tag_text[TAG_OBJECT_BUDGET] not in SPLITLINES_BOUNDARIES)
                if over_budget:
                    # Keep ONE extra character. Slicing exactly at the budget threw
                    # away the character the boundary rules need, so a credential
                    # ending at the cut looked complete and produced a false RED —
                    # the same defect the line-length cap had in round 61, in the
                    # reader added after it.
                    tag_text = tag_text[:TAG_OBJECT_BUDGET + 1]
                    metadata_unread.append(
                        f"tag object over {TAG_OBJECT_BUDGET >> 20} MiB — remainder "
                        f"NOT scanned")
            else:
                metadata_unread.append(
                    f"{tag_file}: not a regular file — tag object NOT scanned")
        except (OSError, UnicodeError) as exc:
            metadata_unread.append(
                f"tag object could not be read ({type(exc).__name__}) — NOT scanned")
    unscanned.extend(metadata_unread)

    for source, where, cut in (
            (os.environ.get("TIER1_EXTRA_TEXT", ""), "in ref name", False),
            (tag_text, "in annotated tag object", tag_truncated)):
        lines = source.splitlines()
        for lineno, chunk in enumerate(lines, 1):
            chunk = chunk.strip()
            if not chunk:
                continue
            # Only the FINAL retained line is truncated. Keeping the lookahead
            # character was half the fix: the reader still told judge_line the text
            # was complete, so a match ending at the cut was judged against a boundary
            # the cut had manufactured. Third reader in three rounds to preserve a
            # lookahead and then not say that it did.
            report_metadata_line(chunk, lineno, where, hits, unscanned,
                                 truncated=cut and lineno == len(lines))

    try:
        past, scanned_history, past_unscanned = history_hits()
        unscanned.extend(past_unscanned)
    except HistoryUnavailable as exc:
        print(f"secrets: INDETERMINATE — {exc}")
        print("\nThe working-tree scan cannot substitute for the history scan, so this\n"
              "gate fails rather than reporting a pass it did not earn.")
        return 1
    hits = reconcile(hits, past)

    if metadata_unread and not hits:
        # A gap in a surface nothing else covers is not a qualified pass. Same verdict
        # and same wording as an unwalkable history range: the scan that could not run
        # must not look like a scan that found nothing.
        print("secrets: INDETERMINATE — pushed repository metadata was not read in full\n")
        for note in metadata_unread:
            print(f"  {redact(note)}")
        print("\nA tag object appears in no tree, no diff and no commit message, so this\n"
              "pass is its only reader. Nothing else would catch a credential in the part\n"
              "that went unread, and this gate does not report a pass it did not earn.")
        return 1

    if not hits:
        scope = "working tree + branch history" if scanned_history else "working tree"
        if unscanned:
            # A clean result over incomplete coverage is not "OK". The reference
            # checker has qualified its all-clear since round 11; this one printed
            # the skips to stderr and then said OK anyway, which is the same
            # coverage lie in the gate that matters more.
            print(f"secrets: no credential-shaped values found ({scope}), but "
                  f"{len(unscanned)} input(s) were NOT scanned:")
            print_unscanned(unscanned, "  ")
            print("\n  Binary blobs and oversized lines are out of scope — see this\n"
                  "  file's header. This is a qualified pass, not a clean one.")
            return 0
        print(f"secrets: OK — no credential-shaped values ({scope})")
        return 0

    # Never print the matched value: CI logs are readable by anyone with repo access,
    # and echoing a live key into them widens the leak this gate exists to catch.
    print(f"secrets: {len(hits)} possible credential(s) committed\n")
    for rel, lineno, label in hits:
        print(f"  {redact(rel)}:{lineno}  ->  {label}")
    if unscanned:
        # The SAME qualification the passing path prints. Reporting skips only when
        # the run is otherwise clean made the failing output read as an exhaustive
        # remediation list: fix these three and you are done. Someone rotating the
        # named keys had no way to know a binary blob went unread, and the moment a
        # reader most needs the coverage caveat is when they are acting on the report.
        print(f"\n  Coverage was INCOMPLETE: {len(unscanned)} input(s) NOT scanned.")
        print_unscanned(unscanned, "    ")
        print("  The list above is what was found, not everything there is.")
        if metadata_unread:
            # Say WHICH of the skips is the fatal one. With the run already red the
            # exit code carries no information about it, and a reader fixing the named
            # credentials would otherwise re-run into the same unearned verdict.
            print("  Of those, the pushed metadata below is unread by ANY pass and is\n"
                  "  on its own enough to fail this gate:")
            for note in metadata_unread:
                print(f"    {redact(note)}")
    print(
        "\nValues are withheld on purpose — printing them would copy the leak into the\n"
        "CI log. If a hit is real: rotate the credential first, then remove it from\n"
        "history. Rotate first. The commit is already public to anyone who fetched it."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
