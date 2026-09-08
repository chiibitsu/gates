# gates

Deterministic CI gates that must prove they can fail before they count.

## Author

Built and maintained by **Angeline S. Viray**, founder of Chiibitsu Labs
(<https://chiibitsu.com>), as the deterministic gate layer of **vibeOS** — her
operating system for shipping production software with AI builders as a non-coder
product architect.

> "A gate that cannot fail is not a gate. A gate that cannot say I don't know
> will say fine."
> — Angeline S. Viray, vibeOS

`check_secrets.py` and `check_references.py` are vibeOS components by the same author,
vendored here byte-for-byte from `scripts/check_secrets.py` and
`scripts/check_references.py` in chiibitsu/vibeOS. The only edit is the one attribution
comment after each shebang.

The fixture-and-selftest rule below was derived from her AI Improvements log: 51 logged
sessions, 17 of which were a mechanism reporting success while doing nothing — and in 7
of those 17, the mechanism that failed open was a check or a CI gate itself. The rule
generalises the principle already written into vibeOS's own CI template; it did not
discover it.

Licensed MIT. See `LICENSE`. Citation metadata in `CITATION.cff`.

## The one rule

**Every gate ships with a known-bad fixture, and the selftest must show the gate fails
on that fixture before the gate counts. Then it must pass the real tree. Both
directions, every CI run. A gate with no fixture fails the selftest.**

That is the whole design. A gate that has never been seen to fail is not known to work,
and a check that quietly does nothing looks exactly like a check that passes.

**The second half of the rule is not implemented yet, and this release is honest about
that.** Every gate here answers with two values: clean, or violation. It has no way to
say *I could not check*. That is why review found the defects it found — in shell, the
failure mode of every tool is "produces no output", which is the same thing this design
uses to mean "found nothing wrong". Success and not-looking share a representation, so
each new error path arrives as a silent pass, for free. Roughly thirty were found here by
review; the selftest caught none of them, because it asks whether the gate CAN fail, not
whether it looked at the right thing.

The fix is a third outcome — exit 2, *could not check*, which CI must treat as a hard
failure — and it lands in the next version, together with real parsers for the formats
that have a grammar. Until it does, the shape of the risk is written down here rather
than discovered later.

One bad fixture is one tree holding several violations, so it proves only that
*something* in it still fails. A shape that stopped being detected hides behind the ones
that still are. So each shape a review found the gate passing gets its own minimal tree
under `fixtures/<name>/bad/cases/`, and the selftest requires exit 1 from every one of
them individually. Every one of the thirteen cases in this repo was written after a
reviewer found the gate walking past that exact shape.

They sit *under* the bad fixture rather than beside it because every gate that filters
out this toolkit's own planted failures filters on the `fixtures/<name>/bad/` prefix —
including the versions already tagged, one of which this repo runs over itself as a
consumer. A layout only the working copy understands is one that breaks its own
published releases.

The tree leg carries the other half. A gate that rejects a *valid* form cannot be planted
in a fixture — the fixture model holds bad trees only — so a false red shows up only by
the real tree going red. That is why this repo's own denylist holds a canary term rather
than nothing: an empty list looks exercised and is not.

## What is here

| Gate | Checks |
|---|---|
| `gates/proxy-location.sh` | if `src/app` exists, any proxy or middleware file sits at `src/`, and the pre-Next-16 `middleware` name is flagged |
| `gates/migrations-lint.sh` | every up migration has a `.down.sql`; every `create table` enables row level security in the same file; destructive statements are noted as tier-3 |
| `gates/required-files.sh` | every path in the repo's own `scripts/gates/required-files.txt` exists and is tracked, dotfiles included |
| `gates/actions-sha-pinned.sh` | every `uses:` in a workflow is a 40-character commit SHA, never a tag |
| `gates/nextjs-env.sh` | a NEXT_PUBLIC_ variable named like a server secret; a tracked `.env` that is not `.env.example`; an optional per-repo denylist of names and slugs |
| `gates/check_secrets.py` | credential **values** in the working tree, and — when a range is supplied — the pushed history, commit messages, author and committer identities, added and renamed filenames, ref names and annotated tag objects, all through a redaction choke point |
| `gates/check_references.py` | every in-repo path cited in the docs resolves; anything it cannot parse is reported UNCHECKED, never passed |

`gates/lib.sh` is shared helpers, not a gate. It takes the tree to check as argument 1
or in `GATE_ROOT`, and exits 2 if neither is given — this toolkit is checked out beside
the repo it inspects, never inside it, so there is deliberately no default root to fall
back to.

## How to call it

Copy `caller-template.yml` into your repo as `.github/workflows/gates.yml` and replace
the placeholder with a real toolkit commit SHA:

```yaml
on: [pull_request, push]
jobs:
  gates:
    uses: chiibitsu/gates/.github/workflows/gates.yml@c3e3f49f91c3c39fc4a74d0ccf6bb8b15d70e3fd  # v1.0.2
    with:
      gates_ref: c3e3f49f91c3c39fc4a74d0ccf6bb8b15d70e3fd # v1.0.2
```

Pin a SHA, not a tag — that is the same rule `gates/actions-sha-pinned.sh` enforces on
you. Renovate with digest pinning will open a PR when a new release lands.

### Keeping the pin current

Renovate's `github-actions` manager bumps the `uses:` line but does not know about
`gates_ref`, so a bump would leave the pair mismatched — the workflow definition from
one commit running the gate scripts from another. Bump both with a custom manager:

```json
{
  "customManagers": [
    {
      "customType": "regex",
      "managerFilePatterns": ["/^\\.github/workflows/.*\\.ya?ml$/"],
      "matchStrings": ["gates_ref:\\s*(?<currentDigest>[0-9a-f]{40})\\s*#\\s*(?<currentValue>v[0-9.]+)"],
      "depNameTemplate": "chiibitsu/gates",
      "datasourceTemplate": "github-tags"
    }
  ]
}
```

The version comment beside `gates_ref` is load-bearing, not decoration: it gives the
custom manager the same release tag the `github-actions` manager resolves for the `uses:`
line, so both pins move to one commit. Tracking a branch here instead let the two resolve
independently and land a workflow definition from one commit running gate scripts from
another.

**The SHA appears twice on purpose.** A reusable workflow cannot discover its own
commit: `github.workflow_sha` and `github.workflow_ref` name the caller's workflow,
`github.action_ref` is empty outside composite actions, and `github.job_workflow_sha`
— which the docs describe as the commit SHA of the reusable workflow file — comes
through empty, measured on this repo rather than assumed. So the ref you pin has to be
handed in, and `gates_ref` is required rather than defaulted, because the only default
available is a branch and that would make your pin cosmetic. Change both together; the
workflow refuses anything that is not a 40-character SHA.

The reusable workflow checks your repo out into `repo/`, this toolkit into a sibling
`gates-toolkit/`, and runs `./gates-toolkit/selftest.sh repo`. Siblings, not nested: a
toolkit checked out inside your tree would put this repo's planted fixtures and its own
documentation into the tree the gates then inspect.

To run it by hand:

```sh
./selftest.sh /path/to/your/repo     # defaults to this repo
```

## The four per-repo config files

Three live in the repo being checked. The fourth belongs to the template, not here.

| File | Gate | What it is |
|---|---|---|
| `scripts/gates/required-files.txt` | required-files | one path per line; files must exist and be tracked, directories must exist |
| `scripts/gates/denylist.txt` | nextjs-env | terms that must never appear in the repo, one per line, case-insensitive. Absent file = check skipped |
| `.ci-allowed-refs` | check_references | deliberate reference exceptions in two sections: permanent above the `#!debt` marker line, promised-but-unbuilt below it. The debt section fails the run once a listed path starts existing, so entries get retired instead of outliving their reason. An **empty** file is a hard error — the marker line has to be there |
| `tests/e2e/protected-routes.json` | protected-routes (Playwright, against the preview deploy) | lives in the app template, not in this toolkit: it needs a running deployment, which a repo-local gate cannot supply |

## Adding a gate

1. Write `gates/<name>.sh`, sourcing `lib.sh`. First line after the shebang is the
   attribution comment, so a file lifted out of this repo still carries the name.
2. Plant `fixtures/<name>/bad/` — the smallest tree that trips it.
3. Run `./selftest.sh`. It must report that the gate catches its fixture **and** passes
   this tree. Without the fixture the selftest fails, which is the point.
4. Every time a review finds this gate passing something it should have caught, add that
   one shape as `fixtures/<name>/bad/cases/<shape>/` before the fix merges. The case has to
   fail on the old gate and pass on the new one, or it is not evidence of anything.

## Releases

| Version | Commit | Use it? |
|---|---|---|
| **v1.0.2** | `c3e3f49` | **Yes.** The first release with no known false green. Everything five review rounds found in v1.0.0 and v1.0.1 is fixed here, each fix carrying the minimal fixture that proves the shape is still caught — thirteen of them. Read Known gaps before relying on it: this version still answers with only two values, clean or violation, and cannot say *I could not check*. |
| v1.0.1 | `45834a1` | **Yes**, with one known false red. A workflow line like `uses: owner/repo@<40 hex> # docker://anything` is rejected as an unpinned container action, because this version tests the whole line for `docker://` instead of the parsed value. It errs toward a visible red, never a silent green, which is why the tag stands rather than moving. Fixed after the tag point. Review since then also found six more defects in the two gates rewritten at that tag point — including two outright false greens, and a denylist that made *any* repo with a non-empty one permanently red. All fixed after the tag; the fixes shipped in v1.0.2. Superseded — move to v1.0.2. |
| v1.0.0 | `39f78d6` | **No.** Four gates could pass a violation: migrations-lint read a commented-out `enable row level security` as evidence; actions-sha-pinned missed two legal YAML spellings of the `uses` key; required-files and nextjs-env skipped every git-backed check inside a linked worktree or submodule. It also deleted a `.gates-selftest` directory in the tree it was inspecting. The tag stays where it is — a published tag on a gate toolkit does not get moved — and this table is the record. |

## Known gaps

Stated rather than papered over. Most are inherited from `check_secrets.py`'s own
header, which is the honest account of what that scanner does not do.

- **History is not scanned by this workflow yet.** `check_secrets.py` covers the pushed
  range, commit metadata, ref names and annotated tag objects only when CI supplies
  them. The v1.0.0 reusable workflow runs it in working-tree mode, so history coverage
  in a consumer repo comes from gitleaks or from GitHub's own secret scanning, not from
  here.
- **Archives are not inspected.** Six review rounds found bypass after bypass in the
  machinery that opened them, and the rate never fell. It was removed.
- **LFS objects in history.** `lfs: true` materialises the checked-out tree only, so a
  credential added and deleted inside one pushed range is a pointer in the patch and
  absent from the tree.
- **Non-UTF-8 history hunks.** UTF-16 and UTF-32 content forced through git's text diff
  driver is reported as NOT scanned rather than decoded. Working-tree files are still
  decoded properly.
- **The pinning gate is a line matcher, and a line matcher cannot parse YAML.** It reads a
  `uses` key that starts a line, optionally after a `-`, a `{` or a quote. It therefore does
  NOT see `uses` when it is not the first key of a flow mapping — `- {name: build, uses:
  actions/checkout@v4}` and `steps: [{uses: a@main}, {uses: b@v1}]` both report ok — and by
  extension it cannot see a `#` inside a quoted scalar on such a line. This was attempted:
  the anchor was replaced with a full extraction pass that found every key on every line,
  and within one review round that version had produced a false green of its own (a `#`
  inside a quoted string read as a comment) and a false red (the text `uses:` inside a
  `run:` shell command). Neither a grep nor an awk can tell a YAML key from the same
  characters inside a string or a script, and the attempt was reverted rather than shipped.
  The real fix is a YAML parser, which is a version change and not a patch. Until then this
  is a stated blind spot rather than a discovered one, and it fails toward a tag being
  missed on an unusual spelling, never toward a pinned action being rejected.
- **A case proves detection by exit code, not by what the gate said.** The selftest asserts
  exit 1 from each case, so a defect that keeps the verdict and corrupts the report — a
  gate that stops halfway through its list and still exits 1, or one that prints the wrong
  evidence under the right heading — passes the case leg. Both have happened here. Checking
  stdout is part of the open issue on validating below the fixture level.
- **Some failure modes cannot be expressed as a fixture.** A gate now treats an errored
  search as a violation rather than as "no matches", because an unreadable directory
  under a workflows tree once made the pinning gate print ok over an unpinned action. No
  committed tree can reproduce that: git does not store a mode-000 directory, and the
  same tree behaves differently depending on which user CI runs as. The same holds for
  the paths taken only when git itself fails. These fixes were verified by hand and are
  the first items in the open issue on validating the parsers below the fixture level.
- **This is not a defence against a hostile pull request.** On `pull_request` GitHub
  runs the workflow definition from the proposed tree, so a PR can replace the job body
  and keep the check name. What closes that is push protection and org-level required
  workflows, neither of which lives in a repo.
- **Unicode tables come from the running CPython**, so a verdict can differ between
  runners. `--selftest` prints the interpreter and Unicode versions so drift is visible.
- **`check_references.py` only recognises paths under a fixed set of top-level
  directories** it was written for — .github, canon, docs, ops, patterns, product, team,
  templates, scripts (named without backticks here on purpose: backtick them and this
  gate correctly reads them as paths this repo does not have, which is how the sentence
  documenting the gate first broke it). Anything else is not read as an in-repo path and
  is therefore not checked: src and supabase in a Next.js repo, and gates and fixtures in
  **this** repo, so a rename inside the toolkit's own
  primary directory is invisible to this gate. The list is not extended here on purpose:
  the file is vendored byte-for-byte from vibeOS and a divergent second copy is the
  parallel-copies failure this shop has logged five times. It moves in vibeOS, or when
  vibeOS switches to calling this repo and this becomes the file's only home.
- **A red check only blocks a merge if branch protection marks it required.** Without
  that, it is a red icon someone can merge straight past. This repo cannot set that for
  you.

## Credit

The gates were derived from things that actually went wrong, each with a logged session
behind it: a proxy at the wrong level that left every route answering anonymous callers
with 200; a migration without a rollback that nearly deleted a live cohort; a published
template that shipped without its dotfiles; `actions/checkout@v4` on a workflow holding
a write token; two live clients' repo names in a public template. Not a wishlist.
