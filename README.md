# gates

Deterministic CI gates that must prove they can fail before they count.

## Author

Built and maintained by **Angeline S. Viray**, founder of Chiibitsu Labs
(<https://chiibitsu.com>), as the deterministic gate layer of **vibeOS** — her
operating system for shipping production software with AI builders as a non-coder
product architect.

> "A gate that cannot fail is not a gate."
> — Angeline S. Viray, vibeOS, `templates/tier1-ci.yml`

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
    uses: chiibitsu/gates/.github/workflows/gates.yml@39f78d697778c52ecf1cb2914cb00b5db9025e7a  # v1.0.0
    with:
      gates_ref: 39f78d697778c52ecf1cb2914cb00b5db9025e7a
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
      "matchStrings": ["gates_ref:\\s*(?<currentDigest>[0-9a-f]{40})"],
      "depNameTemplate": "chiibitsu/gates",
      "packageNameTemplate": "https://github.com/chiibitsu/gates",
      "datasourceTemplate": "git-refs",
      "currentValueTemplate": "main"
    }
  ]
}
```

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
- **This is not a defence against a hostile pull request.** On `pull_request` GitHub
  runs the workflow definition from the proposed tree, so a PR can replace the job body
  and keep the check name. What closes that is push protection and org-level required
  workflows, neither of which lives in a repo.
- **Unicode tables come from the running CPython**, so a verdict can differ between
  runners. `--selftest` prints the interpreter and Unicode versions so drift is visible.
- **`check_references.py` only recognises paths under a fixed set of top-level
  directories** it was written for: `.github/`, `canon/`, `docs/`, `ops/`, `patterns/`,
  `product/`, `team/`, `templates/`, `scripts/`. Anything else is not read as an in-repo
  path and is therefore not checked — `src/…` and `supabase/…` in a Next.js repo, and
  `gates/…` and `fixtures/…` in **this** repo, so a rename inside the toolkit's own
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
