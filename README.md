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
| `gates/service-role.sh` | no request-path module can reach the service-role secret. Walks the import graph out of `app/`, `pages/`, `middleware.*` and `proxy.*`; any import it cannot resolve is reported **UNKNOWN**, never assumed clean |

`gates/lib.sh` is shared helpers, not a gate. It takes the tree to check as argument 1
or in `GATE_ROOT`, and exits 2 if neither is given — this toolkit is checked out beside
the repo it inspects, never inside it, so there is deliberately no default root to fall
back to.

`gates/MANIFEST.txt` is the one place gate names are written down. `selftest.sh` asserts it
against the `gates/` directory **by name, in both directions**, and uses neither list to
filter the other: a gate file with no entry fails, an entry with no file fails. Before it
existed, deleting a gate was invisible — the run read the directory, tested one fewer gate,
and printed *every gate was shown to fail*, which was true of a smaller set than the reader
had any way to know about.

### The draft-stage reviewer — Tier 2, and not a gate

`.github/workflows/review.yml` is a reusable workflow that has a model read the diff against
`REVIEW.md` **while the pull request is still a draft**, so findings arrive before anyone is
asked to look. `REVIEW.md` at the repository root is what it reads: severity calibration, a nit
cap, what not to report, the verification bar, and how to converge on re-review.

**It is not a gate and must never be a required check.** Nothing about it is deterministic, it
cannot be shown to fail on a fixture the way `selftest.sh` shows every gate failing, and
`gates/MANIFEST.txt` deliberately does not list it. Its known-bad case is a procedure a person
runs — `fixtures/review/bad/README.md` — whose result is evidence about one run, not a proof.

Two details that are easy to get wrong:

- **`REVIEW.md` is read by name, from the BASE revision.** Anthropic's managed Code Review
  service picks that file up from the repository root on its own; `anthropics/claude-code-action`
  does not, so the prompt names it. The workflow extracts it out of the base commit into
  `.review-policy.md` before the model runs, because a workspace copy is a file the pull request
  under review can edit — one commit adding "report nothing" and the reviewer obeys, on the run
  that was meant to read that commit. Same arrangement as the gates, which are checked out at a
  pinned ref and never read from the caller's diff. A change to `REVIEW.md` takes effect when it
  merges. If the base has no `REVIEW.md`, the run is UNKNOWN and red rather than unguided.
- **The tally is posted by the workflow, not by the model.** Every run ends with
  `reviewed <sha>: N findings`, and when the model does not report a count the step posts
  `UNKNOWN` and goes red. A reviewer that died silently is indistinguishable from a clean one,
  so that case is made impossible rather than unlikely.

### UNKNOWN

A gate can say three things. A checks UI has two colours.

`ok` is green, a violation is red, and **"I could not check this" is also red** — the same
red. There is no third colour to reach for: `exit 2` does not produce a neutral check run,
and a `::warning` annotation leaves the run green, which is the one outcome "could not check"
must never produce. So UNKNOWN exits 1 exactly like a violation, and the difference lives
where a reader will actually see it — the `UNKNOWN [gate] <reason>` line, the summary line
that counts unknowns separately from violations, and an `::error title=UNKNOWN` annotation.

`selftest.sh` proves it the way it proves everything else. `fixtures/<gate>/bad/unknown/<case>`
trees must make the gate go red **with** an UNKNOWN line and **without** a FAIL line. Only
requiring the red would be satisfied by a gate that invented a violation instead — which
sends someone hunting for a bug in their code rather than a blind spot in the gate.

## How to call it

This snippet carries `<sha-from-the-releases-table>` rather than a real hash, and that is the
one place in this repository where a placeholder is right: it showed `25a1ca1` / v1.0.3 for
three releases after that pin stopped being current, and a stale real SHA is copied without
hesitation while a placeholder cannot be. `caller-template.yml` ships a real SHA because it has
to run; this prose does not.

Copy `caller-template.yml` into your repo as `.github/workflows/gates.yml`. It ships a real
SHA rather than a placeholder, and that SHA is the **previous** release. Replace **all three**
occurrences with the one you want from the Releases table below — the `gates:` `uses:` ref,
the `gates_ref:` under it, and the `review:` `uses:` ref. The first two must stay identical to
each other: a reusable workflow cannot discover its own commit, so the ref it runs from has to
be handed to it, and a mismatch runs one release's workflow over another release's gates. This
sentence said "both occurrences" over a snippet containing three, which is a count narrower
than the thing it describes — the defect this repository exists to catch, in its own
instructions.

```yaml
on: [pull_request, push]
jobs:
  gates:
    uses: chiibitsu/gates/.github/workflows/gates.yml@<sha-from-the-releases-table>  # v1.2.1
    with:
      gates_ref: <sha-from-the-releases-table> # v1.2.1

  # The draft-stage reviewer. Needs a repository secret CLAUDE_CODE_OAUTH_TOKEN, and the
  # permissions block because a called workflow can only narrow the caller's token, never
  # widen it — without it the tally step 403s on a read-only default.
  review:
    permissions:
      contents: read
      pull-requests: write
      issues: read
      id-token: write
    uses: chiibitsu/gates/.github/workflows/review.yml@<sha-from-the-releases-table> # v1.2.1
    secrets:
      CLAUDE_CODE_OAUTH_TOKEN: ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}
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

## The six per-repo config files

Five live in the repo being checked. The sixth belongs to the template, not here.

| File | Gate | What it is |
|---|---|---|
| `scripts/gates/required-files.txt` | required-files | one path per line; files must exist and be tracked, directories must exist |
| `REVIEW.md` | review (Tier 2) | review-only instructions at the repository root: severity, nit cap, skip rules, always-checks, verification bar, convergence. Read by the managed Code Review service automatically, and by `review.yml` because its prompt names it |
| `scripts/gates/service-role-terms.txt` | service-role | the identifiers whose presence in a module means that module can reach service-role, one per line. Absent file = a built-in list of the Supabase spellings. An **empty** file is a hard error: a term list that matches nothing is not a check |
| `scripts/gates/denylist.txt` | nextjs-env | terms that must never appear in the repo, one per line, case-insensitive. Absent file = check skipped |
| `.ci-allowed-refs` | check_references | deliberate reference exceptions in two sections: permanent above the `#!debt` marker line, promised-but-unbuilt below it. The debt section fails the run once a listed path starts existing, so entries get retired instead of outliving their reason. An **empty** file is a hard error — the marker line has to be there |
| `tests/e2e/protected-routes.json` | protected-routes (Playwright, against the preview deploy) | lives in the app template, not in this toolkit: it needs a running deployment, which a repo-local gate cannot supply |

## Adding a gate

1. Write `gates/<name>.sh`, sourcing `lib.sh`. First line after the shebang is the
   attribution comment, so a file lifted out of this repo still carries the name.
2. Add it to `gates/MANIFEST.txt` with its mode (`fixture`, `selftest` or `library`). The
   selftest checks the directory and the manifest against each other in both directions, so
   a gate that is in one and not the other fails the run rather than going unnoticed.
3. Plant `fixtures/<name>/bad/` — the smallest tree that trips it.
4. If the gate has a case it genuinely cannot decide, plant that too, as
   `fixtures/<name>/bad/unknown/<case>/`. It must go red with an UNKNOWN line and no FAIL
   line. Under `bad/`, never beside it: published releases filter their own planted failures
   on the `fixtures/<gate>/bad/` prefix, and `caller-smoke.yml` runs a pinned release over
   this tree.
5. Run `./selftest.sh`. It must report that the gate catches its fixture **and** passes
   this tree. Without the fixture the selftest fails, which is the point.
6. Every time a review finds this gate passing something it should have caught, add that
   one shape as `fixtures/<name>/bad/cases/<shape>/` before the fix merges. The case has to
   fail on the old gate and pass on the new one, or it is not evidence of anything.

## Releases

The Commit column names a **tag** for the current release and a SHA for superseded ones, and that asymmetry is forced: the table lives in the commit being tagged, so it cannot contain that commit's own hash. Resolve the tag — `git rev-list -n1 v1.2.1` — and pin the SHA you get. Pin a SHA, never a tag: a tag is a movable name, and this table exists because names have been wrong here before.

That rule applies to everything this repo pins, not only to itself, and the reviewer's action is the measured case. On 2026-09-08, `anthropics/claude-code-action` resolved as:

```
refs/tags/v1        b7912aeeb535234e3e9385ff49e8237f689b5f14
refs/tags/v1.0.217  ef7878a0506921197f7f9cd8a6c8dc7b11497021
```

`v1` is a moving pointer, and it sat on the commit of **no concrete release** — pinning what `@v1` happens to resolve to would have pinned neither the latest release nor anything with a version number on it. A patch tag does not move, so `review.yml` pins `v1.0.217`. Measured with `git ls-remote` against the action's own repository, not read off a docs page.

A release's `CITATION.cff` names its own version — that is the part that must be right. v1.0.0 and v1.0.1 got it right, v1.0.2 and v1.0.3 did not, and v1.0.4 restores it. The regression is worth reading as evidence for the rule rather than as two mistakes: the correction to a version's metadata is *made by* a pull request, so it lands in a commit **after** the one being tagged, and tagging the merged head of the PR that still reports the previous version is one behind by construction. A release must declare its own version **before** it is tagged. A release's workflow pins cannot name that release, because a commit cannot contain its own future SHA. What they name instead is **not derivable**, so do not try: **from v1.0.2 onward they point at the previous release, and before that they pointed at untagged ancestors** — v1.0.0 pins `186ff05` and v1.0.1 pins `2428668`, neither of which carries any tag, and v1.0.1 labels its untagged pin with its own version number. **Take the SHA to pin from this table, never from the example in a checkout.** That is the whole reason this table exists.

| Version | Commit | Use it? |
|---|---|---|
| **v1.2.1** | tag `v1.2.1` — resolve with `git rev-list -n1 v1.2.1`, or read it off the release page | **Yes — use this one.** Fixes three defects in `service-role.sh` that v1.1.0 and v1.2.0 both shipped, each reproduced before the fix and each carrying a fixture: an ordinary circular import **did not terminate** (a hang, which reports nothing at all); one file reached by two spellings was counted twice, printing two findings each claiming "1 request-path module(s)"; and a multi-line `await import(` was a **false green** — `ok`, exit 0, over a page reaching `SUPABASE_SERVICE_ROLE_KEY`. Also fixes a concurrency key in `review.yml` that collapsed on non-PR events. Carries v1.0.2's known false green in `actions-sha-pinned.sh`, described below. |
| v1.2.0 | `44f6125` | **Do not use.** Its `service-role.sh` is byte-identical to v1.1.0's and carries all three defects listed under v1.2.1 — including a false green on a multi-line dynamic import and a walk that does not terminate on a circular one. The reviewer it adds is sound; the gate underneath it is not. Move to v1.2.1. |
| v1.1.0 | `7832ea6` | **Do not use** — same three `service-role.sh` defects as v1.2.0, described in the v1.2.1 row. Six gates, no reviewer. Added `service-role.sh`, the UNKNOWN outcome, and `gates/MANIFEST.txt` with a both-directions check against the `gates/` directory. Adopting it can turn a consumer red on code that was green under v1.0.4, because `service-role.sh` did not exist to check it; that is a finding, not a regression. |
| v1.0.4 | `e075a93` | **Usable, and superseded by v1.1.0** — five gates instead of six, so nothing checks whether the request path can reach the service-role secret. Its `CITATION.cff` names the version on its tag, which v1.0.0 and v1.0.1 also did and v1.0.2 and v1.0.3 did not. Gates byte-identical to v1.0.2 and v1.0.3, so it carries their one known false green, described below. |
| v1.0.3 | `25a1ca1` | **Do not cite.** Its gates are correct and identical to v1.0.2's, so a pin at this SHA works. But its `CITATION.cff` says `1.0.2` and its caller template says `v1.0.2` — this tag reproduces the exact defect it was cut to fix. The cause is structural and is the useful part: the correction to a version's metadata is *made by* the pull request, so it lands in a commit **after** the one being tagged. Tagging the merged head of the PR that reports the previous version is guaranteed to be one behind. A release has to declare its own version **before** it is tagged, which is what v1.0.4 does. |
| v1.0.2 | `c3e3f49` | **Usable, and superseded by v1.0.4** — same gates, wrong version metadata inside the tag. Everything six review rounds found in v1.0.0 and v1.0.1 is fixed here, each fix carrying the minimal fixture that proves the shape is still caught. It has **one known false green**, reproducible: `steps: [{uses: a/b@main}, {uses: c/d@v1}]` reports ok. The rule that produces it is stated once, in Known gaps below, and deliberately not paraphrased here — a first draft of this row paraphrased it and got the rule wrong in a different way than the gap section did, which is how two statements of one fact always end. Treat this release as a first line, never as the only one. An earlier draft of this row claimed no known false green while the gap below already described one — the claim was wrong, and it is corrected here rather than quietly dropped. |
| v1.0.1 | `45834a1` | **Yes**, with one known false red. A workflow line like `uses: owner/repo@<40 hex> # docker://anything` is rejected as an unpinned container action, because this version tests the whole line for `docker://` instead of the parsed value. It errs toward a visible red, never a silent green, which is why the tag stands rather than moving. Fixed after the tag point. Review since then also found six more defects in the two gates rewritten at that tag point — including two outright false greens, and a denylist that made *any* repo with a non-empty one permanently red. All fixed after the tag; the fixes shipped in v1.0.2. Superseded — move to v1.0.4. |
| v1.0.0 | `39f78d6` | **No.** Four gates could pass a violation: migrations-lint read a commented-out `enable row level security` as evidence; actions-sha-pinned missed two legal YAML spellings of the `uses` key; required-files and nextjs-env skipped every git-backed check inside a linked worktree or submodule. It also deleted a `.gates-selftest` directory in the tree it was inspecting. The tag stays where it is — a published tag on a gate toolkit does not get moved — and this table is the record. |

## Known gaps

Stated rather than papered over. Most are inherited from `check_secrets.py`'s own
header, which is the honest account of what that scanner does not do.

- **History is not scanned by this workflow yet.** `check_secrets.py` covers the pushed
  range, commit metadata, ref names and annotated tag objects only when CI supplies
  them. The reusable workflow — in every release so far, this one included — runs it in
  working-tree mode, so history coverage
  in a consumer repo comes from gitleaks or from GitHub's own secret scanning, not from
  here.
- **The draft-stage reviewer is not deterministic and is not proven by the selftest.** It is a
  model reading a diff. The same change can produce differently-worded findings, and
  `fixtures/review/bad/` is a manual procedure rather than a leg of `selftest.sh` — a leg that
  "passed" would be asserting something it had not established. Treat its output as a second
  reader, never as a check.
- **This repository does not run the reviewer on its own pull requests yet.** `review.yml` ships
  here and is called from consumer repositories; wiring a self-call is a separate change, so
  until then the fixture procedure is the only thing that exercises it. Stated because a
  reviewer nobody has run is a reviewer nobody has seen fail.
- **The migrations-lint gate tokenises SQL; it does not match it.** Statements are scanned
  once — quoted identifiers with their `""` escapes, any schema or database qualifier,
  `unlogged`/`temp`/`temporary`, `IF [NOT] EXISTS`, `ALTER TABLE ONLY`, a statement spanning
  lines — and the created and RLS-enabled **(schema, table) pairs are compared as strings**.
  So RLS on `archive.orders` does not satisfy a `create table public.orders`; an unqualified
  name normalises to `public`; and a quoted identifier keeps its case, because PostgreSQL
  folds `Orders` to `orders` but keeps `"Orders"` distinct — Prisma and Drizzle emit the
  quoted PascalCase form. Three successive regex versions each traded one error for another
  here; the pair comparison leaves no interpolated pattern to be wider than the name it was
  given. It reads a `create table` inside a function body and inside a `DO $$` block, and reds
  on both. It does **not** read one inside a `'…'` string literal: a string is data to the
  scanner, and reading it named tables nobody created and sent fixers to edit their data —
  but a string containing both `create` and `table` is reported UNKNOWN rather than passed
  over, because `execute` runs it. Comments are recognised by the same scanner, not stripped by an
  earlier stage: a stage that cannot see strings took `values ('x /* y')` for the start of a
  block comment and deleted every line to the next `*/`, hiding a whole `create table` —
  verified against PostgreSQL 16 as a real table left with RLS off — and the same swallow
  turned a compliant migration containing `values ('/api/*')` red with a message naming a
  string that does not exist. What it genuinely cannot read, as silent passes: a name
  assembled at runtime (`execute format('create table %I …')` or string concatenation) and
  `select … into`. **An unterminated quoted identifier, string or block comment is UNKNOWN,
  not a pass** — a scanner that lost sync read everything after it as something it is not,
  and one `"` inside an ordinary string literal (an inch mark in `values ('24" monitor')`)
  is enough to do that.
- **The service-role gate tokenises JavaScript; it does not match it.** Strings, template
  literals, line and block comments and regex literals are recognised as what they are, and a
  specifier is emitted only from a real `from`/`import`/`require` position. This replaced a
  `grep -o` extractor whose non-overlapping window let a string ending in the word `from`
  consume the following import into one invented span — a defect with no correct filter,
  because reporting the span was a blocking UNKNOWN on ordinary source (`Array.from(",")`, a
  regex literal, `{ note: "Imported from " }`) and dropping it lost a real import that had
  been swallowed. Both were measured, in three consecutive review rounds, before the
  extractor itself was replaced. A multi-line `await import(` is followed; a `//` comment no
  longer runs into the code after it; `import(/* webpackChunkName */ "./x")` is read as the
  literal import it is. **A template literal or block comment still open at end of file is
  UNKNOWN**, because a scanner that lost sync read the rest of the file as something it is
  not — one stray backtick in JSX text otherwise consumed everything below it, and a
  `require("@/lib/admin")` under it reported `ok`. What it still cannot read is **JSX text**:
  `<p>Copied from "a" to "b"</p>` puts `from` before a quote and nothing short of a JSX parser
  can tell that from an import, so a candidate carrying `<`, `>`, `{` or `}` is dropped as
  text. Node subpath imports (`#internal/db`) are UNKNOWN: they resolve through `package.json`
  `imports`, which this gate does not read.
- **Every scanner here is line-incremental, and the comparison is not a shell loop.** The
  first version accumulated each file with `buf = buf $0 "\n"`, which mawk reallocates and
  copies every line: 12.1s on a 1.1MB generated types file against 0.11s for the greps it
  replaced, and quadratic. Fixing that left the same shape one stage downstream — a nested
  bash loop comparing created tables against RLS-enabled ones, 33.5s for 2000 tables — which
  is now a `grep -Fxv`, 0.10s. `gates.yml` sets no `timeout-minutes`, so either would have
  surfaced not as a red but as a job taking minutes: the shape of the hang this toolkit has
  already shipped once. Both numbers are here because the first fix was reported as closing
  the problem while half of it was still there.
- **The service-role gate resolves like TypeScript, with one deliberate divergence.** It
  follows `./`, `../`, absolute paths, and **every alias declared in tsconfig
  `compilerOptions.paths`** — not just `@/*` — plus a **`baseUrl` with no matching `paths`
  entry**, which is Next.js's documented "Absolute Imports" and which was a false green
  chosen by nothing but the spelling of the import. `baseUrl` arms on the presence of the
  key, read from a **comment-stripped** copy of tsconfig.json, because a commented-out
  `// "baseUrl": "."` is not configuration. A specifier matching no alias is called a
  published package **only if it could be one** — tested against npm's name shape, so
  `@/lib/secret` is UNKNOWN, not a dependency to skip. One that matches an alias and resolves
  to no file is UNKNOWN, never skipped; a `paths` object nothing parses out of is UNKNOWN too.
  It maps the **emitted** extension back to the source (`./m.mjs` → `m.mts`, `.cjs` → `.cts`,
  `.js` → `.ts`/`.tsx`) as `moduleResolution: nodenext` requires. **The divergence:
  implementation before declaration.** TypeScript resolves `./admin.js` to `admin.d.ts` when
  both exist; this gate takes `admin.js`, because a declaration file by construction cannot
  hold a secret and the question here is what code runs in the request path, not where the
  types are.
- **The service-role gate does not follow tsconfig `extends`.** Aliases are read from the
  repo's own `tsconfig.json` only. TypeScript does not deep-merge `paths` — measured with
  tsc 5.6.3: a child that declares `paths` REPLACES the base's object entirely, so a base's
  `@/*` is already dead in that tree — but a child that declares `extends` and no `paths` of
  its own inherits them, and this gate cannot see them. That case is UNKNOWN, not a pass.
  A `baseUrl` **inherited from a base config** is not read either, which makes alias targets
  fail to resolve and go UNKNOWN: a false red, and the direction this toolkit errs in.
- **The service-role gate does not look inside published packages.** A bare specifier
  (`react`, `@supabase/ssr`) is out of scope by definition, so a third-party module that
  reads `process.env.SUPABASE_SECRET_KEY` itself is invisible to it. Repo source is what it
  covers.
- **The service-role term list matches literal names.** `process.env["SUPABASE" +
  "_SECRET_KEY"]` is not a literal occurrence of any listed term and is not caught.
- **The service-role gate knows Next.js request paths and no others.** `app/`, `pages/`,
  `middleware.*`, `proxy.*`. A tree that depends on `next` and has none of them is UNKNOWN;
  a tree that does not depend on `next` is reported as having no request path to walk, in
  those words, rather than as a pass.
- **Archives are not inspected.** Six review rounds found bypass after bypass in the
  machinery that opened them, and the rate never fell. It was removed.
- **LFS objects in history.** `lfs: true` materialises the checked-out tree only, so a
  credential added and deleted inside one pushed range is a pointer in the patch and
  absent from the tree.
- **Non-UTF-8 history hunks.** UTF-16 and UTF-32 content forced through git's text diff
  driver is reported as NOT scanned rather than decoded. Working-tree files are still
  decoded properly.
- **The pinning gate is a line matcher, and a line matcher cannot parse YAML.** Its anchor
  allows only whitespace, `-`, `{`, `,` and a quote before the key. So it sees `uses` only
  when **everything preceding it on that line is one of those characters**, and anything else
  in front makes the key invisible. Two shapes reach that state by different routes, and both
  report ok:

  - `- {name: build, uses: actions/checkout@v4}` — the letters in `name: build` are not in
    the leading class. `uses` is not the first key here.
  - `steps: [{uses: a@main}, {uses: b@v1}]` — `[` is not in the leading class either. Note
    that `uses` **is** the first key of its mapping in this one, so key position is not the
    rule; an earlier version of this note said it was, and gave this line as its example.

  By extension the gate also cannot see a `#` inside a quoted scalar on such a line. This was attempted:
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
