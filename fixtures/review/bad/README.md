# `fixtures/review/bad` — the reviewer's known-bad case

Every gate in this repo ships a fixture that `selftest.sh` proves it fails on. The draft-stage
reviewer cannot be selftested that way, and pretending otherwise would be the exact defect this
toolkit is built to refuse.

**Why it is not in the selftest.** `selftest.sh` asserts a gate exits non-zero on a planted
tree. The reviewer is a model reading a diff and posting comments through the GitHub API: it
needs a live pull request, a token, and a network, and it is not deterministic — the same diff
can produce differently-worded findings. A leg in `selftest.sh` that "passed" would be
asserting something it had not established. So this fixture is a **procedure a person runs**,
and its result is evidence about one run, not a proof.

`gates/MANIFEST.txt` lists gates. `review` is deliberately not in it, because it is not one.

## What is planted

`src/app/api/items/route.ts` holds two defects, on purpose:

| Line | Defect | Required severity |
|---|---|---|
| the `.select("*")` call | a Supabase query with **no organisation scope** | **Important** |
| the `console.error` call | the query result is written to the log | Important or Nit |

The first is the one that matters. `REVIEW.md` says an unscoped query is a data-exposure
finding, and a reviewer that reports it as a Nit — or does not report it — has failed this
fixture just as surely as one that says nothing.

## How to run it

1. In a repository whose workflow calls `chiibitsu/gates/.github/workflows/review.yml`, copy
   `src/app/api/items/route.ts` from this fixture to the same path in that repo.
2. Open a pull request **as a draft**. The reviewer runs only on drafts; on a ready PR the job
   reports `skipped`, and skipped is not a pass.
3. Wait for the `Draft review` job.

## What counts as passing

All three, and a miss on any one is a failure:

- An **inline comment on the `.select("*")` line**, marked **Important**, naming the missing
  organisation scope, and carrying a reproduction rather than an inference from the name.
- The tally comment: `reviewed <short-sha>: N findings`, with `N` at least 1.
- **No finding about anything under `fixtures/`** if this tree is reviewed whole — `REVIEW.md`
  tells it not to report planted failures, and a reviewer that lectures about the fixture has
  not read its instructions.

## What a failure means

The gate scripts fail when a tree is wrong. This fails when **`REVIEW.md` or the prompt in
`review.yml` is wrong** — the tree is doing its job by being bad. Fix the instructions, not the
fixture, and record the run that failed and the run that passed in the pull request that
changes them.
