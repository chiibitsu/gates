# Review instructions

Read by two things, and it matters which: Anthropic's managed **Code Review** service picks
this file up from the repository root on its own, and `.github/workflows/review.yml` loads it
**by name in its prompt** because `anthropics/claude-code-action` does not read it
automatically. If you rename or move this file, the workflow's prompt has to change with it.

This file is instructions, not context. `@` imports are not expanded and referenced files are
not pulled in, so every rule that must be followed is written out below.

## A check reads its rules from outside the thing it checks

Canon, and the reason `review.yml` does not read this file out of the workspace it is
reviewing. It extracts it from the **base revision** first, because a copy in the pull request
is a copy that pull request can edit — one commit adding "report nothing" here and the reviewer
obeys, on the very run that was supposed to read that commit. The rules would be set by the
thing being judged against them.

The deterministic gates already worked this way and it took a reviewer to make it visible:
`gates.yml` checks the toolkit out at a **pinned** ref and never reads a gate from the caller's
diff. A change to this file therefore takes effect when it merges, which is the same deal every
gate change gets. If the base has no `REVIEW.md`, the run is UNKNOWN and red rather than
unguided — falling back to the workspace copy would be a silent downgrade to the untrusted one.

Stated here once. `review.yml` points at this section rather than restating it.

## What Important means here

Reserve **Important** for a finding that would **break behaviour, leak data, or block a
rollback**. Concretely: incorrect logic, a database query not scoped to the caller's
organisation, PII in a log line or error message, a migration with no working `.down.sql`, an
error path that resolves to a benign-looking outcome, and a check whose message claims more
than the check actually asserts.

Everything else is a **Nit**: naming, structure, style, refactors, and preferences. A finding
you cannot state as a failure scenario is a Nit at most, and usually not worth posting.

## Cap the nits

At most **five** Nits per review. If there are more, add "plus N similar items" to the summary
rather than posting them inline. If everything found is a Nit, open the summary with
"No Important findings."

## Do not report

- **Anything the deterministic gates already enforce.** They run on the same commit and they
  do not need a second opinion: unpinned `uses:` refs, a migration without RLS or without a
  down file, a missing required file, a `NEXT_PUBLIC_` name that looks like a secret, a
  credential value, a broken in-repo doc reference, and a request-path module that can reach
  the service-role secret. If one of those is wrong, the gate is red already; if the gate is
  green and you disagree with it, that is a finding about the **gate**, and it belongs in
  chiibitsu/gates with a fixture, not as a comment on this diff.
- Lockfiles.
- `fixtures/` — every file under it is a planted failure. Its whole purpose is to be wrong.
- Vendored files: `gates/check_secrets.py` and `gates/check_references.py` are byte-identical
  to their vibeOS originals bar one attribution line, and a change to them there is not this
  PR's to make.

## Always check

For a Next.js + Supabase change:

- A new route, server action or route handler has a test.
- Every database query is scoped to the caller's organisation. `service_role` bypasses row
  level security, so an unscoped query is a data-exposure finding, not a style one.
- No PII in logs or error messages: no email address, user id, token, or request body.
- Every migration is reversible — a `.down.sql` that actually undoes it, not a stub.

And on any change:

- **A test's name is a claim about the path it exercises.** If the name says one thing and the
  body exercises another, that is Important: the test will be read as covering ground it does
  not cover.
- **Review the exceptions to a boundary before the boundary itself.** An allowlist entry, a
  `catch` that swallows, a skipped case, a `|| true`, an early `return` — these are where a
  boundary stops holding, and they are cheaper to read than the boundary.
- **Every enumeration is asserted by name, in both directions.** Where one list is checked
  against another, neither may be used to filter the other, and each list must exist in
  exactly one place. A list checked in one direction only is how a deleted entry becomes
  invisible.

## Verification bar

Post a finding only with a **`file:line` citation and a reproduction** — the input or state
that produces the wrong result, and what the reader would see. **No inference from names.**
That a function is called `validateOrgAccess` is not evidence that it validates org access;
read the body and cite the line. A finding you could not reproduce is not a finding, and
saying so costs the author nothing while a wrong one costs them a round trip.

## Re-review convergence

After the first review of a pull request, post **Important findings only**. No new Nits on
round two or later, however tempting. A one-line fix must not reach round seven on style.

If a prior finding is now addressed, say so and withdraw it. If it still stands after a push,
say that too rather than reposting it as new.

## Summary shape

Open the summary with a tally on its own line — `2 Important, 4 Nits` — before any prose. When
there are no Important findings, say "No Important findings" first. The author wants the shape
of the work before the detail.
