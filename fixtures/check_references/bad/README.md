# Planted failure for check_references

This document cites `docs/a-path-that-does-not-exist.md`, which is not in this tree.
That prefix is one of the top-level directories check_references.py treats as
repo-owned, so the citation is read as an in-repo path and must not resolve.

There is deliberately no allowlist file beside this one. An allowlist entry is what
makes a broken citation permissible, and a fixture whose failure can be waived is not
a fixture.
