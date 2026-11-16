# Governance

## Who maintains this

One maintainer: [@AmitSinghOM](https://github.com/AmitSinghOM), the
repository owner. The maintainer merges, releases, triages issues and
enforces the [Code of Conduct](CODE_OF_CONDUCT.md). There is no committee.

## How decisions are made

- **Written rules decide first.** [`CONTRIBUTING.md`](CONTRIBUTING.md)
  (gates, fail-first tests, version rules, privacy invariants),
  [`SECURITY.md`](SECURITY.md), [`docs/PRIVACY.md`](docs/PRIVACY.md) and
  the "Compatibility promise" in [`docs/ROADMAP.md`](docs/ROADMAP.md) are
  the standing decisions. A PR that conflicts with them is declined without
  a new discussion; changing the rule is its own PR.
- **Design decisions are recorded.** A change to scoring, the finding
  model, the privacy default or the dependency policy gets an ADR under
  [`docs/adr/`](docs/adr/) before the code merges. The roadmap records
  what is planned, deferred and cut, with the evidence.
- **Evidence over votes.** New rules, languages and patterns need corpus
  evidence (a measured false negative or a confirmed false positive), not
  popularity. Precision claims come from reading every hit at source and
  are recorded under [`docs/reviews/`](docs/reviews/).
- **Nothing merges red.** Every PR passes the full CI matrix. The baseline
  and the self-check threshold only ratchet in the strict direction.
- The maintainer has the final say on anything the rules do not cover and
  writes the reason in the PR or issue so it can be found later.

## Adding a second maintainer

The project wants one when there is a regular contributor. The path:

1. Several merged PRs over at least three months that each met every gate
   on the first review round, including fail-first tests and the privacy
   contract.
2. The maintainer proposes the person in a public issue titled
   `governance: add maintainer <handle>`, with the PRs as evidence. One
   week for objections from anyone.
3. On acceptance: GitHub **Maintain** role on the repository (not Admin:
   releases, settings, environments and the PyPI Trusted Publisher stay
   with the owner), an entry in this file, and an entry in `CODEOWNERS`
   (below).
4. A maintainer inactive for twelve months is moved to an "emeritus" line
   here and the role is removed, by the same public-issue procedure.

Release rights (the `pypi` environment, tags, the Trusted Publisher
configuration described in [`docs/RELEASING.md`](docs/RELEASING.md)) are
a separate, later step, taken only after the second maintainer has cut a
release under supervision.

## CODEOWNERS plan

There is no `.github/CODEOWNERS` yet; with one maintainer it would list
one name for everything and add nothing. When a second maintainer is
added it is created in the same PR, with:

- `*` -> both maintainers, so every PR gets a reviewer automatically;
- `/cqa_analyzer/anonymize.py`, `/cqa_analyzer/offline.py`,
  `/docs/PRIVACY.md`, `/SECURITY.md` -> the owner, so a privacy or
  security change always has the owner's review;
- `/.github/workflows/`, `/docs/RELEASING.md`, `/requirements-release.*`
  -> the owner, because they define what reaches PyPI.

Branch protection on `main` then requires one code-owner review in
addition to green CI.

## If the maintainer disappears

Everything needed to build, test and release is in this repository
([`docs/MAINTENANCE.md`](docs/MAINTENANCE.md), "Continuity notes"); no
local state, keys or tokens exist. The last release keeps installing and
scanning correctly because the analyzer has no server to fail. A fork may
continue the project under the MIT [`LICENSE`](LICENSE); the PyPI name
`cqa-analyzer` is owned by the maintainer's account and would need PyPI's
project-name transfer process.

## Changing this document

By pull request, like any other file. Changes to the "Adding a second
maintainer" procedure take effect for proposals opened after the merge.
