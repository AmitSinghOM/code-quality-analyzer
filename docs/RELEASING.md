# Releasing to PyPI

The distribution is published as **`cqa-analyzer`**. The name
`code-quality-analyzer` on PyPI belongs to an unrelated project, so all
install documentation must say `pip install cqa-analyzer` while the CLI
command remains `code-quality-analyzer`.

Publishing uses **PyPI Trusted Publishing (OIDC)** via
`.github/workflows/publish.yml` — no API token exists anywhere.
Publishing a GitHub release triggers the workflow, which rebuilds the
distributions from the tagged source, verifies the tag matches the
package version, and uploads to PyPI.

## One-time setup (PyPI website)

1. Create a PyPI account with 2FA enabled.
2. Configure the trusted publisher at
   [pypi.org/manage/account/publishing](https://pypi.org/manage/account/publishing/)
   using the **pending publisher** form (the project does not exist yet):
   - PyPI project name: `cqa-analyzer`
   - Owner: `AmitSinghOM`
   - Repository: `code-quality-analyzer`
   - Workflow name: `publish.yml`
   - Environment name: `pypi`
3. In the GitHub repository settings, create an environment named
   `pypi` (Settings → Environments). Optionally add yourself as a
   required reviewer so every upload needs a manual approval click.

No token is created, stored, or shared at any point.

## Release procedure

Run every step from the package root with a clean working tree.

1. **Gate.** All of these must pass:

   ```bash
   .venv/bin/python -m pytest
   .venv/bin/python -m ruff check .
   .venv/bin/python -m pip_audit
   ```

2. **Versions.** Confirm `cqa_analyzer/__init__.py` (`__version__`,
   `RULESET_VERSION`) and the `CHANGELOG.md` entry agree, and that the
   changelog entry is dated. Update the pinned-version example in the
   README's **Upgrade** section (`cqa-analyzer==X.Y.Z`) to the new
   version — `tests/test_release_metadata.py` fails if it is stale, so
   the gate in step 1 catches a forgotten bump.

3. **Merge to main and push the tag** `vX.Y.Z` matching `__version__`
   (do not publish the release yet).

4. **Dry-run the publish workflow.** In Actions → *Publish to PyPI* →
   *Run workflow*, set `tag=vX.Y.Z` and leave `dry_run=true` (the
   default). Confirm the `build` job passes its tag/version guard and
   `twine check --strict`; the `publish` job is skipped. The build job
   installs `build` and `twine` from the hash-pinned
   `requirements-release.txt` (regenerate it with the command at the top
   of `requirements-release.in` when bumping either tool). One residual:
   `python -m build` still resolves the setuptools build backend into its
   isolated environment from pyproject's `[build-system]` range, unhashed.

5. **Publish the GitHub release** for that tag. The `release` event
   runs `publish.yml` for real: it rebuilds from the tagged source,
   verifies the tag/version agreement, runs `twine check --strict`, and
   uploads to PyPI through the `pypi` environment via OIDC.

6. **Verify.** Watch the workflow run, then `pip install cqa-analyzer`
   in a fresh venv, run one scan, and confirm the version. Update the
   README pre-commit `rev:` pin if this release should become the
   documented hook version.

## Post-release

- Bump `__version__` only when the next change lands (versions are not
  pre-bumped).

## Known constraints

- The tag must exactly equal `v` + `__version__`; the publish workflow
  fails closed on any mismatch.
- A manual *Run workflow* dispatch only uploads when `dry_run` is
  explicitly set to `false`.
- Manual `twine upload` remains possible as a break-glass path with a
  short-lived project-scoped token, but Trusted Publishing is the
  supported flow.
