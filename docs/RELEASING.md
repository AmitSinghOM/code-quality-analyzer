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
   changelog entry is dated.

3. **Merge to main and publish a GitHub release** whose tag is
   `vX.Y.Z` matching `__version__`. Publishing the release triggers
   `publish.yml`, which rebuilds from the tagged source, verifies the
   tag/version agreement, runs `twine check --strict`, and uploads to
   PyPI through the `pypi` environment via OIDC.

4. **Verify.** Watch the workflow run, then `pip install cqa-analyzer`
   in a fresh venv, run one scan, and confirm the version. Update the
   README pre-commit `rev:` pin if this release should become the
   documented hook version.

## Post-release

- Bump `__version__` only when the next change lands (versions are not
  pre-bumped).

## Known constraints

- The tag must exactly equal `v` + `__version__`; the publish workflow
  fails closed on any mismatch.
- Manual `twine upload` remains possible as a break-glass path with a
  short-lived project-scoped token, but Trusted Publishing is the
  supported flow.
