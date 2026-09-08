# Releasing to PyPI

The distribution is published as **`cqa-analyzer`**. The name
`code-quality-analyzer` on PyPI belongs to an unrelated project, so all
install documentation must say `pip install cqa-analyzer` while the CLI
command remains `code-quality-analyzer`.

## One-time setup (maintainer machine)

1. Create a PyPI account with 2FA enabled.
2. Create a project-scoped API token at
   [pypi.org/manage/account/token](https://pypi.org/manage/account/token/)
   (account-scoped for the first upload; replace it with a project-scoped
   token immediately after the project exists).
3. Never commit the token. Supply it per-invocation via
   `TWINE_USERNAME=__token__` and `TWINE_PASSWORD=<token>` environment
   variables, or a `keyring` entry.

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

3. **Tag.** Tag the release commit and push the tag (the pre-commit hook
   contract pins tags):

   ```bash
   git tag -a vX.Y.Z -m "vX.Y.Z: <summary>"
   git push origin vX.Y.Z
   ```

4. **Build.** Build from a clean `dist/`:

   ```bash
   rm -rf dist
   .venv/bin/python -m build
   ```

5. **Validate.** Both artifacts must pass, and the wheel must work in a
   fresh environment:

   ```bash
   .venv/bin/python -m twine check dist/*
   python3 -m venv /tmp/relcheck && /tmp/relcheck/bin/pip install \
     dist/cqa_analyzer-X.Y.Z-py3-none-any.whl
   /tmp/relcheck/bin/code-quality-analyzer <some-project> --offline
   rm -rf /tmp/relcheck
   ```

6. **Upload to TestPyPI first** and verify an install from it:

   ```bash
   .venv/bin/python -m twine upload --repository testpypi dist/*
   pip install --index-url https://test.pypi.org/simple/ \
     --no-deps cqa-analyzer
   ```

7. **Upload to PyPI:**

   ```bash
   .venv/bin/python -m twine upload dist/*
   ```

8. **Verify.** `pip install cqa-analyzer` in a fresh venv, run one scan,
   and confirm the version. Then update the README pre-commit `rev:` pin
   if this release should become the documented hook version.

## Post-release

- Create a GitHub release from the tag, pasting the CHANGELOG entry.
- Bump `__version__` only when the next change lands (versions are not
  pre-bumped).

## Known constraints

- The first upload must be done by a human with the PyPI token; there is
  no CI publishing pipeline yet. When one is added, use PyPI Trusted
  Publishing (OIDC) from GitHub Actions instead of a long-lived token.
- Artifacts are not GPG-signed; PyPI attestation via Trusted Publishing
  is the planned integrity path.
