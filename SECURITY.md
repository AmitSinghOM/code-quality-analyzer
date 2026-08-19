# Security policy

## Supported versions

Security fixes are applied to the latest released minor version. Users should upgrade to the newest available release before reporting an issue that may already be resolved.

## Reporting a vulnerability

Use GitHub private vulnerability reporting for the repository when available. Do not open a public issue containing an exploit, secret, private source code, or sensitive path information.

Include only the minimum information needed to reproduce the problem:

- Analyzer version and Python version
- Operating system
- A minimal synthetic reproduction
- Expected and observed behavior
- Security impact

Do not attach proprietary repositories. Replace project names, paths, identifiers, credentials, and source with synthetic placeholders.

## Scope

Security-sensitive areas include:

- Filesystem traversal and symlink handling
- Non-regular or oversized input handling
- Report and baseline privacy
- Parser resource exhaustion
- Package metadata parsing
- Optional future project-code execution
- Dependency and distribution integrity

Default analysis is passive and must not import, build, or execute the analyzed project. Any future executable check must be explicit, documented, bounded, and disabled by default.

## Response expectations

Maintainers should acknowledge a complete report, reproduce it with synthetic data, assess affected versions, and publish a fix and release note before public technical details are shared.
