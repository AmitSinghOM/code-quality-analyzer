"""PY-SEC-001..005: Python security rules (AST based).

Same boundary as the regex-language family in ``languages/_security.py``:
each rule fires on a call shape or literal the AST shows directly, never on
data flow. A literal argument is ``ast.Constant``; anything else — a name,
an f-string, ``%``/``.format``/``+`` — is dynamic.
"""

from __future__ import annotations

import ast
import contextvars
import re
from collections.abc import Iterable

from .findings import Finding, Location
from .languages._parity import is_test_path
from .languages._security import is_secret_name

_SAFE_YAML_LOADERS = frozenset({"SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader"})
_UNSAFE_LOADS = {
    ("pickle", "load"),
    ("pickle", "loads"),
    ("cPickle", "load"),
    ("cPickle", "loads"),
    ("_pickle", "load"),
    ("_pickle", "loads"),
    ("marshal", "load"),
    ("marshal", "loads"),
    ("shelve", "open"),
    ("dill", "load"),
    ("dill", "loads"),
    ("yaml", "unsafe_load"),
    ("yaml", "unsafe_load_all"),
}
_SUBPROCESS_CALLS = frozenset(
    {"run", "call", "check_call", "check_output", "Popen", "getoutput", "getstatusoutput"}
)
_RANDOM_FUNCTIONS = frozenset(
    {
        "random",
        "randint",
        "choice",
        "choices",
        "randrange",
        "getrandbits",
        "randbytes",
        "uniform",
        "sample",
        "shuffle",
        "triangular",
    }
)
_TLS_ATTRIBUTES = frozenset({"_create_unverified_context", "CERT_NONE"})
_CERT_NONE_CONTEXT = re.compile(r"(?i)cert_?reqs|verify_?mode")


_MODULE_CONSTANTS: contextvars.ContextVar[frozenset[str]] = contextvars.ContextVar(
    "cqa_module_constants", default=frozenset()
)


def module_constants(tree: ast.AST) -> frozenset[str]:
    """Names bound exactly once, at module level, to a string literal.

    ``CMD = "ls -la"`` at the top of a file makes ``subprocess.run(CMD,
    shell=True)`` a literal command, not a runtime one. A name assigned
    anywhere else in the module (a second assignment, a loop target, an
    augmented assignment, a ``global`` rebinding) is not a constant.
    """
    stores: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            stores[node.id] = stores.get(node.id, 0) + 1
    constants: set[str] = set()
    for statement in getattr(tree, "body", []):
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
            target, value = statement.targets[0], statement.value
        elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
            target, value = statement.target, statement.value
        else:
            continue
        if (
            isinstance(target, ast.Name)
            and isinstance(value, ast.Constant)
            and isinstance(value.value, str)
            and stores.get(target.id) == 1
        ):
            constants.add(target.id)
    return frozenset(constants)


def _shlex_safe(node: ast.expr) -> bool:
    """``shlex.join(...)``, ``shlex.quote(...)``, or an f-string whose every
    interpolation is ``shlex.quote(...)``: quoted by construction."""
    if isinstance(node, ast.Call):
        return _attr(node.func) in {("shlex", "join"), ("shlex", "quote")}
    if isinstance(node, ast.JoinedStr):
        holes = [part for part in node.values if isinstance(part, ast.FormattedValue)]
        return bool(holes) and all(_shlex_safe(hole.value) for hole in holes)
    return False


def _is_dynamic(node: ast.expr | None) -> bool:
    if node is None or isinstance(node, ast.Constant):
        return False
    if isinstance(node, ast.Name) and node.id in _MODULE_CONSTANTS.get():
        return False
    return not _shlex_safe(node)


def _attr(node: ast.expr) -> tuple[str, str] | None:
    """``module.attr`` as ``("module", "attr")`` when ``module`` is a bare name."""
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return node.value.id, node.attr
    return None


def _location(node: ast.AST, path: str, identity_path: str) -> Location:
    return Location(
        path=path,
        line=node.lineno,
        column=node.col_offset + 1,
        end_line=getattr(node, "end_lineno", None),
        end_column=(
            node.end_col_offset + 1 if getattr(node, "end_col_offset", None) is not None else None
        ),
        identity_path=identity_path,
    )


class _SecurityRule:
    """Shared plumbing: one finding per line, optional test-path downgrade."""

    rule_id = ""
    category = "security"
    severity = "warning"
    confidence = "high"
    remediation = ""
    downgrade_in_tests = False

    def evaluate(
        self,
        tree: ast.AST,
        path: str,
        identity_path: str | None = None,
    ) -> Iterable[Finding]:
        identity_path = identity_path or path
        in_tests = self.downgrade_in_tests and is_test_path(identity_path)
        seen: set[int] = set()
        reset_handle = _MODULE_CONSTANTS.set(module_constants(tree))
        try:
            yield from self._walk(tree, path, identity_path, in_tests, seen)
        finally:
            _MODULE_CONSTANTS.reset(reset_handle)

    def _walk(
        self,
        tree: ast.AST,
        path: str,
        identity_path: str,
        in_tests: bool,
        seen: set[int],
    ) -> Iterable[Finding]:
        for node in ast.walk(tree):
            hit = self.classify(node)
            if hit is None or node.lineno in seen:
                continue
            seen.add(node.lineno)
            yield Finding(
                rule_id=self.rule_id,
                category=self.category,
                severity="note" if in_tests else self.severity,
                confidence=self.confidence,
                message=hit,
                location=_location(node, path, identity_path),
                remediation=self.remediation,
            )

    def classify(self, node: ast.AST) -> str | None:  # pragma: no cover - abstract
        raise NotImplementedError


class UnsafeDeserializationRule(_SecurityRule):
    """PY-SEC-001: pickle/marshal/shelve/dill loads, ``yaml.load`` without a safe Loader."""

    rule_id = "PY-SEC-001"
    remediation = (
        "Deserialize untrusted data with a format that cannot execute code "
        "(json, yaml.safe_load) or restrict the loader."
    )
    downgrade_in_tests = True

    def classify(self, node: ast.AST) -> str | None:
        if not isinstance(node, ast.Call):
            return None
        target = _attr(node.func)
        if target is None:
            return None
        if target in _UNSAFE_LOADS:
            return f"{target[0]}.{target[1]} deserializes arbitrary objects (CWE-502)."
        if (
            target[0] == "yaml"
            and target[1] in {"load", "load_all"}
            and not _yaml_loader_is_safe(node)
        ):
            return (
                f"yaml.{target[1]} without a safe Loader can instantiate arbitrary "
                "Python objects (CWE-502)."
            )
        return None


def _yaml_loader_is_safe(node: ast.Call) -> bool:
    loader = next((k.value for k in node.keywords if k.arg == "Loader"), None)
    if loader is None and len(node.args) >= 2:
        loader = node.args[1]
    name = getattr(loader, "attr", None) or getattr(loader, "id", None)
    return name in _SAFE_YAML_LOADERS


class ShellCommandRule(_SecurityRule):
    """PY-SEC-002: ``subprocess.*(cmd, shell=True)`` / ``os.system(cmd)`` with dynamic ``cmd``."""

    rule_id = "PY-SEC-002"
    confidence = "medium"
    remediation = (
        "Pass the command as an argument list without shell=True; quote with "
        "shlex.quote if a shell is unavoidable."
    )

    def classify(self, node: ast.AST) -> str | None:
        if not isinstance(node, ast.Call):
            return None
        target = _attr(node.func)
        if target is None:
            return None
        module, name = target
        if module == "os" and name in {"system", "popen"}:
            return _os_shell(node, name)
        if name in _SUBPROCESS_CALLS:
            return _subprocess_shell(node, module, name)
        return None


def _os_shell(node: ast.Call, name: str) -> str | None:
    if node.args and _is_dynamic(node.args[0]):
        return f"os.{name} runs a shell command assembled at runtime (CWE-78)."
    return None


def _subprocess_shell(node: ast.Call, module: str, name: str) -> str | None:
    shell = _keyword(node, "shell")
    if not (isinstance(shell, ast.Constant) and shell.value is True):
        return None
    command = node.args[0] if node.args else _keyword(node, "args")
    if _is_dynamic(command):
        return f"{module}.{name}(shell=True) runs a command assembled at runtime (CWE-78)."
    return None


def _keyword(node: ast.Call, name: str) -> ast.expr | None:
    return next((k.value for k in node.keywords if k.arg == name), None)


class DynamicCodeExecutionRule(_SecurityRule):
    """PY-SEC-003: ``eval(x)`` / ``exec(x)`` with a non-literal ``x``."""

    rule_id = "PY-SEC-003"
    remediation = (
        "Use ast.literal_eval for data, a dispatch table for behaviour, or "
        "importlib for module names; never evaluate runtime strings."
    )

    def classify(self, node: ast.AST) -> str | None:
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            return None
        if node.func.id in {"eval", "exec"} and node.args and _is_dynamic(node.args[0]):
            return f"{node.func.id}() evaluates a string built at runtime (CWE-95)."
        return None


class TlsVerificationDisabledRule(_SecurityRule):
    """PY-SEC-004: ``verify=False``, unverified SSL context, ``CERT_NONE``, no hostname check."""

    rule_id = "PY-SEC-004"
    remediation = (
        "Keep certificate verification on; pin a CA bundle (verify=<path>) "
        "or use a trust store for private CAs."
    )
    downgrade_in_tests = True

    def classify(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Call):
            return _tls_call(node)
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            return _tls_assignment(getattr(node.targets[0], "attr", None), node.value)
        return None


def _is_false(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _tls_call(node: ast.Call) -> str | None:
    for keyword in node.keywords:
        if keyword.arg == "verify" and _is_false(keyword.value):
            return "TLS certificate verification is disabled with verify=False (CWE-295)."
        if keyword.arg in {"cert_reqs", "verify_mode"} and _attr(keyword.value) == (
            "ssl",
            "CERT_NONE",
        ):
            return "TLS peer certificates are not required (ssl.CERT_NONE) (CWE-295)."
    if _attr(node.func) == ("ssl", "_create_unverified_context"):
        return "ssl._create_unverified_context() disables certificate verification (CWE-295)."
    return None


def _tls_assignment(attribute: str | None, value: ast.expr) -> str | None:
    if attribute == "check_hostname" and _is_false(value):
        return "Hostname verification is disabled (check_hostname = False) (CWE-295)."
    if attribute == "verify_mode" and _attr(value) == ("ssl", "CERT_NONE"):
        return "TLS peer certificates are not required (ssl.CERT_NONE) (CWE-295)."
    return None


class InsecureRandomForSecretRule(_SecurityRule):
    """PY-SEC-005: ``random.*`` output bound to a secret-shaped name."""

    rule_id = "PY-SEC-005"
    confidence = "medium"
    remediation = (
        "Generate tokens, passwords and nonces with the secrets module "
        "(secrets.token_urlsafe, secrets.choice)."
    )

    def classify(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Call):
            return _random_keyword(node)
        binding = _binding(node)
        if binding is None:
            return None
        names, value = binding
        secret = next((n for n in names if n and is_secret_name(n)), None)
        if secret is None or not _uses_random(value):
            return None
        return f"'{secret}' is produced by the non-cryptographic random module (CWE-330)."


def _binding(node: ast.AST) -> tuple[list[str], ast.expr] | None:
    """``(target names, value)`` for a plain or annotated assignment with a value."""
    if isinstance(node, ast.Assign):
        return [_target_name(t) for t in node.targets], node.value
    if isinstance(node, ast.AnnAssign) and node.value is not None:
        return [_target_name(node.target)], node.value
    return None


def _random_keyword(node: ast.Call) -> str | None:
    for keyword in node.keywords:
        if keyword.arg and is_secret_name(keyword.arg) and _uses_random(keyword.value):
            return (
                f"Argument '{keyword.arg}' is produced by the non-cryptographic "
                "random module (CWE-330)."
            )
    return None


def _target_name(target: ast.expr) -> str:
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    return ""


def _uses_random(value: ast.expr) -> bool:
    """True when the expression calls ``random.<fn>`` and never ``SystemRandom``."""
    found = False
    for sub in ast.walk(value):
        if isinstance(sub, ast.Name) and sub.id == "SystemRandom":
            return False
        if isinstance(sub, ast.Attribute) and sub.attr == "SystemRandom":
            return False
        if isinstance(sub, ast.Call):
            target = _attr(sub.func)
            if target is not None and target[0] == "random" and target[1] in _RANDOM_FUNCTIONS:
                found = True
    return found


SECURITY_RULES = (
    UnsafeDeserializationRule,
    ShellCommandRule,
    DynamicCodeExecutionRule,
    TlsVerificationDisabledRule,
    InsecureRandomForSecretRule,
)
