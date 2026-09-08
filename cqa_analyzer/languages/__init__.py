"""Built-in language adapters."""

from .go import (
    GoImport,
    GoLanguageAdapter,
    GoPackageGraph,
    GoPackageGraphProvider,
    GoRulePack,
    register_go_plugins,
)
from .python import (
    PythonComplexityProvider,
    PythonArchitectureSignalProvider,
    PythonLanguageAdapter,
    PythonPackageProvider,
    PythonRulePack,
    register_python_plugins,
)
from .typescript import (
    TsPackageProvider,
    TypeScriptLanguageAdapter,
    TypeScriptRulePack,
    register_typescript_plugins,
)

__all__ = [
    "GoImport",
    "GoLanguageAdapter",
    "GoPackageGraph",
    "GoPackageGraphProvider",
    "GoRulePack",
    "PythonArchitectureSignalProvider",
    "PythonComplexityProvider",
    "PythonLanguageAdapter",
    "PythonPackageProvider",
    "PythonRulePack",
    "TsPackageProvider",
    "TypeScriptLanguageAdapter",
    "TypeScriptRulePack",
    "register_go_plugins",
    "register_python_plugins",
    "register_typescript_plugins",
]
