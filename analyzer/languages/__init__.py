"""Built-in language adapters."""

from .go import GoLanguageAdapter, GoRulePack, register_go_plugins
from .python import (
    PythonComplexityProvider,
    PythonArchitectureSignalProvider,
    PythonLanguageAdapter,
    PythonPackageProvider,
    PythonRulePack,
    register_python_plugins,
)

__all__ = [
    "GoLanguageAdapter",
    "GoRulePack",
    "PythonArchitectureSignalProvider",
    "PythonComplexityProvider",
    "PythonLanguageAdapter",
    "PythonPackageProvider",
    "PythonRulePack",
    "register_go_plugins",
    "register_python_plugins",
]
