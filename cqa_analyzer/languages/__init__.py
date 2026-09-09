"""Built-in language adapters."""

from .csharp import (
    CSharpLanguageAdapter,
    CSharpPackageProvider,
    CSharpRulePack,
    register_csharp_plugins,
)
from .go import (
    GoImport,
    GoLanguageAdapter,
    GoPackageGraph,
    GoPackageGraphProvider,
    GoRulePack,
    register_go_plugins,
)
from .java import (
    JavaLanguageAdapter,
    JavaPackageProvider,
    JavaRulePack,
    register_java_plugins,
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
    "CSharpLanguageAdapter",
    "CSharpPackageProvider",
    "CSharpRulePack",
    "GoImport",
    "GoLanguageAdapter",
    "GoPackageGraph",
    "GoPackageGraphProvider",
    "GoRulePack",
    "JavaLanguageAdapter",
    "JavaPackageProvider",
    "JavaRulePack",
    "PythonArchitectureSignalProvider",
    "PythonComplexityProvider",
    "PythonLanguageAdapter",
    "PythonPackageProvider",
    "PythonRulePack",
    "TsPackageProvider",
    "TypeScriptLanguageAdapter",
    "TypeScriptRulePack",
    "register_csharp_plugins",
    "register_go_plugins",
    "register_java_plugins",
    "register_python_plugins",
    "register_typescript_plugins",
]
