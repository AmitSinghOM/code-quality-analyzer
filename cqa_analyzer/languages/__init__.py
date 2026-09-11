"""Built-in language adapters."""

from .c_family import (
    CCMakePackageProvider,
    CLanguageAdapter,
    CRulePack,
    register_c_plugins,
)
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
from .kotlin import (
    KotlinLanguageAdapter,
    KotlinPackageProvider,
    KotlinRulePack,
    register_kotlin_plugins,
)
from .rust import (
    RustArchitectureSignalProvider,
    RustCargoPackageProvider,
    RustLanguageAdapter,
    RustRulePack,
    register_rust_plugins,
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
    "CCMakePackageProvider",
    "CLanguageAdapter",
    "CRulePack",
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
    "KotlinLanguageAdapter",
    "KotlinPackageProvider",
    "KotlinRulePack",
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
    "register_c_plugins",
    "register_java_plugins",
    "register_kotlin_plugins",
    "register_python_plugins",
    "register_rust_plugins",
    "RustArchitectureSignalProvider",
    "RustCargoPackageProvider",
    "RustLanguageAdapter",
    "RustRulePack",
    "register_typescript_plugins",
]
