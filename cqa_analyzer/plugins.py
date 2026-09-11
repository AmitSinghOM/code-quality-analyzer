"""Built-in plugin assembly."""

from .deep import register_deep_plugins
from .languages import (
    register_c_plugins,
    register_csharp_plugins,
    register_go_plugins,
    register_java_plugins,
    register_kotlin_plugins,
    register_python_plugins,
    register_rust_plugins,
    register_typescript_plugins,
)
from .registry import PluginRegistry
from .reporters import register_standard_reporters


def create_default_registry() -> PluginRegistry:
    """Create an isolated registry containing all built-in plugins."""
    registry = register_python_plugins(PluginRegistry())
    registry = register_go_plugins(registry)
    registry = register_typescript_plugins(registry)
    registry = register_java_plugins(registry)
    registry = register_kotlin_plugins(registry)
    registry = register_csharp_plugins(registry)
    registry = register_c_plugins(registry)
    registry = register_rust_plugins(registry)
    registry = register_deep_plugins(registry)
    return register_standard_reporters(registry)
