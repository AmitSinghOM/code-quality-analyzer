"""Built-in plugin assembly."""

from .languages import register_python_plugins
from .registry import PluginRegistry


def create_default_registry() -> PluginRegistry:
    """Create an isolated registry containing all built-in plugins."""
    return register_python_plugins(PluginRegistry())
