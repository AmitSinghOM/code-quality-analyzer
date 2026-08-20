"""Deterministic plugin registry for language-neutral analyzer extensions."""

from __future__ import annotations

from pathlib import Path

from .protocols import (
    DEFAULT_CAPABILITY_VERSION,
    PLUGIN_API_VERSION,
    LanguageAdapter,
    MetricProvider,
    ProjectProvider,
    Reporter,
    RulePack,
)


class PluginRegistrationError(ValueError):
    """Raised when a plugin conflicts with an existing registration."""


class CapabilityNegotiationError(LookupError):
    """Raised when a required plugin capability cannot be satisfied."""


class PluginRegistry:
    """Register and resolve adapters, rule packs, metrics, and reporters."""

    def __init__(self) -> None:
        self._languages: dict[str, LanguageAdapter] = {}
        self._extensions: dict[str, str] = {}
        self._rule_packs: dict[tuple[str, str], RulePack] = {}
        self._metrics: dict[tuple[str, str], MetricProvider] = {}
        self._project_providers: dict[
            tuple[str, str], ProjectProvider
        ] = {}
        self._reporters: dict[str, Reporter] = {}

    def register_language(self, adapter: LanguageAdapter) -> None:
        _validate_plugin_api(adapter)
        language_id = adapter.language_id
        if language_id in self._languages:
            raise PluginRegistrationError(
                f"Language adapter already registered: {language_id}"
            )
        normalized_extensions = tuple(
            _normalize_extension(extension)
            for extension in adapter.extensions
        )
        for extension in normalized_extensions:
            owner = self._extensions.get(extension)
            if owner is not None:
                raise PluginRegistrationError(
                    f"Extension {extension} already belongs to {owner}"
                )
        self._languages[language_id] = adapter
        for extension in normalized_extensions:
            self._extensions[extension] = language_id

    def language(self, language_id: str) -> LanguageAdapter:
        try:
            return self._languages[language_id]
        except KeyError as error:
            raise LookupError(
                f"No language adapter registered for {language_id}"
            ) from error

    def adapter_for_path(self, path: str | Path) -> LanguageAdapter | None:
        suffix = Path(path).suffix.lower()
        language_id = self._extensions.get(suffix)
        return self._languages.get(language_id) if language_id else None

    def register_rule_pack(self, rule_pack: RulePack) -> None:
        _validate_plugin_api(rule_pack)
        if rule_pack.language_id not in self._languages:
            raise PluginRegistrationError(
                "Register a language adapter before its rule packs"
            )
        key = (rule_pack.language_id, rule_pack.rule_pack_id)
        if key in self._rule_packs:
            raise PluginRegistrationError(
                f"Rule pack already registered: {rule_pack.rule_pack_id}"
            )
        self._rule_packs[key] = rule_pack

    def rule_packs_for(self, language_id: str) -> tuple[RulePack, ...]:
        return tuple(
            plugin
            for (owner, _), plugin in sorted(self._rule_packs.items())
            if owner == language_id
        )

    def register_metric_provider(self, provider: MetricProvider) -> None:
        _validate_plugin_api(provider)
        _validate_version(
            getattr(provider, "capability_version", DEFAULT_CAPABILITY_VERSION),
            "capability version",
        )
        if provider.language_id not in self._languages:
            raise PluginRegistrationError(
                "Register a language adapter before its metric providers"
            )
        key = (provider.language_id, provider.provider_id)
        if key in self._metrics:
            raise PluginRegistrationError(
                f"Metric provider already registered: {provider.provider_id}"
            )
        self._metrics[key] = provider

    def metric_providers_for(
        self,
        language_id: str,
    ) -> tuple[MetricProvider, ...]:
        return tuple(
            plugin
            for (owner, _), plugin in sorted(self._metrics.items())
            if owner == language_id
        )

    def register_project_provider(self, provider: ProjectProvider) -> None:
        _validate_plugin_api(provider)
        _validate_version(
            getattr(provider, "capability_version", DEFAULT_CAPABILITY_VERSION),
            "capability version",
        )
        if provider.language_id not in self._languages:
            raise PluginRegistrationError(
                "Register a language adapter before its project providers"
            )
        key = (provider.language_id, provider.capability)
        if key in self._project_providers:
            raise PluginRegistrationError(
                "Project provider already registered for "
                f"{provider.language_id}:{provider.capability}"
            )
        self._project_providers[key] = provider

    def project_provider(
        self,
        language_id: str,
        capability: str,
    ) -> ProjectProvider | None:
        return self._project_providers.get((language_id, capability))

    def negotiate_project_provider(
        self,
        language_id: str,
        capability: str,
        required_version: str = DEFAULT_CAPABILITY_VERSION,
        *,
        optional: bool = False,
    ) -> ProjectProvider | None:
        """Resolve a provider whose capability contract satisfies a version."""
        provider = self.project_provider(language_id, capability)
        if provider is None:
            if optional:
                return None
            raise CapabilityNegotiationError(
                f"No provider registered for {language_id}:{capability}"
            )
        provided_version = getattr(
            provider,
            "capability_version",
            DEFAULT_CAPABILITY_VERSION,
        )
        if not _capability_satisfies(provided_version, required_version):
            if optional:
                return None
            raise CapabilityNegotiationError(
                f"{language_id}:{capability} provides {provided_version}; "
                f"required compatible version is {required_version}"
            )
        return provider

    def default_project_providers(self) -> tuple[ProjectProvider, ...]:
        return tuple(
            provider
            for _, provider in sorted(self._project_providers.items())
            if provider.enabled_by_default
        )

    def register_reporter(self, reporter: Reporter) -> None:
        _validate_plugin_api(reporter)
        _validate_version(
            getattr(reporter, "capability_version", DEFAULT_CAPABILITY_VERSION),
            "capability version",
        )
        if reporter.format_name in self._reporters:
            raise PluginRegistrationError(
                f"Reporter already registered: {reporter.format_name}"
            )
        self._reporters[reporter.format_name] = reporter

    def reporter(self, format_name: str) -> Reporter:
        try:
            return self._reporters[format_name]
        except KeyError as error:
            raise LookupError(
                f"No reporter registered for {format_name}"
            ) from error

    def negotiate_reporter(
        self,
        format_name: str,
        required_version: str = DEFAULT_CAPABILITY_VERSION,
    ) -> Reporter:
        """Resolve a reporter with a compatible report-rendering contract."""
        reporter = self.reporter(format_name)
        provided_version = getattr(
            reporter,
            "capability_version",
            DEFAULT_CAPABILITY_VERSION,
        )
        if not _capability_satisfies(provided_version, required_version):
            raise CapabilityNegotiationError(
                f"Reporter {format_name} provides {provided_version}; "
                f"required compatible version is {required_version}"
            )
        return reporter

    def source_extensions(self) -> tuple[str, ...]:
        """Return all registered source extensions in deterministic order."""
        return tuple(sorted(self._extensions))

    def capabilities(self) -> dict:
        """Return deterministic, non-sensitive plugin metadata."""
        return {
            "plugin_api_version": PLUGIN_API_VERSION,
            "languages": {
                language_id: adapter.adapter_version
                for language_id, adapter in sorted(self._languages.items())
            },
            "rule_packs": [
                {
                    "language_id": language_id,
                    "rule_pack_id": rule_pack_id,
                    "ruleset_version": plugin.ruleset_version,
                }
                for (language_id, rule_pack_id), plugin in sorted(
                    self._rule_packs.items()
                )
            ],
            "metric_providers": [
                {
                    "language_id": language_id,
                    "provider_id": provider_id,
                    "capability_version": getattr(
                        self._metrics[(language_id, provider_id)],
                        "capability_version",
                        DEFAULT_CAPABILITY_VERSION,
                    ),
                }
                for language_id, provider_id in sorted(self._metrics)
            ],
            "project_providers": [
                {
                    "language_id": language_id,
                    "capability": capability,
                    "provider_id": provider.provider_id,
                    "capability_version": getattr(
                        provider,
                        "capability_version",
                        DEFAULT_CAPABILITY_VERSION,
                    ),
                    "enabled_by_default": provider.enabled_by_default,
                }
                for (language_id, capability), provider in sorted(
                    self._project_providers.items()
                )
            ],
            "reporters": [
                {
                    "format_name": format_name,
                    "capability_version": getattr(
                        reporter,
                        "capability_version",
                        DEFAULT_CAPABILITY_VERSION,
                    ),
                }
                for format_name, reporter in sorted(self._reporters.items())
            ],
        }


def _validate_plugin_api(plugin: object) -> None:
    requested = getattr(plugin, "plugin_api_version", PLUGIN_API_VERSION)
    current = _validate_version(PLUGIN_API_VERSION, "core plugin API version")
    target = _validate_version(requested, "plugin API version")
    if target[0] != current[0] or target > current:
        raise PluginRegistrationError(
            f"Plugin requires API {requested}; core provides {PLUGIN_API_VERSION}"
        )


def _capability_satisfies(provided: str, required: str) -> bool:
    provided_version = _validate_version(provided, "provided capability version")
    required_version = _validate_version(required, "required capability version")
    return (
        provided_version[0] == required_version[0]
        and provided_version >= required_version
    )


def _validate_version(version: str, label: str) -> tuple[int, int, int]:
    parts = version.split(".")
    if len(parts) != 3 or any(not part.isdigit() for part in parts):
        raise PluginRegistrationError(
            f"Invalid {label} {version!r}; expected MAJOR.MINOR.PATCH"
        )
    return tuple(int(part) for part in parts)  # type: ignore[return-value]


def _normalize_extension(extension: str) -> str:
    normalized = extension.lower()
    if not normalized.startswith("."):
        normalized = f".{normalized}"
    return normalized
