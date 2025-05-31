"""Base analyzer class and analyzer registry functionality."""

import abc
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Type

from insect.finding import Finding


class BaseAnalyzer(abc.ABC):
    """Base class for all analyzers in Insect.

    All analyzer implementations should inherit from this class.
    """

    name: str = "base"  # Should be overridden in subclasses
    description: str = "Base analyzer"  # Should be overridden in subclasses
    supported_extensions: Set[str] = set()  # Should be overridden in subclasses

    def __init__(self, config: Dict[str, Any]) -> None:
        """Initialize the analyzer with the provided configuration.

        Args:
            config: The configuration dictionary for the analyzer.
        """
        self.config = config
        self.enabled = config.get("analyzers", {}).get(self.name, True)

    @abc.abstractmethod
    def analyze_file(self, file_path: Path) -> List[Finding]:
        """Analyze a file and return a list of findings.

        Args:
            file_path: Path to the file to analyze.

        Returns:
            List of findings identified in the file.
        """
        pass

    def can_analyze_file(self, file_path: Path) -> bool:
        """Check if this analyzer can analyze the specified file.

        Args:
            file_path: Path to the file to check.

        Returns:
            True if this analyzer can analyze the file, False otherwise.
        """
        if not self.enabled:
            return False

        if not self.supported_extensions:
            return False

        return (
            file_path.suffix.lower() in self.supported_extensions
            or "*" in self.supported_extensions
        )

    def __repr__(self) -> str:
        """Return a string representation of the analyzer."""
        return f"{self.__class__.__name__}(name={self.name})"


# Registry of analyzer classes
_analyzer_classes: Dict[str, Type[BaseAnalyzer]] = {}


def register_analyzer(analyzer_class: Type[BaseAnalyzer]) -> Type[BaseAnalyzer]:
    """Register an analyzer class for use in the system.

    This is typically used as a decorator on analyzer classes.

    Args:
        analyzer_class: The analyzer class to register.

    Returns:
        The analyzer class (unchanged).

    Example:
        @register_analyzer
        class MyAnalyzer(BaseAnalyzer):
            name = "my_analyzer"
            ...
    """
    _analyzer_classes[analyzer_class.name] = analyzer_class
    return analyzer_class


def get_analyzer_class(name: str) -> Optional[Type[BaseAnalyzer]]:
    """Get an analyzer class by name.

    Args:
        name: The name of the analyzer class to get.

    Returns:
        The analyzer class if found, None otherwise.
    """
    return _analyzer_classes.get(name)


def get_all_analyzer_classes() -> Dict[str, Type[BaseAnalyzer]]:
    """Get all registered analyzer classes.

    Returns:
        Dictionary mapping analyzer names to analyzer classes.
    """
    return _analyzer_classes.copy()


def create_analyzer_instance(
    name: str, config: Dict[str, Any]
) -> Optional[BaseAnalyzer]:
    """Create an instance of an analyzer by name.

    Args:
        name: The name of the analyzer to create.
        config: Configuration dictionary to pass to the analyzer.

    Returns:
        An analyzer instance if found, None otherwise.
    """
    analyzer_class = get_analyzer_class(name)
    if analyzer_class:
        return analyzer_class(config)
    return None


# Import analyzers to register them - these imports are needed for side effects
from . import binary_analyzer  # noqa: F401, E402
from . import container_analyzer  # noqa: F401, E402
from . import javascript_static_analyzer  # noqa: F401, E402
from . import metadata_analyzer  # noqa: F401, E402
from . import python_static_analyzer  # noqa: F401, E402
from . import secret_analyzer  # noqa: F401, E402
from . import static_analyzer  # noqa: F401, E402
from . import vulnerability_analyzer  # noqa: F401, E402
from .config import config_analyzer  # noqa: F401, E402
from .shell import analyzer  # noqa: F401, E402
