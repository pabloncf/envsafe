"""Abstract base class for all envsafe scanners."""

from abc import ABC, abstractmethod
from pathlib import Path

from envsafe.models import Finding


class BaseScanner(ABC):
    """Base class that all scanners must implement."""

    @abstractmethod
    def scan(self, path: Path) -> list[Finding]:
        """Scan the given path and return any findings.

        Args:
            path: Root directory to scan.

        Returns:
            List of findings discovered during the scan.
        """
