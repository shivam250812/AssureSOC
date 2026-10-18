"""AssureSOC — AI SOC copilot: raw security telemetry -> prioritised incidents -> response + compliance."""

from .pipeline import Workspace, analyse

__version__ = "0.1.0"

__all__ = [
    "Workspace",
    "analyse",
    "__version__",
]
