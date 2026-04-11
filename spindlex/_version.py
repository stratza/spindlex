# spindlex/_version.py

__version__ = "0.4.2"
__version_info__ = (0, 4, 2)


def get_version() -> str:
    """Return the current version as a string."""
    return __version__


def get_version_info() -> tuple[int, int, int]:
    """Return the current version as a tuple of integers."""
    return __version_info__
