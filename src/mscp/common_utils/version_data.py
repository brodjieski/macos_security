# mscp/common_utils/version_data.py

# Standard python modules
from typing import Any

# Local python modules
from .logger_instance import logger

# Additional python modules


def get_version_data(
    os_name: str, os_version: float, mscp_data: dict[str, Any]
) -> dict[str, Any]:
    """
    Retrieve version data for a given operating system name and version.

    Args:
        os_name (str): The name of the operating system.
        os_version (int): The version of the operating system.

    Returns:
        dict[str, Any]: A dictionary containing the version data for the specified OS name and version.
                        If no matching version data is found, an empty dictionary is returned.

    Raises:
        FileNotFoundError: If the version file is not found.
        Exception: If there is an error parsing the version file.
    """

    # version_file: Path = Path(config["includes_dir"], "version.yaml")
    try:
        platforms: dict = mscp_data.get("versions", {}).get("platforms", {})
        valid_types = sorted(platforms.keys())

        if os_name.lower() not in platforms:
            raise ValueError(
                f"Unknown os_type {os_name!r}. Valid options: {valid_types}"
            )

        valid_versions = [e.get("os_version") for e in platforms[os_name.lower()]]
        match = next(
            (e for e in platforms[os_name.lower()] if e.get("os_version") == os_version),
            None,
        )

        if match is None:
            raise ValueError(
                f"Unknown os_version {os_version!r} for {os_name!r}. "
                f"Valid versions: {valid_versions}"
            )

        return match

    except ValueError:
        raise
    except Exception as e:
        logger.error("Error parsing mscp_data file: {}", e)
        return {}
