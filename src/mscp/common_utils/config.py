# mscp/common_utils/config.py

# Standard python modules
from importlib.resources import files
from pathlib import Path

# Local python modules
from .file_handling import open_file
from .logger_instance import logger

# Locate the data directory bundled with the package.
# Falls back to __file__-relative path when running from the source tree
# without an editable install.
try:
    _pkg_data = Path(str(files("mscp").joinpath("data")))
    if not _pkg_data.is_dir():
        raise FileNotFoundError(_pkg_data)
except Exception:
    _pkg_data = Path(__file__).parent.parent / "data"

_cwd = Path.cwd()

CONFIG_PATH: Path = _pkg_data / "config.yaml"

try:
    logger.info("Attempting to open config file: {}", CONFIG_PATH)
    config = open_file(CONFIG_PATH)
    logger.success("Config file loaded successfully")
except Exception as e:
    logger.error("An error occurred while loading the config file: {}", e)
    raise

# Resolve top-level package-relative paths
for _key in ("includes_dir", "mscp_data", "shell_template_dir"):
    if _key in config:
        config[_key] = str(_pkg_data / config[_key])

# Resolve defaults (all package-relative)
for _key in config.get("defaults", {}):
    config["defaults"][_key] = str(_pkg_data / config["defaults"][_key])

# Resolve custom (CWD/custom/ relative; empty string means the custom root itself)
_custom_base = _cwd / "custom"
for _key, _val in list(config.get("custom", {}).items()):
    config["custom"][_key] = str(_custom_base if not _val else _custom_base / _val)

# Resolve output path (CWD-relative)
config["output_dir"] = str(_cwd / config.get("output_dir", "build/"))
