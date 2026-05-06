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

# Keys resolved against the bundled package data directory.
_pkg_dir_keys = frozenset({
    "baseline_dir", "documents_templates_dir", "images_dir",
    "locales_dir", "rules_dir", "sections_dir",
    "shell_template_dir", "templates_dir", "themes_dir",
})

for _key in ("includes_dir", "mscp_data", *_pkg_dir_keys):
    if _key in config:
        config[_key] = str(_pkg_data / config[_key])

# Resolve user-configurable paths against CWD when relative, expand ~ when absolute-ish.
for _key in ("output_dir", "custom_dir"):
    _val = Path(config.get(_key, "build/" if _key == "output_dir" else "~/.mscp")).expanduser()
    config[_key] = str(_val if _val.is_absolute() else _cwd / _val)

# Custom base: now guaranteed absolute.
_custom_base: Path = Path(config["custom_dir"])
_defaults_only = frozenset({"locales_dir", "shell_template_dir"})

config["custom"] = {
    "root_dir": str(_custom_base),
    "misc_dir": str(_custom_base / "misc"),
}
for _key in _pkg_dir_keys - _defaults_only:
    config["custom"][_key] = str(_custom_base / Path(config[_key]).relative_to(_pkg_data))

def ensure_custom_dirs() -> None:
    """Create the custom directory structure under custom_dir if it doesn't exist."""
    for path in config["custom"].values():
        Path(path).mkdir(parents=True, exist_ok=True)


def set_custom_dir(path: Path) -> None:
    """Re-resolve all custom config paths against a new base directory."""
    global _custom_base
    for key in config.get("custom", {}):
        rel = Path(config["custom"][key]).relative_to(_custom_base)
        config["custom"][key] = str(path / rel)
    _custom_base = path
    config["custom_dir"] = str(path)
