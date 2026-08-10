from pathlib import Path
from uuid import UUID

import pytest
import yaml

SIGMA_DIR = Path(__file__).resolve().parent.parent / "sigma_rules"
SIGMA_FILES = sorted(SIGMA_DIR.glob("*.yml"))

# Core Sigma schema fields every rule in this repo is expected to carry.
REQUIRED_FIELDS = (
    "title",
    "id",
    "status",
    "description",
    "logsource",
    "detection",
    "level",
    "tags",
)

# Severity levels defined by the Sigma specification.
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}


def _load(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def test_sigma_directory_has_rules():
    assert SIGMA_FILES, f"no Sigma rule files found in {SIGMA_DIR}"


@pytest.mark.parametrize("path", SIGMA_FILES, ids=[p.name for p in SIGMA_FILES])
class TestSigmaRuleWellFormed:
    def test_parses_as_yaml_mapping(self, path):
        rule = _load(path)
        assert isinstance(rule, dict), f"{path.name} does not parse as a YAML mapping"

    def test_has_required_fields(self, path):
        rule = _load(path)
        for field in REQUIRED_FIELDS:
            assert field in rule and rule[field], f"{path.name} missing required field '{field}'"

    def test_id_is_valid_uuid(self, path):
        rule = _load(path)
        # Raises ValueError (failing the test) if the id is not a valid UUID.
        UUID(str(rule["id"]))

    def test_level_is_valid(self, path):
        rule = _load(path)
        assert rule["level"] in VALID_LEVELS, f"{path.name} has invalid level '{rule['level']}'"

    def test_detection_has_condition(self, path):
        rule = _load(path)
        detection = rule["detection"]
        assert isinstance(detection, dict), f"{path.name} detection block is not a mapping"
        assert detection.get("condition"), f"{path.name} detection block has no condition"

    def test_tags_include_mitre_attack(self, path):
        rule = _load(path)
        tags = rule["tags"]
        assert isinstance(tags, list) and tags, f"{path.name} tags must be a non-empty list"
        assert any(str(t).startswith("attack.") for t in tags), (
            f"{path.name} has no MITRE ATT&CK (attack.*) tag"
        )
