from pathlib import Path

import pytest

from config.schema import ScanConfig, load_config


def test_load_config_valid(tmp_path: Path):
    config_file = tmp_path / "config.yml"
    config_file.write_text(
        """
scan:
  static_reachability: true
  tools:
    - trivy
    - tainter
risk:
  exposure: public
  data_sensitivity: high
policy:
  block_if:
    - severity: CRITICAL
      verdict: CONFIRMED
"""
    )

    config = load_config(str(config_file))
    assert isinstance(config, ScanConfig)
    assert config.scan.static_reachability is True
    assert config.scan.tools == ["trivy", "tainter"]
    assert config.risk.exposure == "public"
    assert config.policy.block_if[0].severity == "CRITICAL"


def test_load_config_missing_file(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        load_config(str(tmp_path / "absent.yml"))


def test_load_config_invalid(tmp_path: Path):
    config_file = tmp_path / "config.yml"
    config_file.write_text("{}")
    with pytest.raises(ValueError):
        load_config(str(config_file))
