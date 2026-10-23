"""Shared fixtures for the offline TorPool test suite."""

from pathlib import Path

import pytest

from torpool.config import TorPoolConfig


@pytest.fixture
def config(tmp_path: Path) -> TorPoolConfig:
    """A minimal config pointed at a temporary quarantine directory."""
    cfg = TorPoolConfig(
        circuits=2,
        output_dir=tmp_path / "quarantine",
        temp_dir=tmp_path / "quarantine" / "tmp",
        config_path=tmp_path / "config.toml",
        graph=False,
    )
    cfg.validate()
    return cfg


@pytest.fixture(autouse=True)
def _no_proxy_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure proxy variables never influence tests."""
    for var in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    ):
        monkeypatch.delenv(var, raising=False)


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Gate integration tests behind the TORPOOL_INTEGRATION=1 environment variable."""
    import os

    if os.environ.get("TORPOOL_INTEGRATION") != "1":
        skip_integration = pytest.mark.skip(
            reason="Integration tests disabled by default. Set TORPOOL_INTEGRATION=1 to run."
        )
        for item in items:
            if "integration" in item.keywords:
                item.add_marker(skip_integration)
