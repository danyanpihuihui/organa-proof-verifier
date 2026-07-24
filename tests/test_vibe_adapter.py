import json
from pathlib import Path

import pytest

from bitmap_memory_portal.vibe_adapter import (
    build_vibe_validation_artifact,
    load_vibe_tool_policy,
    validate_vibe_tool_request,
)


def _policy_path() -> Path:
    return Path(__file__).parents[1] / ".external" / "vibe-trading" / "read_only_policy.json"


def test_vibe_policy_allows_validation_tools_and_denies_execution_surfaces():
    policy = load_vibe_tool_policy(_policy_path())

    assert validate_vibe_tool_request("get_market_data", policy) is True
    assert validate_vibe_tool_request("backtest", policy) is True
    assert validate_vibe_tool_request("factor_analysis", policy) is True

    with pytest.raises(PermissionError, match="trading_account"):
        validate_vibe_tool_request("trading_account", policy)
    with pytest.raises(PermissionError, match="write_file"):
        validate_vibe_tool_request("write_file", policy)
    with pytest.raises(PermissionError, match="run_swarm"):
        validate_vibe_tool_request("run_swarm", policy)
    with pytest.raises(PermissionError, match="unknown_future_tool"):
        validate_vibe_tool_request("unknown_future_tool", policy)


def test_build_vibe_validation_artifact_hashes_source_and_result(tmp_path):
    source_manifest = tmp_path / "source_manifest.json"
    result = tmp_path / "market_data_result.json"
    source_manifest.write_text(
        json.dumps({"sample": "冰轮环境 000811", "signal_date": "2026-04-28"}, ensure_ascii=False),
        encoding="utf-8",
    )
    result.write_text(
        json.dumps({"source": "tencent", "rows": [{"date": "2026-04-28", "close": 24.35}]}, ensure_ascii=False),
        encoding="utf-8",
    )

    artifact = build_vibe_validation_artifact(
        claim="Validate the historical post-signal price path without changing APICKUP rules.",
        sample_id="apickup-000811-2026-04-28",
        source_manifest_path=source_manifest,
        result_path=result,
        tool_name="get_market_data",
        tool_arguments={
            "codes": ["000811.SZ"],
            "start_date": "2026-04-28",
            "end_date": "2026-05-13",
            "source": "tencent",
            "interval": "1D",
        },
        warnings=["Validation output is not a buy/sell signal."],
    )

    assert artifact["artifact_type"] == "organa-finance-validation-cell-result"
    assert artifact["adapter_id"] == "vibe-trading"
    assert artifact["adapter_version"] == "0.1.11"
    assert artifact["mode"] == "read-only-shadow-validation"
    assert artifact["sample_id"] == "apickup-000811-2026-04-28"
    assert artifact["source_manifest"]["sha256"].startswith("sha256:")
    assert artifact["result"]["sha256"].startswith("sha256:")
    assert artifact["canonical_state_mutation"] is False
    assert artifact["trade_execution_allowed"] is False
    assert artifact["model_rule_changes_allowed"] is False
    assert artifact["warnings"] == ["Validation output is not a buy/sell signal."]
