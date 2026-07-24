import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_openapi_describes_minimum_organa_verifier_contract():
    spec = json.loads((ROOT / "openapi.json").read_text(encoding="utf-8"))

    assert spec["openapi"].startswith("3.1.")
    assert spec["info"]["title"] == "Organa Proof Verifier API"
    assert set(spec["paths"]) >= {
        "/health",
        "/v1/cell/{coordinate}",
        "/v1/verify/package",
        "/v1/verify/controller-claim",
    }
    assert "get" in spec["paths"]["/health"]
    assert "get" in spec["paths"]["/v1/cell/{coordinate}"]
    assert "post" in spec["paths"]["/v1/verify/package"]
    assert "post" in spec["paths"]["/v1/verify/controller-claim"]


def test_openapi_contract_does_not_claim_business_truth_or_private_access():
    raw = (ROOT / "openapi.json").read_text(encoding="utf-8").lower()

    assert "cryptographic and structural verification" in raw
    assert "does not prove business truth" in raw
    assert "private strategy" not in raw
    assert "api key" not in raw
