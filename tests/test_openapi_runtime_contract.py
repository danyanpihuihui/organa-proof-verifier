import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_openapi_errors_match_structured_runtime_shape():
    spec = json.loads((ROOT / "openapi.json").read_text(encoding="utf-8"))
    error = spec["components"]["schemas"]["VerificationError"]
    response = spec["components"]["schemas"]["VerificationResponse"]

    assert error["required"] == ["code", "message"]
    assert response["properties"]["errors"]["items"] == {"$ref": "#/components/schemas/VerificationError"}


def test_openapi_package_contract_accepts_structured_files_and_disallows_remote_paths():
    spec = json.loads((ROOT / "openapi.json").read_text(encoding="utf-8"))
    schema = spec["paths"]["/v1/verify/package"]["post"]["requestBody"]["content"]["application/json"]["schema"]

    assert "files" in schema["properties"]
    assert "package_path" not in schema["properties"]
    assert "package_url" not in schema["properties"]
    assert schema["required"] == ["files"]


def test_openapi_does_not_advertise_unimplemented_resolver_query_override():
    spec = json.loads((ROOT / "openapi.json").read_text(encoding="utf-8"))
    parameters = spec["paths"]["/v1/cell/{coordinate}"]["get"]["parameters"]

    assert [item["name"] for item in parameters] == ["coordinate"]
