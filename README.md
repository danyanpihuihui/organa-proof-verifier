# Organa Proof Verifier

A public, read-only verifier for Organa Cell manifests, resource hashes, registry links and BIP-322 controller claims.

The verifier checks cryptographic and structural integrity. It does not prove the truth of business content, economic performance or private execution.

## Endpoints

- `GET /health`
- `GET /openapi.json`
- `GET /v1/cell/7187.bitmap`
- `POST /v1/verify/package`
- `POST /v1/verify/controller-claim`

## Local run

```bash
python3 -m pip install -r requirements-verifier.txt
npm ci --omit=dev
PYTHONPATH=src python3 -m bitmap_memory_portal.verifier_http --host 127.0.0.1 --port 8787
curl http://127.0.0.1:8787/health
curl http://127.0.0.1:8787/v1/cell/7187.bitmap
```

## Test

```bash
PYTHONPATH=src python3 -m pytest tests -q
```

## Container

```bash
docker build -f Dockerfile.verifier -t organa-proof-verifier .
docker run --rm -p 8787:8787 organa-proof-verifier
```

## Security boundary

- No wallet secrets or API keys are required.
- Remote fetching is HTTPS-only and blocks private, loopback, link-local and reserved addresses.
- Downloads and request bodies are bounded.
- HTTP clients cannot request arbitrary local filesystem paths.
- The service is read-only and cannot mutate an Organa Cell's canonical state.
