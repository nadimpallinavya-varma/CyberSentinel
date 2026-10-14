# CyberSentinel

CyberSentinel is a local-first Security Operations Center (SOC) platform for small teams that need explainable detection and incident response without a full SOC staff. It identifies suspicious authentication activity, preserves evidence, and supports analyst investigation while keeping all demonstrations inside authorized local/test assets.

## Problem and solution

Small businesses commonly lack centralized visibility into brute-force attempts, suspicious login bursts, and unauthorized access. CyberSentinel ingests authentication events and Wazuh-compatible alerts, applies transparent rules, stores incidents in PostgreSQL, and exposes operational metrics for Prometheus/Grafana.

## Technologies

- Frontend: HTML/JavaScript, Tailwind CDN, Lucide, same-origin Nginx `/api` proxy
- Backend: Python 3.12, FastAPI, Pydantic, SQLAlchemy, Alembic
- Data: PostgreSQL 16; SQLite is available for local tests
- Detection: explainable rule-based engine with deduplication and evidence preservation
- DevOps: GitHub Actions, Docker Compose, Minikube/Kubernetes
- Monitoring: Prometheus client metrics, Prometheus, Grafana
- Integration: lightweight authenticated Wazuh-compatible alert adapter; full Wazuh is intentionally not installed locally

## Architecture

```mermaid
flowchart LR
  Browser[Analyst browser] --> Nginx[Nginx frontend / same-origin API proxy]
  Nginx --> API[FastAPI backend]
  API --> DB[(PostgreSQL)]
  API --> Rules[Detection rules + incident evidence]
  Wazuh[Wazuh manager, future external integration] -->|X-Wazuh-API-Key| API
  API --> Metrics[/metrics]
  Prom[Prometheus] -->|scrapes| Metrics
  Graf[Grafana] -->|PromQL| Prom
  CI[GitHub Actions] --> Tests[Tests + Docker/K8s validation]
```

## Run with Docker

```bash
docker compose up --build
```

- UI: http://localhost:8080
- API: http://localhost:8000
- Swagger/OpenAPI: http://localhost:8000/docs
- Health: http://localhost:8000/health

The demo generator only creates `is_demo=true` authentication events against the local `Demo Auth Service` asset. It does not contact external systems or block IPs.

## Run backend locally

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

Without `DATABASE_URL`, local development uses SQLite. For PostgreSQL, copy `.env.example` to `.env` and set `DATABASE_URL` to a local PostgreSQL URL.

## Test

```bash
cd backend
pytest -q
```

API highlights: `POST /api/demo/{normal|brute_force|burst|success_after_failures}`, `POST /api/events`, `GET /api/incidents`, `PATCH /api/incidents/{id}`, `GET /api/assets`, and `GET /api/reports/summary`.

## GitHub Actions CI

The workflow at `.github/workflows/ci.yml` runs on pushes and pull requests targeting `main`. It uses only GitHub-hosted Ubuntu runner tools and does not require production credentials, paid services, PostgreSQL access, or external security systems.

Each CI run:

1. Sets up Python 3.12 and installs `backend/requirements.txt`.
2. Runs the backend pytest suite using the local SQLite test configuration.
3. Sets up Node.js 20 and runs `frontend_regression_test.js`.
4. Validates `docker compose config`.
5. Builds the backend and frontend Docker images.

Run the same checks locally from the project root:

```bash
cd backend
../.venv/bin/pytest -q
cd ..
node frontend_regression_test.js
docker compose config --quiet
docker build --tag cybersentinel-backend:ci ./backend
docker build --tag cybersentinel-frontend:ci .
```

CI status must be confirmed in the GitHub Actions tab after pushing this repository to GitHub; local validation does not constitute a completed GitHub Actions run.

## Kubernetes on Minikube

Phase 4 uses same-origin routing: the frontend calls `/api/...`, and Nginx proxies those requests to the Kubernetes-internal `backend` Service. Browser JavaScript never uses the internal Service DNS name.

The manifests are in `kubernetes/`. They use a 1Gi PostgreSQL PVC, one replica per workload, conservative resource limits, HTTP probes, a PostgreSQL readiness gate, and a backend command that runs `alembic upgrade head` before Uvicorn starts serving.

For the documented ARM64 Docker driver workflow:

```bash
minikube start --driver=docker --cpus=2 --memory=4096
./kubernetes/deploy.sh
kubectl -n cybersentinel port-forward svc/frontend 8080:80
```

Open http://localhost:8080. To exercise the real backend through the frontend proxy:

```bash
curl -i -X POST http://localhost:8080/api/demo/brute_force
kubectl -n cybersentinel get pods,svc,pvc
kubectl -n cybersentinel logs deploy/backend
```

Troubleshooting:

```bash
kubectl -n cybersentinel describe pod -l app=backend
kubectl -n cybersentinel logs statefulset/postgres
kubectl -n cybersentinel get events --sort-by=.lastTimestamp
```

Cleanup:

```bash
kubectl delete namespace cybersentinel
```

The Kubernetes Secret contains development-only placeholder credentials. Replace it through a separate local secret-management process before any non-development use; no production secrets are committed.

## Prometheus and Grafana monitoring

Phase 5 adds lightweight monitoring in the `cybersentinel` namespace. FastAPI exposes `/metrics` for the in-cluster Prometheus scraper; it is not published through the frontend Nginx proxy. Metrics use bounded labels only—no raw IP addresses, user IDs, or incident IDs.

The metrics include HTTP request totals, latency histograms, HTTP errors, processed security events, generated incidents, and detections by rule and severity. Grafana is provisioned automatically with a Prometheus data source and the CyberSentinel Operations dashboard.

Deploy or update the stack:

```bash
./kubernetes/deploy.sh
```

Access monitoring locally:

```bash
kubectl -n cybersentinel port-forward svc/prometheus 9090:9090
kubectl -n cybersentinel port-forward svc/grafana 3000:3000
```

- Prometheus: http://localhost:9090
- Grafana: http://localhost:3000
- Development login: `admin` / `cybersentinel-grafana-dev`

Verify real scrape data:

```bash
kubectl -n cybersentinel port-forward svc/backend 8000:8000
curl http://localhost:8000/metrics
curl 'http://localhost:9090/api/v1/query?query=up%7Bjob%3D%22cybersentinel-backend%22%7D'
curl -X POST http://localhost:8000/api/demo/brute_force
curl 'http://localhost:9090/api/v1/query?query=cybersentinel_security_events_processed_total'
```

Prometheus and Grafana use small resource requests/limits suitable for the 2 CPU / 4 GB Minikube cluster. Prometheus stores data in an `emptyDir` with a two-hour retention window because this is a development deployment; destroy/recreate removes monitoring history.

Monitoring cleanup:

```bash
kubectl -n cybersentinel delete deployment prometheus grafana
kubectl -n cybersentinel delete service prometheus grafana
kubectl -n cybersentinel delete configmap prometheus-config grafana-provisioning
kubectl -n cybersentinel delete secret grafana-admin
```

## Wazuh-compatible alert ingestion

CyberSentinel accepts validated Wazuh-compatible JSON at:

```text
POST /api/integrations/wazuh/alerts
X-Wazuh-API-Key: <configured-key>
```

The key is read from `WAZUH_API_KEY`, is never exposed through the frontend, and is not logged. Kubernetes uses the development-only placeholder in `kubernetes/wazuh-secret.yaml`; replace it locally with `kubectl create secret` before any real integration. The adapter maps Wazuh rule ID, level, timestamp, agent, source IP, and description into existing security events and incidents. Identical alert fingerprints are stored as events but do not create duplicate incidents.

Synthetic local demonstration:

```bash
curl -X POST http://localhost:8000/api/integrations/wazuh/alerts \
  -H 'Content-Type: application/json' \
  -H 'X-Wazuh-API-Key: replace-with-a-local-development-key' \
  -d @docs/sample-wazuh-alert.json
```

This sample is synthetic test data and does not originate from a live Wazuh manager. A future production adapter should send the same validated shape from a protected Wazuh integration network, rotate the API key, and add TLS/network policy at the perimeter.

## Security limitations

- Development credentials in Kubernetes manifests are placeholders only.
- The Wazuh adapter uses an API key, not production-grade mutual TLS or a secrets manager.
- Automatic containment is not implemented; no external IPs are blocked.
- Prometheus uses short-lived `emptyDir` storage in Minikube.
- The lightweight adapter is not a replacement for a full Wazuh manager, indexer, or dashboard.
- CORS is restricted to local development origins; production deployment needs a hardened origin policy.

## Full validation

```bash
node frontend_regression_test.js
cd backend && ../.venv/bin/pytest -q && cd ..
docker compose config --quiet
ruby -e "require 'yaml'; Dir['kubernetes/*.yaml'].each { |f| YAML.load_stream(File.read(f)) }"
```
