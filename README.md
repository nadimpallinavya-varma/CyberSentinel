# CyberSentinel

CyberSentinel is a local-first security operations platform. The UI in `index.html` is preserved; Phase 2 adds a FastAPI API, SQLAlchemy persistence, Alembic migrations, explainable detection rules, safe synthetic demos, and Docker Compose.

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
