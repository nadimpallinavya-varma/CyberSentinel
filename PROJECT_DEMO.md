# CyberSentinel — 3-minute college demo

## 0:00–0:30 — Problem and architecture

Say: “Small teams need SOC visibility but may not have a dedicated SOC. CyberSentinel centralizes authentication telemetry, explainable detection, incident evidence, and operational monitoring. The browser uses Nginx, FastAPI evaluates events, PostgreSQL stores evidence, Kubernetes runs the services, and Prometheus/Grafana show health.”

Open the dashboard at `http://localhost:8080`.

## 0:30–1:20 — Live detection workflow

1. Open Detection Center.
2. Click **Repeated failed logins**.
3. Explain that the browser sends `POST /api/demo/brute_force` through the same-origin Nginx proxy.
4. Show the returned event count, rule name `AUTH-FAILURE-SEQUENCE`, severity, and evidence.
5. Open Incidents and select the new incident.
6. Acknowledge it, then resolve it.

Expected output: five synthetic events are processed and a high-severity incident is stored. Repeat runs may be deduplicated by design.

## 1:20–2:05 — Wazuh-compatible integration

In a terminal, run:

```bash
curl -X POST http://localhost:8000/api/integrations/wazuh/alerts \
  -H 'Content-Type: application/json' \
  -H 'X-Wazuh-API-Key: cybersentinel-wazuh-dev-only' \
  -d @docs/sample-wazuh-alert.json
```

Say: “This is a synthetic Wazuh-compatible alert. It is not from a live Wazuh manager. The API validates the payload, authenticates the integration, maps the rule and agent into existing CyberSentinel models, and suppresses identical duplicate incidents.”

Expected output: `duplicate: false`, a `WAZUH-5712` detection rule, and a high-severity incident. Sending the same request again returns `duplicate: true`.

## 2:05–2:40 — Monitoring and DevOps

Open:

- Prometheus: `http://localhost:9090`
- Grafana: `http://localhost:3000`
- Grafana login: `admin` / `cybersentinel-grafana-dev`

Show the provisioned **CyberSentinel Operations** dashboard. Point out HTTP request rate, p95 latency, errors, security events, incidents, and rule/severity detections. These panels use PromQL against live backend metrics.

## 2:40–3:00 — Close

Say: “The platform is intentionally local and safe: demo events use TEST-NET data, credentials are development placeholders, incident response is analyst-driven, and the full Wazuh stack is optional for a future integration.”

## Start commands

```bash
minikube start --driver=docker --cpus=2 --memory=4096
./kubernetes/deploy.sh
kubectl -n cybersentinel port-forward svc/frontend 8080:80
kubectl -n cybersentinel port-forward svc/prometheus 9090:9090
kubectl -n cybersentinel port-forward svc/grafana 3000:3000
```

## Troubleshooting

```bash
kubectl -n cybersentinel get pods,svc,pvc
kubectl -n cybersentinel logs deploy/backend
kubectl -n cybersentinel logs deploy/prometheus
kubectl -n cybersentinel logs deploy/grafana
kubectl -n cybersentinel get events --sort-by=.lastTimestamp
curl http://localhost:8000/health
curl http://localhost:8000/metrics
```

## DevOps tools in one sentence

- Docker packages reproducible frontend/backend images.
- Compose runs the local multi-container workflow.
- GitHub Actions tests code and builds images on every main-branch change.
- Kubernetes schedules and probes services in Minikube.
- PostgreSQL persists incidents and evidence.
- Prometheus scrapes real application metrics.
- Grafana turns PromQL queries into the operations dashboard.
- Alembic applies database migrations before FastAPI serves traffic.
