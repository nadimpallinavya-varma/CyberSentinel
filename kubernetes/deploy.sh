#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAMESPACE="cybersentinel"

cd "$ROOT_DIR"
command -v minikube >/dev/null || { echo "minikube is required" >&2; exit 1; }
command -v kubectl >/dev/null || { echo "kubectl is required" >&2; exit 1; }

echo "Building ARM64-compatible local images..."
docker build --platform linux/arm64 -t cybersentinel-backend:local ./backend
docker build --platform linux/arm64 -t cybersentinel-frontend:local .

echo "Loading images into Minikube..."
minikube image load cybersentinel-backend:local
minikube image load cybersentinel-frontend:local

echo "Applying manifests..."
kubectl apply -f kubernetes/namespace.yaml
kubectl apply -f kubernetes/configmap.yaml -f kubernetes/secret.yaml -f kubernetes/wazuh-secret.yaml
kubectl apply -f kubernetes/postgres.yaml -f kubernetes/backend.yaml -f kubernetes/frontend.yaml
kubectl apply -f kubernetes/prometheus.yaml -f kubernetes/grafana.yaml

# The local image tag is intentionally stable for Minikube. Restart the backend
# so a newly loaded local image is used even when the Deployment spec is unchanged.
kubectl -n "$NAMESPACE" rollout restart deployment/backend

kubectl -n "$NAMESPACE" rollout status statefulset/postgres --timeout=180s
kubectl -n "$NAMESPACE" rollout status deployment/backend --timeout=180s
kubectl -n "$NAMESPACE" rollout status deployment/frontend --timeout=180s
kubectl -n "$NAMESPACE" rollout status deployment/prometheus --timeout=180s
kubectl -n "$NAMESPACE" rollout status deployment/grafana --timeout=180s

echo "Deployment is ready. In another terminal, run:"
echo "kubectl -n $NAMESPACE port-forward svc/frontend 8080:80"
echo "Then open http://localhost:8080"
echo "Prometheus: kubectl -n $NAMESPACE port-forward svc/prometheus 9090:9090"
echo "Grafana: kubectl -n $NAMESPACE port-forward svc/grafana 3000:3000"
