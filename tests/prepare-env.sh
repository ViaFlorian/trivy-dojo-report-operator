#!/usr/bin/env bash

set -o errexit
set -o pipefail
set -o nounset
if [[ "${TRACE-0}" == "1" ]]; then set -o xtrace; fi

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)

minikube start
helm repo add aquasecurity https://aquasecurity.github.io/helm-charts/
helm dependency build "${SCRIPT_DIR}/resources/helm/"
helm install trivy-operator "${SCRIPT_DIR}/resources/helm/"
kubectl create namespace defectdojo
