#!/bin/sh

set -eu

api_url="${GRAFANA_URL}/apis/dashboard.grafana.app/v2/namespaces/default/dashboards"
dashboard_name="firewall-soc-ops"
folder_uid="cfxg8fvwln280d"

printf '%s\n' "Waiting for Grafana to become ready..."
while ! curl -fsS "${GRAFANA_URL}/api/health" >/dev/null 2>&1; do
  sleep 2
done

response_file="$(mktemp)"
folder_status="$(curl -sS -o "${response_file}" -w '%{http_code}' \
  -X POST \
  -H 'Accept: application/json' \
  -H 'Content-Type: application/json' \
  --data "{\"uid\":\"${folder_uid}\",\"title\":\"Firewall World Model\"}" \
  "${GRAFANA_URL}/api/folders")"

case "${folder_status}" in
  2??|409) ;;
  *)
    printf '%s\n' "Grafana folder provisioning failed (HTTP ${folder_status})." >&2
    cat "${response_file}" >&2
    exit 1
    ;;
esac

status="$(curl -sS -o "${response_file}" -w '%{http_code}' \
  -X POST \
  -H 'Accept: application/json' \
  -H 'Content-Type: application/json' \
  --data-binary "@${DASHBOARD_FILE}" \
  "${api_url}")"

case "${status}" in
  2??)
    printf '%s\n' "Grafana dashboard provisioned."
    ;;
  409|412)
    status="$(curl -sS -o "${response_file}" -w '%{http_code}' \
      -X PUT \
      -H 'Accept: application/json' \
      -H 'Content-Type: application/json' \
      --data-binary "@${DASHBOARD_FILE}" \
      "${api_url}/${dashboard_name}")"
    case "${status}" in
      2??) printf '%s\n' "Grafana dashboard updated." ;;
      *)
        printf '%s\n' "Grafana dashboard update failed (HTTP ${status})." >&2
        cat "${response_file}" >&2
        exit 1
        ;;
    esac
    ;;
  *)
    printf '%s\n' "Grafana dashboard provisioning failed (HTTP ${status})." >&2
    cat "${response_file}" >&2
    exit 1
    ;;
esac
