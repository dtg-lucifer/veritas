# ==============================================================================
# Veritas & AI World Model — Operational Makefile
# ==============================================================================
# SIH 2026 Problem Statement: Autonomous Veritas with AI World Model Predictive Defense.
# Run `make help` to inspect available commands grouped by operational category.
# ==============================================================================

.PHONY: help infra-up infra-down infra-restart infra-logs \
        backend dashboard dev \
        sniff replay-benign replay-botnet replay-bruteforce replay-infiltration \
        reset-simulation scale-100 check-health check-rollout check-alerts \
        check-redis check-kafka check-targets check-loki \
        build-dashboard test-eval demo-terminal export-report clean

SHELL := /bin/bash
ACTIVE_IFACE ?= $(shell ip route get 8.8.8.8 2>/dev/null | awk '{print $$5; exit}')

# ------------------------------------------------------------------------------
# Default Target: Help
# ------------------------------------------------------------------------------
help:
	@echo ""
	@echo "╔══════════════════════════════════════════════════════════════════════════════╗"
	@echo "║       Veritas & AI WORLD MODEL — OPERATIONAL PLAYBOOK              ║"
	@echo "╚══════════════════════════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "INFRASTRUCTURE (Docker Compose):"
	@echo "  make infra-up         Start Kafka, Kafka-UI, Redis, Prometheus, Loki, Grafana"
	@echo "  make infra-down       Stop and tear down all Docker microservices"
	@echo "  make infra-restart    Restart all Docker containers"
	@echo "  make infra-logs       Tail live logs across all Docker services"
	@echo ""
	@echo "SERVICES BRING-UP (Run in separate terminals):"
	@echo "  make backend          Start FastAPI AI World Model Gateway on :8000 (Terminal 1)"
	@echo "  make dashboard        Start Next.js SOC Radar UI on :3000 (Terminal 2)"
	@echo "  make dev              Launch all Docker infra + reminder for Terminal 1 & 2"
	@echo ""
	@echo "TELEMETRY & ATTACK INJECTION (Terminal 3):"
	@echo "  make sniff            			Sniff real laptop Wi-Fi/Ethernet interface via Scapy (sudo)"
	@echo "  make replay-benign-burst    	Stream Monday benign baseline (Zero False-Positive proof) - 200 flows @ 100 flows/sec"
	@echo "  make replay-botnet-burst    	Stream Friday Botnet C2 / Lateral Movement attack - 200 flows @ 100 flows/sec"
	@echo "  make replay-bruteforce-burst 	Stream Wednesday SSH/FTP Brute-Force attack - 200 flows @ 100 flows/sec"
	@echo "  make replay-infiltration-burst Stream Thursday Port Reconnaissance / Infiltration attack - 200 flows @ 100 flows/sec"
	@echo "  make replay-benign    			Stream Monday benign baseline (Zero False-Positive proof)"
	@echo "  make replay-botnet    			Stream Friday Botnet C2 / Lateral Movement attack"
	@echo "  make replay-bruteforce 		Stream Wednesday SSH/FTP Brute-Force attack"
	@echo "  make replay-infiltration 		Stream Thursday Port Reconnaissance / Infiltration attack"
	@echo ""
	@echo "SOC MANAGEMENT & BENCHMARKING (Terminal 4):"
	@echo "  make reset-simulation Reset 2-min state buffer and alerts to clean baseline"
	@echo "  make scale-100        Scale network capacity to 100 workstations (no reboot)"
	@echo "  make check-health     Inspect gateway and ML subsystem health"
	@echo "  make check-rollout    Inspect 5-step forward prediction rollout (t+15s -> t+75s)"
	@echo "  make check-alerts     Fetch recent security incidents and alerts"
	@echo "  make check-redis      Read Redis ingestion throughput and error counters"
	@echo "  make check-kafka      Inspect Kafka consumer worker streaming status"
	@echo "  make check-targets    Verify Prometheus scrape target health"
	@echo "  make check-loki       Query live structured logs from Grafana Loki"
	@echo ""
	@echo "ML OFFLINE WALKTHROUGH & REPORTS:"
	@echo "  make demo-terminal    Run 32-dim state table & forward rollout terminal walkthrough"
	@echo "  make export-report    Export formal Markdown SOC incident report"
	@echo "  make test-eval        Run test evaluation harness on mock flows"
	@echo "  make build-dashboard  Verify Next.js production build"
	@echo ""

# ------------------------------------------------------------------------------
# Infrastructure Management
# ------------------------------------------------------------------------------
infra-up:
	sudo docker compose up -d kafka kafka-ui redis prometheus loki grafana
	@echo "Core infrastructure ready:"
	@echo " - Kafka Broker:     localhost:9092"
	@echo " - Kafka Web UI:    http://localhost:8081"
	@echo " - Redis Telemetry:  localhost:6379"
	@echo " - Prometheus:       http://localhost:9090"
	@echo " - Grafana Loki:     http://localhost:3100"
	@echo " - Grafana SOC:      http://localhost:3001"

infra-down:
	sudo docker compose down

infra-restart:
	sudo docker compose restart

infra-logs:
	sudo docker compose logs -f --tail=100

# ------------------------------------------------------------------------------
# Core Application Bring-Up
# ------------------------------------------------------------------------------
backend:
	@echo "Starting FastAPI AI World Model Gateway..."
	cd backend && WINDOW_SECONDS=15 uv run uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload

dashboard:
	@echo "Starting Next.js SOC Dashboard on http://localhost:3000..."
	cd dashboard && pnpm dev

dev: infra-up
	@echo ""
	@echo "=========================================================================="
	@echo "Docker containers up! Now open two terminals for live presentation:"
	@echo "  Terminal 1: make backend"
	@echo "  Terminal 2: make dashboard"
	@echo "=========================================================================="

# ------------------------------------------------------------------------------
# Telemetry Ingestion & Attack Replays
# ------------------------------------------------------------------------------
sniff:
	@echo "Active interface detected: $(ACTIVE_IFACE)"
	@if [ -z "$(ACTIVE_IFACE)" ]; then \
		echo "Could not detect active interface. Run: make sniff ACTIVE_IFACE=<iface>"; exit 1; \
	fi
	cd logger && sudo uv run logger sniff --interface $(ACTIVE_IFACE)

replay-benign-burst:
	@echo "Streaming Monday benign traffic (200 flows at 100 flows/sec)..."
	cd logger && uv run logger --day=monday --rate=100 --max-flows=200

replay-botnet-burst:
	@echo "Streaming Friday Botnet C2 attack traffic..."
	cd logger && uv run logger --day=friday --scenario=attack --rate=100 --max-flows=200

replay-bruteforce-burst:
	@echo "Streaming Wednesday SSH/FTP Brute Force attack traffic..."
	cd logger && uv run logger --day=wednesday --scenario=attack --rate=100 --max-flows=200

replay-infiltration-burst:
	@echo "Streaming Thursday Reconnaissance & Infiltration attack traffic..."
	cd logger && uv run logger --day=thursday --scenario=attack --rate=100 --max-flows=200

replay-benign:
	@echo "Streaming Monday benign traffic (Continuous)..."
	cd logger && uv run logger --day=monday --rate=100

replay-botnet:
	@echo "Streaming Friday Botnet C2 attack traffic (Continuous)..."
	cd logger && uv run logger --day=friday --scenario=attack --rate=100

replay-bruteforce:
	@echo "Streaming Wednesday SSH/FTP Brute Force attack traffic (Continuous)..."
	cd logger && uv run logger --day=wednesday --scenario=attack --rate=100

replay-infiltration:
	@echo "Streaming Thursday Reconnaissance & Infiltration attack traffic (Continuous)..."
	cd logger && uv run logger --day=thursday --scenario=attack --rate=100

# ------------------------------------------------------------------------------
# SOC Management & REST API Commands
# ------------------------------------------------------------------------------
reset-simulation:
	@echo "Resetting World Model 2-minute memory context..."
	curl -s -X POST http://localhost:8000/api/v1/simulation/reset | jq .

scale-100:
	@echo "Scaling network capacity to 100 connected workstations..."
	curl -s -X POST http://localhost:8000/api/v1/config \
		-H "Content-Type: application/json" \
		-d '{"network": {"connected_clients_count": 100, "baseline_clients_capacity": 1, "auto_scale_volumetric_thresholds": true}}' | jq .

check-health:
	curl -s http://localhost:8000/health | jq .

check-rollout:
	curl -s http://localhost:8000/api/v1/simulation/latest | jq '{max_risk: .simulation.max_infiltration_prob, peak_stage: .simulation.peak_stage, policy: .simulation.recommended_policy, rollout: .simulation.rollout_steps}'

check-alerts:
	curl -s http://localhost:8000/api/v1/alerts | jq .

check-redis:
	curl -s http://localhost:8000/api/v1/metrics/redis | jq .

check-kafka:
	curl -s http://localhost:8000/api/v1/kafka/status | jq .

check-targets:
	curl -s http://localhost:9090/api/v1/targets | jq .data.activeTargets

check-loki:
	curl -s -G "http://localhost:3100/loki/api/v1/query_range" --data-urlencode 'query={job="firewall_backend"}' | jq .data.result

# ------------------------------------------------------------------------------
# ML Walkthrough, Testing & Quality Assurance
# ------------------------------------------------------------------------------
demo-terminal:
	@echo "Running standalone 5-step forward simulation walkthrough..."
	cd ml && uv run python demo.py --file data/external-network/cic-ids-2018/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv --rollout-steps 5

export-report:
	@mkdir -p ml/reports
	@echo "Exporting formal SOC presentation report to ml/reports/judge_presentation_report.md..."
	cd ml && uv run python demo.py \
		--file data/external-network/cic-ids-2018/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv \
		--rollout-steps 5 \
		--output reports/judge_presentation_report.md

test-eval:
	cd backend && uv run python test_eval.py

build-dashboard:
	pnpm --prefix dashboard build

clean:
	rm -rf dashboard/.next ml/reports/*.md
	@echo "Cleaned build artifacts."
