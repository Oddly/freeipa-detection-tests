.PHONY: up down test clean logs status

COMPOSE := podman compose -f podman-compose.yml

# Build and start all services (FreeIPA takes ~5 min on first run)
up:
	$(COMPOSE) up -d
	@echo "Waiting for services to become healthy..."
	@echo "FreeIPA initial setup takes 3-5 minutes on first run."
	@echo "Run 'make status' to check progress, 'make test' when ready."

# Run the full test suite
test:
	$(COMPOSE) run --rm test-runner

# Check service health
status:
	$(COMPOSE) ps
	@echo ""
	@echo "=== Health ==="
	@podman inspect --format='{{.Name}}: {{.State.Health.Status}}' freeipa elasticsearch kibana 2>/dev/null || true

# View live logs
logs:
	$(COMPOSE) logs -f

logs-freeipa:
	$(COMPOSE) logs -f freeipa

logs-filebeat:
	$(COMPOSE) logs -f filebeat

logs-test:
	$(COMPOSE) logs -f test-runner

# Stop all services
down:
	$(COMPOSE) down

# Stop and remove all data (full reset)
clean:
	$(COMPOSE) down -v
	podman volume rm -f freeipa-detection-tests_freeipa-data freeipa-detection-tests_freeipa-logs freeipa-detection-tests_es-data 2>/dev/null || true
