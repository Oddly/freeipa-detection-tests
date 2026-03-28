.PHONY: up down status logs clean

COMPOSE := podman compose -f podman-compose.yml

# Start FreeIPA server (~5 min on first run)
up:
	$(COMPOSE) up -d
	@echo "FreeIPA is starting. Initial setup takes 3-5 minutes."
	@echo "Run 'make logs' to watch progress, 'make status' to check health."

# Check service health
status:
	@podman inspect --format='{{.Name}}: {{.State.Health.Status}}' freeipa 2>/dev/null || echo "freeipa: not running"

# Watch logs
logs:
	$(COMPOSE) logs -f freeipa

# Stop FreeIPA
down:
	$(COMPOSE) down

# Full reset (remove all data)
clean:
	$(COMPOSE) down -v
