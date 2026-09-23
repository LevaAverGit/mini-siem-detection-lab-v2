.PHONY: install test demo run-api lint clean help dashboard-up dashboard-down

help:
	@echo "Available targets:"
	@echo "  install        — create venv and install all dependencies"
	@echo "  test           — run pytest"
	@echo "  demo           — ingest all sample logs and show summary"
	@echo "  run-api        — start FastAPI server on port 8000"
	@echo "  dashboard-up   — start the Grafana SOC dashboard (runs demo first if needed)"
	@echo "  dashboard-down — stop the Grafana SOC dashboard"
	@echo "  lint           — ruff check"
	@echo "  clean          — remove venv, pycache, test db files"

install:
	python3.11 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt

test:
	.venv/bin/pytest tests/ -v

demo:
	.venv/bin/python -m cli.main demo

run-api:
	.venv/bin/uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

dashboard-up:
	@test -f demo.db || $(MAKE) demo
	docker compose up -d
	@echo "Grafana on http://127.0.0.1:3000 — open 'SOC Overview — mini-SIEM' (anonymous view, no login)."

dashboard-down:
	docker compose down

lint:
	.venv/bin/ruff check app/ cli/ tests/ || true

clean:
	rm -rf .venv __pycache__ .pytest_cache
	find . -name "*.pyc" -delete
	find . -name "*.db" -delete
