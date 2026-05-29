.PHONY: install test demo run-api lint clean help

help:
	@echo "Available targets:"
	@echo "  install   — create venv and install all dependencies"
	@echo "  test      — run pytest"
	@echo "  demo      — ingest all sample logs and show summary"
	@echo "  run-api   — start FastAPI server on port 8000"
	@echo "  lint      — ruff check"
	@echo "  clean     — remove venv, pycache, test db files"

install:
	python3.11 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt

test:
	.venv/bin/pytest tests/ -v

demo:
	.venv/bin/python -m cli.main demo

run-api:
	.venv/bin/uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

lint:
	.venv/bin/ruff check app/ cli/ tests/ || true

clean:
	rm -rf .venv __pycache__ .pytest_cache
	find . -name "*.pyc" -delete
	find . -name "*.db" -delete
