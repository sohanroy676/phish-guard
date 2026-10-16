# PhishGuard. Works on Linux/macOS and on Windows with Git Bash + GNU make.
ifeq ($(OS),Windows_NT)
  VENV_BIN := .venv/Scripts
else
  VENV_BIN := .venv/bin
endif
PY := $(VENV_BIN)/python
PYTHON_VERSION := 3.12

.PHONY: setup app test test-all lint format audit prepare train-url train-email evaluate audit-deps

setup:
	python -m venv .venv || uv venv --python $(PYTHON_VERSION) .venv
	$(PY) -m pip install -r requirements.lock
	$(PY) -m pip install -e . --no-deps
	cd web && npm ci
	@test -f .env || cp .env.example .env

app:
	$(PY) -m uvicorn phishguard.app.main:app --reload --port 8000

test:
	$(PY) -m pytest -q -m "not slow"

test-all:
	$(PY) -m pytest -q

lint:
	$(VENV_BIN)/ruff check .
	$(VENV_BIN)/ruff format --check .
	cd web && npm run lint

format:
	$(VENV_BIN)/ruff format .
	cd web && npm run format

audit-deps:
	$(VENV_BIN)/pip-audit -r requirements.lock
	cd web && npm audit

# Data and model targets arrive with v0.3.0 and v0.5.0.
audit prepare train-url train-email evaluate:
	@echo "$@ is not implemented yet" && exit 1
