# PhishGuard. Works on Linux/macOS and on Windows with Git Bash + GNU make.
ifeq ($(OS),Windows_NT)
  VENV_BIN := .venv/Scripts
else
  VENV_BIN := .venv/bin
endif
PY := $(VENV_BIN)/python
PYTHON_VERSION := 3.12

.PHONY: setup app test test-all lint format audit audit-email prepare prepare-email train-url train-email evaluate evaluate-email audit-deps

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

audit:
	$(PY) -m phishguard.training.audit url

prepare:
	$(PY) -m phishguard.training.prepare_url url

train-url:
	$(PY) -m phishguard.training.train url

evaluate:
	$(PY) -m phishguard.training.evaluate url

audit-email:
	$(PY) -m phishguard.training.audit_email email

prepare-email:
	$(PY) -m phishguard.training.prepare_email email

train-email:
	$(PY) -m phishguard.training.train email

evaluate-email:
	$(PY) -m phishguard.training.evaluate email
