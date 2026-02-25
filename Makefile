PYTHON ?= python
TEST_RESULTS_DIR ?= test-results
JUNIT_XML ?=
ifneq ($(strip $(JUNIT_XML)),)
JUNIT_FLAG := --junitxml=$(JUNIT_XML)
else
JUNIT_FLAG :=
endif

.PHONY: test test-cov integration lint lint-fix build deps

test:
	$(PYTHON) -m pytest tests -m "not integration" $(JUNIT_FLAG)

test-cov:
	$(PYTHON) -m pytest tests -m "not integration" --cov --cov-report=term-missing --cov-report=html:coverage-html --cov-report=xml:coverage.xml $(JUNIT_FLAG)

integration:
	$(PYTHON) -m pytest -s tests/integration -m integration $(JUNIT_FLAG)

lint:
	$(PYTHON) -m ruff check .

lint-fix:
	$(PYTHON) -m ruff check --fix .

build:
	$(PYTHON) -m build

deps:
	$(PYTHON) -m pip install -r requirements.txt
	$(PYTHON) -m pip install -r dev-requirements.txt
	$(PYTHON) -m pip install -e ".[dev]"
