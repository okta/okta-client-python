PYTHON ?= python
TEST_RESULTS_DIR ?= test-results
JUNIT_XML ?=
ifneq ($(strip $(JUNIT_XML)),)
JUNIT_FLAG := --junitxml=$(JUNIT_XML)
else
JUNIT_FLAG :=
endif

.PHONY: test test-cov integration lint lint-fix build deps clean publish-test publish check-dist

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

clean:
	rm -rf dist/ build/ *.egg-info src/*.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

check-dist:
	@if [ ! -d "dist" ] || [ -z "$$(ls -A dist 2>/dev/null)" ]; then \
		echo "No distribution files found. Run 'make build' first."; \
		exit 1; \
	fi
	$(PYTHON) -m twine check dist/*

publish-test:
	@if [ ! -d "dist" ] || [ -z "$$(ls -A dist 2>/dev/null)" ]; then \
		echo "No distribution files found. Run 'make build' first."; \
		exit 1; \
	fi
	$(PYTHON) -m twine check dist/*
	$(PYTHON) -m twine upload --repository testpypi dist/*

publish:
	@if [ ! -d "dist" ] || [ -z "$$(ls -A dist 2>/dev/null)" ]; then \
		echo "No distribution files found. Run 'make build' first."; \
		exit 1; \
	fi
	$(PYTHON) -m twine check dist/*
	$(PYTHON) -m twine upload dist/*
