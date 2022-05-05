# version: 1.2

.PHONY: all virtualenv
MAX_LINE_LENGTH=110
PYTHON_IMPLEMENTATION:=$(shell python -c "import sys;import platform;sys.stdout.write(platform.python_implementation())")
PYTHON_VERSION:=$(shell python -c "import sys;sys.stdout.write('%d.%d' % sys.version_info[:2])")

LINT_TARGETS:=flake8

ifneq ($(findstring PyPy,$(PYTHON_IMPLEMENTATION)),PyPy)
	LINT_TARGETS:=$(LINT_TARGETS) mypy black_check pylint
endif


virtualenv: ./env/requirements.built

env:
	python -m venv env

./env/requirements.built: env requirements-dev.txt
	./env/bin/pip install -r requirements-dev.txt
	cp requirements-dev.txt ./env/requirements.built

.PHONY: ci
ci: lint test_coverage

.PHONY: lint
lint: $(LINT_TARGETS)

flake8:
	flake8 --max-line-length=$(MAX_LINE_LENGTH) setup.py examples zeroconf

pylint:
	pylint zeroconf

.PHONY: black_check
black_check:
	black --check setup.py examples zeroconf

mypy:
# --no-warn-redundant-casts --no-warn-unused-ignores is needed since we support multiple python versions
# We should be able to drop this once python 3.6 goes away
	mypy --no-warn-redundant-casts --no-warn-unused-ignores examples/*.py zeroconf

test:
	pytest --durations=20 --timeout=60 -v tests

test_coverage:
	pytest --durations=20 --timeout=60 -v --cov=zeroconf --cov-branch --cov-report xml --cov-report html --cov-report term-missing tests

autopep8:
	autopep8 --max-line-length=$(MAX_LINE_LENGTH) -i setup.py examples zeroconf

