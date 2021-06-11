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
	virtualenv env

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
	pylint zeroconf/__init__.py zeroconf/aio.py zeroconf/asyncio.py

.PHONY: black_check
black_check:
	black --check setup.py examples zeroconf

mypy:
	mypy examples/*.py zeroconf/*.py

test:
	pytest -v zeroconf/test.py zeroconf/test_aio.py zeroconf/test_asyncio.py

test_coverage:
	pytest -v --cov=zeroconf --cov-branch --cov-report html --cov-report term-missing zeroconf/test.py zeroconf/test_aio.py zeroconf/test_asyncio.py

autopep8:
	autopep8 --max-line-length=$(MAX_LINE_LENGTH) -i setup.py examples zeroconf
