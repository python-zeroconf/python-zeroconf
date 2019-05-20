.PHONY: all virtualenv
MAX_LINE_LENGTH=110
PYTHON_IMPLEMENTATION:=$(shell python -c "import sys;import platform;sys.stdout.write(platform.python_implementation())")
PYTHON_VERSION:=$(shell python -c "import sys;sys.stdout.write('%d.%d' % sys.version_info[:2])")

LINT_TARGETS:=flake8

ifneq ($(findstring PyPy,$(PYTHON_IMPLEMENTATION)),PyPy)
	LINT_TARGETS:=$(LINT_TARGETS) mypy
endif
ifneq ($(findstring 3.5,$(PYTHON_VERSION)),3.5)
	LINT_TARGETS:=$(LINT_TARGETS) black_check
endif


virtualenv: ./env/requirements.built

env:
	virtualenv env

./env/requirements.built: env requirements-dev.txt
	./env/bin/pip install -r requirements-dev.txt
	cp requirements-dev.txt ./env/requirements.built

.PHONY: ci
ci: test_coverage lint

.PHONY: lint
lint: $(LINT_TARGETS)

flake8:
	flake8 --max-line-length=$(MAX_LINE_LENGTH) examples *.py

.PHONY: black_check
black_check:
	black --check *.py examples

mypy:
	mypy examples/*.py test_zeroconf.py zeroconf.py

test:
	nosetests -v

test_coverage:
	nosetests -v --with-coverage --cover-package=zeroconf

autopep8:
	autopep8 --max-line-length=$(MAX_LINE_LENGTH) -i examples *.py
