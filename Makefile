.PHONY: all virtualenv
MAX_LINE_LENGTH=110

virtualenv: ./env/requirements.built

env:
	virtualenv env

./env/requirements.built: env requirements-dev.txt
	./env/bin/pip install -r requirements-dev.txt
	cp requirements-dev.txt ./env/requirements.built

flake8:
	flake8 --max-line-length=$(MAX_LINE_LENGTH) examples *.py

mypy:
	mypy examples/*.py zeroconf.py

test:
	nosetests -v

test_coverage:
	nosetests -v --with-coverage --cover-package=zeroconf

autopep8:
	autopep8 --max-line-length=$(MAX_LINE_LENGTH) -i examples *.py
