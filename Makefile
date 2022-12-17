# version: 1.3


test:
	poetry run pytest --durations=20 --timeout=60 -v tests
