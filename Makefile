.PHONY: run test
run:
	bash scripts/start.sh
test:
	.venv/bin/python -m pytest -q
