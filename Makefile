.PHONY: run test
run:
	./scripts/start.sh
test:
	.venv/bin/python -m pytest -q
