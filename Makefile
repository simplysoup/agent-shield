.PHONY: test lint demo

test:
	python -m pytest -q

demo:
	python -m agentshield.cli demo
