.PHONY: install dev test demo scan serve ide lint clean

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

test:
	python3 -m pytest -q

demo:
	codequal file examples/sample_bad.py

scan:
	codequal repo . --fail-on none

serve:
	codequal serve

ide:
	cd ide/vscode && npm install && npm run compile

clean:
	rm -rf build dist *.egg-info .pytest_cache codequal/__pycache__ \
	       codequal/scanners/__pycache__ tests/__pycache__ \
	       ide/vscode/out ide/vscode/node_modules *.sarif codequal.json codequal.md
