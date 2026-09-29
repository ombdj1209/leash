.PHONY: install test eval serve
install: ; pip install -e ".[dev]"
test: ; python -m pytest -q
eval: ; python run_eval.py
serve: ; uvicorn leash.server:app --port 8100
