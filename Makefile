.PHONY: help test demo evidence lint clean

help:
	@echo "targets:"
	@echo "  make test      - install dev deps and run the pytest suite"
	@echo "  make demo      - run the gate on the committed KEV tripwire fixture (visible output)"
	@echo "  make evidence  - rebuild the trudesk funnel evidence (needs raw scans; see script header)"
	@echo "  make lint      - actionlint the workflows (needs docker)"

test:
	pip install -e ".[dev]"
	pytest -q

# One-command visible demo from a clean clone: scan the synthetic KEV tripwire
# and show the gate blocking it via the KEV path. Exits non-zero (the gate blocks)
# on purpose, so `|| true` keeps `make demo` from reporting failure.
demo:
	python -m gate evaluate \
	  --osv tests/fixtures/scans/osv-kev-tripwire.json \
	  --kev tests/fixtures/kev-snapshot.json \
	  --epss tests/fixtures/epss-snapshot.csv \
	  --title "DEMO: synthetic KEV tripwire" || true

evidence:
	@echo "See scripts/build_evidence.py header for the full invocation with raw scan paths."

lint:
	docker run --rm -v "$$PWD:/repo" -w /repo rhysd/actionlint:latest -color \
	  .github/workflows/ci.yml .github/workflows/security-scan.yml .github/workflows/target-scan.yml

clean:
	rm -rf build dist *.egg-info .pytest_cache scan-out
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
