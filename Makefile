PYTHON ?= python3

.PHONY: help test compile check demo clean

help:
	@echo "tls-doctor development targets:"
	@echo "  make test     run the full test suite"
	@echo "  make compile  byte-compile the package and tests"
	@echo "  make check    compile and test"
	@echo "  make demo     run a live diagnosis against example.com"
	@echo "  make clean    remove generated caches and build artifacts"

test:
	$(PYTHON) -m unittest discover -s tests -v

compile:
	$(PYTHON) -m compileall -q tls_doctor tests

check: compile test

demo:
	$(PYTHON) -m tls_doctor example.com

clean:
	rm -rf build dist .pytest_cache
	rm -rf tls_doctor/__pycache__ tests/__pycache__
	rm -rf *.egg-info
