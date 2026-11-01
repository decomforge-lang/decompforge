# Atajos de desarrollo (en Windows puedes usar scripts/check.ps1).
# Si tu intérprete no se llama `python`, usa `make adapters PYTHON=python3`.
PYTHON ?= python
.PHONY: build test lint fmt check doc coverage demo schema-check adapters re-schema-check

build:
	cargo build --workspace

test:
	cargo test --workspace

fmt:
	cargo fmt --all

lint:
	cargo clippy --workspace --all-targets -- -D warnings

check: fmt lint test doc

doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps

coverage:
	cargo llvm-cov --package decompforge-core --all-targets --fail-under-lines 80

demo:
	rm -rf target/demo
	cargo run -q -p decompforge-cli -- init demo --sample --dir target/demo

schema-check: demo
	cargo run -q -p decompforge-cli -- export --format json --project target/demo/demo.dfproj --output target/demo/export.json
	$(PYTHON) scripts/validate_export.py target/demo/export.json

# Adaptadores de la Fase 2: cliente Python y ciclo real export -> apply.
adapters:
	cd adapters/python && $(PYTHON) -m unittest discover -s tests -t . -v

re-schema-check: demo
	cargo run -q -p decompforge-cli -- export --format re-json --project target/demo/demo.dfproj --output target/demo/export-re.json
	PYTHONPATH=adapters/python $(PYTHON) -m decompforge_re validate target/demo/export-re.json
