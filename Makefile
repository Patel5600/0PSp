.PHONY: production-check

production-check:
	@test "$$(riscv64-unknown-elf-gcc -dumpfullversion)" = "15.3.0" || { echo "Production-1 requires riscv64-unknown-elf-gcc 15.3.0 (the guest ELF commitment is pinned)"; exit 1; }
	cargo +1.91.1 test --locked --manifest-path proof/openvm/v3-nullifier-spike/Cargo.toml
	cargo +1.91.1 openvm build --manifest-path proof/openvm/v3-nullifier-spike/Cargo.toml
	cargo +1.91.1 test --locked --manifest-path proof/openvm/v3-nullifier-spike/proof-output-checker/Cargo.toml
	cargo +1.91.1 build --locked --release --manifest-path proof/openvm/v3-nullifier-spike/proof-output-checker/Cargo.toml
	python -m pytest -q -p no:cacheprovider --basetemp=.pytest-production-work
	python scripts/production_check.py
