.PHONY: check
check:
	cargo fmt --check
	cargo clippy --all-features --all-targets -- -D warnings
