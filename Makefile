# HashChat — Rust-only build.
#
# OPSEC: targets do not print secrets, cookies, or key material.

CARGO ?= cargo
CARGO_FLAGS ?= --release --locked
TUI_BIN := target/release/hashchat-tui

.PHONY: help lib tui run-tui test clean

help:
	@echo "HashChat Makefile (Rust)"
	@echo "  make lib      - cargo build $(CARGO_FLAGS)  (library)"
	@echo "  make tui      - cargo build $(CARGO_FLAGS) --bin hashchat-tui --features tui"
	@echo "  make run-tui  - build tui then ./run-tui"
	@echo "  make test     - cargo test --lib"
	@echo "  make clean    - cargo clean"

lib:
	$(CARGO) build $(CARGO_FLAGS)

tui:
	$(CARGO) build $(CARGO_FLAGS) --bin hashchat-tui --features tui
	@echo "Built $(TUI_BIN)"

run-tui: tui
	./run-tui

test:
	$(CARGO) test --lib

clean:
	$(CARGO) clean
