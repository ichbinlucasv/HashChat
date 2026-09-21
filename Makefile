# HashChat — Rust is the only recommended desktop path.
# Haskell remains in-tree as transitional / not recommended (see INSTALL.md).
#
# OPSEC: targets do not print secrets, cookies, or key material.

CARGO ?= cargo
CARGO_FLAGS ?= --release --locked
TUI_BIN := target/release/hashchat-tui

.PHONY: help lib tui run-tui test clean

help:
	@echo "HashChat Makefile (Rust recommended)"
	@echo "  make lib      - cargo build $(CARGO_FLAGS)  (library / FFI)"
	@echo "  make tui      - cargo build $(CARGO_FLAGS) --bin hashchat-tui --features tui"
	@echo "  make run-tui  - build tui then ./run-tui"
	@echo "  make test     - cargo test --lib"
	@echo "  make clean    - cargo clean"
	@echo "Haskell desktop: transitional / not recommended (HASHCHAT_ALLOW_HASKELL=1)."

lib:
	$(CARGO) build $(CARGO_FLAGS)

tui:
	$(CARGO) build $(CARGO_FLAGS) --bin hashchat-tui --features tui
	@mkdir -p rust-lib
	@test -f target/release/libhashchat_rust.so && cp -f target/release/libhashchat_rust.so rust-lib/ || true
	@echo "Built $(TUI_BIN)"

run-tui: tui
	./run-tui

test:
	$(CARGO) test --lib

clean:
	$(CARGO) clean
