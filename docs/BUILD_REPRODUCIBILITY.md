# Reproducible builds

```bash
rustup install stable
cargo build --release --locked --features tui --bin hashchat-tui
```

Pin a toolchain with `rust-toolchain.toml` later if you need bit-identical CI. There is no Cabal path.
