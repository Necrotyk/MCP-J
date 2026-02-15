# MCP-J Makefile

.PHONY: build test clean install run-cli check fmt package-vscode lint

# Rust
build:
	cargo build --release

test:
	cargo test

clean:
	cargo clean

install:
	cargo install --path mcp-j-cli

check:
	cargo clippy -- -D warnings

fmt:
	cargo fmt --all

lint: fmt check

# Run CLI with arguments (e.g. make run-cli ARGS="-- /bin/bash")
run-cli:
	cargo run -p mcp-j-cli -- $(ARGS)

# VSCode Extension
vscode-install:
	cd clients/vscode-mcp-j && npm install

vscode-package: vscode-install
	cd clients/vscode-mcp-j && npx vsce package
