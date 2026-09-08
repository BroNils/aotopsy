.PHONY: build test fuzz clean install bench coverage analyze

BINARY := aotopsy

build:
	go build -o $(BINARY) ./cmd/aotopsy

test:
	go test ./cmd/... ./internal/... ./tools/...

fuzz:
	go test -fuzz=FuzzELFOpen -fuzztime=30s ./internal/elfx/
	go test -fuzz=FuzzExtract -fuzztime=30s ./internal/snapshot/

# Integration assets, listed one by one rather than globbed: a missing file
# then names itself in the install error instead of expanding to nothing
# (issue #17), and no stray script gets installed without a decision.
GHIDRA_ASSETS := \
	ghidra_scripts/aotopsy_prescript.py \
	ghidra_scripts/aotopsy_apply.py \
	ghidra_scripts/AARCH64_dart.cspec
IDA_ASSETS := \
	ida_scripts/aotopsy_apply.py

install: build $(GHIDRA_ASSETS) $(IDA_ASSETS)
	install -d ~/.aotopsy/bin
	install -d ~/.aotopsy/ghidra_scripts
	install -d ~/.aotopsy/ida_scripts
	install -m 755 $(BINARY) ~/.aotopsy/bin/$(BINARY)
	install -m 644 $(GHIDRA_ASSETS) ~/.aotopsy/ghidra_scripts/
	install -m 644 $(IDA_ASSETS) ~/.aotopsy/ida_scripts/
	@echo ""
	@echo "installed: ~/.aotopsy/bin/$(BINARY)"
	@echo "installed: ~/.aotopsy/ghidra_scripts/"
	@echo "installed: ~/.aotopsy/ida_scripts/"
	@echo ""
	@if command -v aotopsy >/dev/null 2>&1; then \
		echo "aotopsy is already in PATH"; \
	else \
		RC=~/.zshrc; \
		[ -f ~/.bashrc ] && [ ! -f ~/.zshrc ] && RC=~/.bashrc; \
		echo "Add to PATH:"; \
		echo "  echo 'export PATH=\"\$$HOME/.aotopsy/bin:\$$PATH\"' >> $$RC"; \
		echo "  source $$RC"; \
	fi

clean:
	rm -f $(BINARY)
	go clean ./cmd/... ./internal/... ./tools/...

bench: ## Regenerate BENCHMARK.md from the ground-truth symtab differential
	@bash scripts/gen_benchmark.sh BENCHMARK.md

coverage: ## Regenerate COVERAGE.md by parsing every local corpus sample
	@bash scripts/gen_coverage.sh COVERAGE.md

analyze: build ## Cross-check export-dart output against the real Dart analyzer (SAMPLE=, DART=)
	@bash scripts/analyze.sh
