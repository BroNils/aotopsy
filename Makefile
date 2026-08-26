.PHONY: build test fuzz boot clean scan disasm render report skills flutter-meta ghidra inventory parity install

BINARY := aotopsy
SAMPLE ?= samples/blutter-lce.so
SAMPLE_NAME := $(basename $(notdir $(SAMPLE)))
OUT_DIR := out/$(SAMPLE_NAME)
GHIDRA_HOME ?= /Volumes/tank4a - Data/opt/homebrew/Caskroom/ghidra/11.4-20250620/ghidra_11.4_PUBLIC
GHIDRA_PROJECTS ?= scratch/ghidra-projects

build:
	go build -o $(BINARY) ./cmd/aotopsy

test:
	go test ./...

fuzz:
	go test -fuzz=FuzzELFOpen -fuzztime=30s ./internal/elfx/
	go test -fuzz=FuzzExtract -fuzztime=30s ./internal/snapshot/

boot:
	@echo "CLAUDE=$$(shasum -a 256 CLAUDE.md | cut -c1-8)"
	@test -f br/BR-C.md && echo "BR-C=$$(shasum -a 256 br/BR-C.md | cut -c1-8)" || echo "BR-C=NA"
	@test -f br/BR-L.md && echo "BR-L=$$(shasum -a 256 br/BR-L.md | cut -c1-8)" || echo "BR-L=NA"

scan: build
	./$(BINARY) scan --libapp $(SAMPLE)

scan-json: build
	./$(BINARY) scan --libapp $(SAMPLE) --json

disasm: build
	./$(BINARY) disasm --libapp $(SAMPLE) --out $(OUT_DIR)

render: build
	./$(BINARY) render --in $(OUT_DIR) --no-dot
	@echo "render output: $(OUT_DIR)/render/"

render-svg: build
	./$(BINARY) render --in $(OUT_DIR) --max-nodes 100
	@echo "render output: $(OUT_DIR)/render/"

report: disasm render
	@echo "report complete: $(OUT_DIR)/"

flutter-meta: build
	./$(BINARY) flutter-meta --in $(OUT_DIR)

SCRIPT_DIR ?= $(HOME)/.aotopsy/ghidra_scripts

ghidra: flutter-meta
	mkdir -p "$(GHIDRA_PROJECTS)"
	"$(GHIDRA_HOME)/support/analyzeHeadless" \
		"$(GHIDRA_PROJECTS)" aotopsy_$(SAMPLE_NAME) \
		-import $(SAMPLE) -overwrite \
		-scriptPath "$(SCRIPT_DIR)" \
		-preScript aotopsy_prescript.py \
		-postScript aotopsy_apply.py "$(CURDIR)/$(OUT_DIR)/flutter_meta.json" "$(CURDIR)/$(OUT_DIR)/decompiled" \
		2>&1 | tee $(OUT_DIR)/ghidra_apply.log

inventory: build
	mkdir -p out
	./$(BINARY) inventory --dir samples/flutter --out out/flutter_inventory.jsonl

parity: build
	mkdir -p out/parity
	./$(BINARY) parity --samples scratch/samples --out out/parity

install: build
	install -d ~/.aotopsy/bin
	install -d ~/.aotopsy/ghidra_scripts
	install -d ~/.aotopsy/ida_scripts
	install -m 755 $(BINARY) ~/.aotopsy/bin/$(BINARY)
	install -m 644 ghidra_scripts/*.py ~/.aotopsy/ghidra_scripts/
	install -m 644 ida_scripts/*.py ~/.aotopsy/ida_scripts/
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
	go clean ./...

skills:
	@echo "Available skills:"
	@ls -1 .claude/skills/ 2>/dev/null | while read d; do echo "  /$$d"; done || echo "  (none)"

bench: ## Regenerate BENCHMARK.md from the ground-truth symtab differential
	@bash scripts/gen_benchmark.sh BENCHMARK.md

coverage: ## Regenerate COVERAGE.md by parsing every local corpus sample
	@bash scripts/gen_coverage.sh COVERAGE.md
