.PHONY: build typecheck lint test format clean fuzz

PNPM ?= pnpm
NODE ?= node
RUN_PARALLEL ?= ../scripts/run-parallel
PRETTIER ?= ../node_modules/.bin/prettier

UNIT_TESTS := $(filter-out $(wildcard test/*.integration.test.ts),$(wildcard test/*.test.ts))
INTEGRATION_TESTS := $(wildcard test/*.integration.test.ts)

# Host fuzzer target name (see host/fuzz/targets)
TARGET ?= virtio

build:
	@$(PNPM) run build

typecheck:
	@$(PNPM) exec tsc -p tsconfig.json --noEmit

lint: typecheck

format:
	@$(PRETTIER) --write --ignore-unknown --no-error-on-unmatched-pattern \
		"src/**/*.ts" \
		"bin/**/*.ts" \
		"test/**/*.ts" \
		"fuzz/**/*.ts" \
		"examples/**/*.ts" \
		"package.json" \
		"tsconfig.json" \
		"README.md"

test:
	@$(NODE) --test $(UNIT_TESTS)
	@$(NODE) --test --test-concurrency=1 $(INTEGRATION_TESTS)

fuzz:
	@$(PNPM) run fuzz -- $(TARGET)

clean:
	@rm -rf dist
