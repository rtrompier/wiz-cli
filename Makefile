.PHONY: build release test clean

VERSION ?= $(shell grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
REPO := rtrompier/wiz-cli

build:
	cargo build --release

test:
	cargo test

clean:
	cargo clean

release:
	@if [ -z "$(VERSION)" ]; then echo "Could not determine version"; exit 1; fi
	@if git rev-parse "v$(VERSION)" >/dev/null 2>&1; then echo "Tag v$(VERSION) already exists"; exit 1; fi
	@echo "=== Preparing release v$(VERSION) ==="
	@sed -i '' 's/^version = ".*"/version = "$(VERSION)"/' Cargo.toml
	@cargo generate-lockfile
	@git add -A
	@git commit -m "chore: release v$(VERSION)" || true
	@git tag "v$(VERSION)"
	@git push
	@git push --tags
	@echo ""
	@echo "=== Waiting for GitHub Actions to build release ==="
	@sleep 10
	@RUN_ID=$$(gh run list -R $(REPO) --branch v$(VERSION) --limit 1 --json databaseId -q '.[0].databaseId') && \
		echo "Watching workflow run $$RUN_ID..." && \
		gh run watch $$RUN_ID -R $(REPO) --exit-status || (echo "Release build failed!" && exit 1)
	@echo ""
	@echo "=== Release v$(VERSION) complete! ==="
