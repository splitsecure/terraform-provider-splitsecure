VERSION := $(shell cat VERSION)

LDFLAGS := -X main.version=$(VERSION)

TERRAFORMRC := $(HOME)/.terraformrc
DEV_MARKER  := \# splitsecure-dev-override

.PHONY: build lint test docs check-docs clean install-dev uninstall-dev

build:
	go build -ldflags '$(LDFLAGS)' -o terraform-provider-splitsecure .

lint:
	golangci-lint run ./...

test:
	go test ./...

docs:
	go generate ./...

check-docs: docs
	@if [ -n "$$(git status --porcelain docs/)" ]; then \
		echo "docs/ is out of date. Run 'make docs' and commit." >&2; \
		git diff docs/ >&2; \
		exit 1; \
	fi

clean:
	rm -f terraform-provider-splitsecure

install-dev: build
	@if [ -f $(TERRAFORMRC) ] && ! grep -q '^$(DEV_MARKER)' $(TERRAFORMRC); then \
		echo "$(TERRAFORMRC) exists and is not managed by this Makefile." >&2; \
		echo "Back it up and re-run 'make install-dev'." >&2; \
		exit 1; \
	fi
	@printf '$(DEV_MARKER)\nprovider_installation {\n  dev_overrides {\n    "splitsecure/splitsecure" = "%s"\n  }\n  direct {}\n}\n' "$(CURDIR)" > $(TERRAFORMRC)
	@echo "Dev override installed in $(TERRAFORMRC)."
	@echo "All terraform invocations now use $(CURDIR)/terraform-provider-splitsecure."
	@echo "Run 'make uninstall-dev' to remove."

uninstall-dev:
	@if [ ! -f $(TERRAFORMRC) ]; then \
		echo "$(TERRAFORMRC) does not exist -- nothing to remove."; \
	elif grep -q '^$(DEV_MARKER)' $(TERRAFORMRC); then \
		rm $(TERRAFORMRC); \
		echo "Removed $(TERRAFORMRC)."; \
	else \
		echo "$(TERRAFORMRC) is not managed by this Makefile -- not touched." >&2; \
		exit 1; \
	fi
