VERSION := $(shell cat VERSION)

LDFLAGS := -X main.version=$(VERSION)

.PHONY: build lint test docs check-docs clean

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
