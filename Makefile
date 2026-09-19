.PHONY: build test rpm clean

BINARY := keyfence
BUILD_DIR := ./bin
VERSION := $(shell awk '/^Version:/ {print $$2}' releng/keyfence.spec)
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS ?= -X main.version=$(VERSION) -X main.buildDate=$(BUILD_DATE)

build:
	go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY) ./cmd/keyfence

test:
	./scripts/test.sh

# An RPM without tagging a release. The tarball is assembled from the working
# tree, so this builds what is checked out rather than what was last published.
#
# BuildRequires names the golang package; a Go installed some other way (a
# tarball, a homebrew) satisfies the build but not rpm's database, so the
# dependency check is skipped when that is the situation rather than failing on
# a toolchain that is plainly there.
rpm:
	@command -v rpmbuild >/dev/null || { echo "rpmbuild is not installed: dnf install rpm-build rpmdevtools"; exit 1; }
	rm -rf build/rpm build/src
	mkdir -p build/rpm/SOURCES build/rpm/SPECS build/src/keyfence-$(VERSION)
	tar --exclude=.git --exclude=bin --exclude=build --exclude=.beads -cf - . \
	  | tar -xf - -C build/src/keyfence-$(VERSION)
	tar -czf build/rpm/SOURCES/keyfence-$(VERSION).tar.gz -C build/src keyfence-$(VERSION)
	cp releng/keyfence.spec build/rpm/SPECS/
	@rpm -q golang >/dev/null 2>&1 || echo "note: golang is not installed as a package; skipping the dependency check"
	rpmbuild --define "_topdir $(CURDIR)/build/rpm" \
	  $$(rpm -q golang >/dev/null 2>&1 || echo --nodeps) \
	  -bb build/rpm/SPECS/keyfence.spec
	@echo
	@echo "built: $$(ls $(CURDIR)/build/rpm/RPMS/*/*.rpm)"

clean:
	rm -rf $(BUILD_DIR) build
