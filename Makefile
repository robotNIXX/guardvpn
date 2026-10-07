VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
PKG     := github.com/robotNIXX/guardvpn
LDFLAGS := -s -w -X $(PKG)/internal/version.Version=$(VERSION) -X $(PKG)/internal/version.Commit=$(COMMIT)
CMD     := ./cmd/vpn-guard

.PHONY: all darwin windows test vet dist clean

all: test darwin windows

# macOS needs cgo (IOKit, Security, libproc): build on a Mac.
# Produces a universal (arm64 + x86_64) binary.
darwin:
	mkdir -p bin/darwin
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 CC="clang -arch arm64" \
		go build -trimpath -ldflags '$(LDFLAGS)' -o bin/darwin/vpn-guard-arm64 $(CMD)
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 CC="clang -arch x86_64" \
		go build -trimpath -ldflags '$(LDFLAGS)' -o bin/darwin/vpn-guard-amd64 $(CMD)
	lipo -create -output bin/darwin/vpn-guard bin/darwin/vpn-guard-arm64 bin/darwin/vpn-guard-amd64
	rm bin/darwin/vpn-guard-arm64 bin/darwin/vpn-guard-amd64

# Windows is pure Go: cross-compiles from any OS.
windows:
	for arch in amd64 arm64; do \
		mkdir -p bin/windows-$$arch; \
		CGO_ENABLED=0 GOOS=windows GOARCH=$$arch \
			go build -trimpath -ldflags '$(LDFLAGS)' -o bin/windows-$$arch/vpn-guard.exe $(CMD) || exit 1; \
	done

test:
	go test ./...

vet:
	go vet ./...
	GOOS=windows go vet ./...

# Self-contained install bundles.
dist: darwin windows
	rm -rf dist && mkdir -p dist/vpn-guard-macos dist/vpn-guard-windows-amd64 dist/vpn-guard-windows-arm64
	cp bin/darwin/vpn-guard scripts/darwin/*.sh deploy/darwin/com.vpnguard.daemon.plist config.example.json dist/vpn-guard-macos/
	for arch in amd64 arm64; do \
		cp bin/windows-$$arch/vpn-guard.exe scripts/windows/*.ps1 config.example.json dist/vpn-guard-windows-$$arch/; \
	done
	cd dist && for d in */; do zip -qr "$${d%/}-$(VERSION).zip" "$$d"; done

clean:
	rm -rf bin dist
