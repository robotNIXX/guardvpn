VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
PKG     := github.com/robotNIXX/guardvpn
LDFLAGS := -s -w -X $(PKG)/internal/version.Version=$(VERSION) -X $(PKG)/internal/version.Commit=$(COMMIT)
DAEMON  := ./cmd/vpn-guard
AGENT   := ./cmd/vpn-guard-agent
APP     := bin/darwin/VPN Guard.app

# Minimum macOS for the cgo parts (compile and link must agree, otherwise
# clang targets the SDK version and ld warns on every object file).
MACOS_MIN := 11.0
export MACOSX_DEPLOYMENT_TARGET := $(MACOS_MIN)
CC_ARM64  := clang -arch arm64 -mmacosx-version-min=$(MACOS_MIN)
CC_AMD64  := clang -arch x86_64 -mmacosx-version-min=$(MACOS_MIN)

.PHONY: all darwin darwin-daemon darwin-agent windows test vet icons dist clean

all: test darwin windows

# ---- macOS (needs cgo: build on a Mac). Universal arm64 + x86_64. ----
darwin: darwin-daemon darwin-agent

darwin-daemon:
	mkdir -p bin/darwin
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 CC="$(CC_ARM64)" CGO_LDFLAGS="-mmacosx-version-min=$(MACOS_MIN)" \
		go build -trimpath -ldflags '$(LDFLAGS)' -o bin/darwin/vpn-guard-arm64 $(DAEMON)
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 CC="$(CC_AMD64)" CGO_LDFLAGS="-mmacosx-version-min=$(MACOS_MIN)" \
		go build -trimpath -ldflags '$(LDFLAGS)' -o bin/darwin/vpn-guard-amd64 $(DAEMON)
	lipo -create -output bin/darwin/vpn-guard bin/darwin/vpn-guard-arm64 bin/darwin/vpn-guard-amd64
	rm bin/darwin/vpn-guard-arm64 bin/darwin/vpn-guard-amd64

darwin-agent: icons
	mkdir -p bin/darwin
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 CC="$(CC_ARM64)" CGO_LDFLAGS="-mmacosx-version-min=$(MACOS_MIN)" \
		go build -tags production -trimpath -ldflags '$(LDFLAGS)' -o bin/darwin/vpn-guard-agent-arm64 $(AGENT)
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 CC="$(CC_AMD64)" CGO_LDFLAGS="-mmacosx-version-min=$(MACOS_MIN)" \
		go build -tags production -trimpath -ldflags '$(LDFLAGS)' -o bin/darwin/vpn-guard-agent-amd64 $(AGENT)
	rm -rf "$(APP)"
	mkdir -p "$(APP)/Contents/MacOS" "$(APP)/Contents/Resources"
	lipo -create -output "$(APP)/Contents/MacOS/vpn-guard-agent" bin/darwin/vpn-guard-agent-arm64 bin/darwin/vpn-guard-agent-amd64
	rm bin/darwin/vpn-guard-agent-arm64 bin/darwin/vpn-guard-agent-amd64
	sed 's/__VERSION__/$(VERSION)/g' deploy/darwin/Info.plist > "$(APP)/Contents/Info.plist"
	cp build/AppIcon.icns "$(APP)/Contents/Resources/AppIcon.icns"
	codesign --force --sign - "$(APP)"

icons:
	go run ./tools/mkicon -iconset build/AppIcon.iconset -ico build/vpn-guard.ico
	iconutil -c icns build/AppIcon.iconset -o build/AppIcon.icns

# ---- Windows (pure Go: cross-compiles from any OS). ----
windows:
	for arch in amd64 arm64; do \
		mkdir -p bin/windows-$$arch; \
		CGO_ENABLED=0 GOOS=windows GOARCH=$$arch \
			go build -trimpath -ldflags '$(LDFLAGS)' -o bin/windows-$$arch/vpn-guard.exe $(DAEMON) || exit 1; \
		CGO_ENABLED=0 GOOS=windows GOARCH=$$arch \
			go build -tags production -trimpath -ldflags '$(LDFLAGS) -H windowsgui' -o bin/windows-$$arch/vpn-guard-agent.exe $(AGENT) || exit 1; \
	done

test:
	go test ./...

vet:
	go vet ./...
	GOOS=windows go vet ./...

# ---- Install bundles ----
dist: darwin windows
	rm -rf dist && mkdir -p dist/vpn-guard-macos dist/vpn-guard-windows-amd64 dist/vpn-guard-windows-arm64
	cp bin/darwin/vpn-guard scripts/darwin/*.sh deploy/darwin/com.vpnguard.daemon.plist \
		deploy/darwin/com.vpnguard.agent.plist config.example.json dist/vpn-guard-macos/
	cp -R "$(APP)" dist/vpn-guard-macos/
	for arch in amd64 arm64; do \
		cp bin/windows-$$arch/*.exe scripts/windows/*.ps1 config.example.json dist/vpn-guard-windows-$$arch/; \
	done
	cd dist && for d in */; do zip -qry "$${d%/}-$(VERSION).zip" "$$d"; done

clean:
	rm -rf bin dist build
