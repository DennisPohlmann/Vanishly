# Vanishly - package and container image.

# Version: a v* git tag on HEAD, otherwise the VERSION file.
VERSION ?= $(shell git describe --tags --exact-match --match 'v*' 2>/dev/null | sed 's/^v//' || true)
ifeq ($(VERSION),)
VERSION := $(shell cat VERSION)
endif
PKG     := vanishly-$(VERSION)
IMAGE   ?= vanishly

.PHONY: check vendor package image up clean

check:
	npm ci
	npm run vendor
	npm run lint
	npm test

# vendor/scalar.js for the API reference page, from the development packages.
vendor:
	test -d node_modules/@scalar/api-reference || npm ci --ignore-scripts
	npm run vendor

# dist/vanishly-<version>.tar.gz unpacks to /opt/vanishly, the systemd unit
# and the example settings. Pure JavaScript: one archive for every CPU.
package: vendor
	rm -rf dist/root && mkdir -p dist/root/opt/vanishly dist/root/etc/systemd/system dist/root/etc/vanishly
	cp -r package.json package-lock.json VERSION LICENSE THIRD-PARTY-LICENSES.md \
	  src public views translations openapi templates vendor dist/root/opt/vanishly/
	cd dist/root/opt/vanishly && npm ci --omit=dev --ignore-scripts && rm -f package-lock.json
	cp packaging/vanishly.service dist/root/etc/systemd/system/
	cp .env.example dist/root/etc/vanishly/vanishly.env
	tar -C dist/root --owner=0 --group=0 -czf dist/$(PKG).tar.gz .
	cd dist && sha256sum $(PKG).tar.gz > $(PKG).tar.gz.sha256

# Local container image, tagged with the version.
image:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) .

# App and Redis, built from this folder.
up:
	docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build

clean:
	rm -rf dist
