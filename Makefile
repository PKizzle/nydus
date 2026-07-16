all: release

all-build: build contrib-build

all-release: release contrib-release

all-static-release: static-release docker-static contrib-release

all-install: install contrib-install

all-clean: clean contrib-clean

TEST_WORKDIR_PREFIX ?= "/tmp"
INSTALL_DIR_PREFIX ?= "/usr/local/bin"
DOCKER ?= "true"

CARGO ?= $(shell which cargo)
RUSTUP ?= $(shell which rustup)
CARGO_BUILD_GEARS = -v ~/.ssh/id_rsa:/root/.ssh/id_rsa -v ~/.cargo/git:/root/.cargo/git -v ~/.cargo/registry:/root/.cargo/registry
SUDO = $(shell which sudo)
CARGO_COMMON ?=

EXCLUDE_PACKAGES =
UNAME_M := $(shell uname -m)
UNAME_S := $(shell uname -s)
STATIC_TARGET = $(UNAME_M)-unknown-linux-musl
ifeq ($(UNAME_S),Linux)
	CARGO_COMMON += --features=virtiofs,block-uffd,block-nbd
ifeq ($(UNAME_M),ppc64le)
	STATIC_TARGET = powerpc64le-unknown-linux-gnu
endif
ifeq ($(UNAME_M),riscv64)
	STATIC_TARGET = riscv64gc-unknown-linux-gnu
endif
endif
ifeq ($(UNAME_S),Darwin)
	EXCLUDE_PACKAGES += --exclude nydus-blobfs
ifeq ($(UNAME_M),amd64)
	STATIC_TARGET = x86_64-apple-darwin
endif
ifeq ($(UNAME_M),arm64)
	STATIC_TARGET = aarch64-apple-darwin
endif
endif
RUST_TARGET_STATIC ?= $(STATIC_TARGET)

# `migrate` (the bbolt->fjall legacy migration + the nydus-migrate tool) is a
# DEFAULT snapshotter feature on every architecture: third_party/bbolt-rs pins
# `aligners = { default-features = false }`, so the old SIMD-only-on-x86 build
# break on ppc64le/riscv64 is gone and no per-arch feature gating is needed.

# Extra opt-in cargo features to fold into the build. Used by the Dragonfly e2e
# job to enable backend-dragonfly-proxy, which is excluded from the default build
# (it pulls dragonfly-client-util -> OpenSSL/tokio and blocks the musl-static
# build) but is required to exercise the Dragonfly proxy error-handling path.
# Build on a glibc target, e.g. `make release EXTRA_FEATURES=backend-dragonfly-proxy`.
ifneq ($(EXTRA_FEATURES),)
	CARGO_COMMON += --features=$(EXTRA_FEATURES)
endif

# --- Relocate the build directory for checkouts whose path contains spaces ---
# OpenSSL's vendored build (the openssl-src crate, pulled in by `static-release`)
# runs perl `Configure` and `make` inside Cargo's OUT_DIR, which lives under the
# target directory. OpenSSL cannot be configured/built from a path containing a
# space, so a checkout under e.g. ".../Source Code/nydus" makes vendored builds
# fail with "cp: ... Not a directory". When the repo path contains a space (and
# the caller has not already chosen a target dir), relocate Cargo's target dir to
# a space-free, checkout-specific location so the vendored OpenSSL build succeeds.
# Only the build *output* moves; the sources stay in place.
empty :=
space := $(empty) $(empty)
ifeq ($(CARGO_TARGET_DIR),)
ifneq ($(findstring $(space),$(CURDIR)),)
export CARGO_TARGET_DIR := /tmp/nydus-build-$(shell echo '$(CURDIR)' | cksum | cut -d' ' -f1)/target
$(info Makefile: repo path contains spaces; relocating CARGO_TARGET_DIR to $(CARGO_TARGET_DIR))
endif
endif
TARGET_DIR := $(if $(CARGO_TARGET_DIR),$(CARGO_TARGET_DIR),$(CURDIR)/target)

LLVM_PROFILE_FILE := $(PWD)/coverage/nydus-%p-%m.profraw
DEBUG_BINARY_DIR := $(TARGET_DIR)/debug/
GRCOV_ARGS := --binary-path ${DEBUG_BINARY_DIR} -s . \
	      --branch --ignore-not-existing \
	      --ignore '*/.rustup/*' --ignore '*/rustup/*' \
	      --ignore '*/.cargo/*' --ignore '*/cargo/*'
CARGO_COV_FLAGS :=

# define ENABLE_DEBUG to disable release optimization and trace code coverage
ifdef ENABLE_DEBUG
$(eval CARGO_COV_FLAGS += NYDUS_NYDUSD_latest=${DEBUG_BINARY_DIR}/nydusd )
$(eval CARGO_COV_FLAGS += NYDUS_BUILDER_latest=${DEBUG_BINARY_DIR}/nydus-image )
$(eval CARGO_COV_FLAGS += RUSTFLAGS='-C instrument-coverage')
$(eval CARGO_COV_FLAGS += TEST_WORKDIR_PREFIX=$(TEST_WORKDIR_PREFIX) )
$(eval CARGO_COV_FLAGS += LLVM_PROFILE_FILE=$(LLVM_PROFILE_FILE) )
else
$(eval CARGO_BUILD_FLAGS += --release)
endif

current_dir := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
env_go_path := $(shell go env GOPATH 2> /dev/null)
go_path := $(if $(env_go_path),$(env_go_path),"$(HOME)/go")
go_work_version := $(shell grep '^go ' go.work | awk '{print $$2}')

# Functions

# Func: build golang target in docker
# Args:
#   $(1): The path where go build a golang project
#   $(2): How to build the golang project
define build_golang
	echo "Building target $@ by invoking: $(2)"
	if [ $(DOCKER) = "true" ]; then \
		docker run --rm -v ${go_path}:/go -v ${current_dir}:/nydus-rs --workdir /nydus-rs/$(1) golang:${go_work_version} \
			sh -c "git config --global --add safe.directory /nydus-rs && $(2)" ;\
	else \
		$(2) -C $(1); \
	fi
endef

.PHONY: .format .musl_target .clean_libz_sys \
	all all-build all-release all-static-release build release static-release

.format:
	${CARGO} fmt -- --check

.musl_target:
	$(eval CARGO_BUILD_FLAGS += --target ${RUST_TARGET_STATIC})

# Workaround to clean up stale cache for libz-sys
.clean_libz_sys:
	@${CARGO} clean --target ${RUST_TARGET_STATIC} -p libz-sys
	@${CARGO} clean --target ${RUST_TARGET_STATIC} --release -p libz-sys

prepare-codecov:
	${CARGO} install grcov --locked
	${RUSTUP} component add llvm-tools-preview

# Targets that are exposed to developers and users.
build: .format
	$(CARGO_COV_FLAGS) ${CARGO} build --workspace $(EXCLUDE_PACKAGES) $(CARGO_COMMON) $(CARGO_BUILD_FLAGS)
	# Cargo will skip checking if it is already checked
	${CARGO} clippy --workspace $(EXCLUDE_PACKAGES) $(CARGO_COMMON) $(CARGO_BUILD_FLAGS) --bins --tests -- -Dwarnings --allow clippy::unnecessary_cast --allow clippy::needless_borrow --allow clippy::result_large_err --allow clippy::manual_is_multiple_of --allow clippy::io_other_error

release: .format build

static-release: .clean_libz_sys .musl_target .format build

clean:
	[ -d coverage ] && rm -rf coverage || true
	${CARGO} clean

install: release
	@sudo mkdir -m 755 -p $(INSTALL_DIR_PREFIX)
	@sudo install -m 755 target/release/nydusd $(INSTALL_DIR_PREFIX)/nydusd
	@sudo install -m 755 target/release/nydus-image $(INSTALL_DIR_PREFIX)/nydus-image
	@sudo install -m 755 target/release/nydusctl $(INSTALL_DIR_PREFIX)/nydusctl

# unit test
ut:
	$(CARGO_COV_FLAGS) TEST_WORKDIR_PREFIX=$(TEST_WORKDIR_PREFIX) RUST_BACKTRACE=1 ${CARGO} test --no-fail-fast --workspace $(EXCLUDE_PACKAGES) $(CARGO_COMMON) $(CARGO_BUILD_FLAGS) -- --skip integration --nocapture --test-threads=8

# you need install cargo nextest first from: https://nexte.st/book/pre-built-binaries.html
ut-nextest:
	$(CARGO_COV_FLAGS) TEST_WORKDIR_PREFIX=$(TEST_WORKDIR_PREFIX) RUST_BACKTRACE=1 ${RUSTUP} run stable cargo nextest run --no-fail-fast --filter-expr 'test(test) - test(integration)' --workspace $(EXCLUDE_PACKAGES) $(CARGO_COMMON) $(CARGO_BUILD_FLAGS)

# install miri first from https://github.com/rust-lang/miri/
# nydus-snapshotter is excluded from Miri: it links compio (io_uring) + mimalloc
# and is FFI/syscall-heavy, which Miri cannot execute.
miri-ut-nextest:
	$(CARGO_COV_FLAGS) MIRIFLAGS=-Zmiri-disable-isolation TEST_WORKDIR_PREFIX=$(TEST_WORKDIR_PREFIX) RUST_BACKTRACE=1 ${RUSTUP} run nightly cargo miri nextest run --no-fail-fast --filter-expr 'test(test) - test(integration) - test(deduplicate::tests) - test(inode_bitmap::tests::test_inode_bitmap)' --workspace $(EXCLUDE_PACKAGES) --exclude nydus-snapshotter $(CARGO_COMMON) $(CARGO_BUILD_FLAGS)

smoke-only:
	CARGO_COV_FLAGS="$(CARGO_COV_FLAGS)" make -C smoke test

smoke-performance:
	CARGO_COV_FLAGS="$(CARGO_COV_FLAGS)" make -C smoke test-performance

smoke-benchmark:
	CARGO_COV_FLAGS="$(CARGO_COV_FLAGS)" make -C smoke test-benchmark

smoke-takeover:
	CARGO_COV_FLAGS=$(CARGO_COV_FLAGS) make -C smoke test-takeover

smoke: release smoke-only

generate-codecov-markdown: prepare-codecov
	grcov $(dir ${LLVM_PROFILE_FILE})/*.profraw -t markdown $(GRCOV_ARGS) --output-path coverage/coverage.md

generate-codecov: prepare-codecov
	grcov $(dir ${LLVM_PROFILE_FILE})/*.profraw -t lcov $(GRCOV_ARGS) --output-path coverage/coverage.info

# write unit teset coverage to codecov.json, used for Github CI
coverage-codecov:
	TEST_WORKDIR_PREFIX=$(TEST_WORKDIR_PREFIX) ${RUSTUP} run stable cargo llvm-cov --codecov --output-path codecov.json --workspace $(EXCLUDE_PACKAGES) $(CARGO_COMMON) $(CARGO_BUILD_FLAGS) -- --skip integration --nocapture --test-threads=8


# The Go contrib tools (contrib/nydusify, contrib/nydus-overlayfs) were removed;
# nydusify is now the Rust workspace crate `nydusify/`. The contrib-* target names
# are kept because CI workflows call them, but they now cover only the Rust
# nydusify build (contrib/nydus-backend-proxy is opt-in and unaffected).
contrib-build: nydusify

contrib-release: nydusify-release

contrib-test: nydusify-test

contrib-lint: nydusify-lint

contrib-clean: nydusify-clean

contrib-install: nydusify-release
	@sudo mkdir -m 755 -p $(INSTALL_DIR_PREFIX)
	@sudo install -m 755 $(TARGET_DIR)/release/nydusify $(INSTALL_DIR_PREFIX)/nydusify

nydusify:
	${CARGO} build -p nydusify

nydusify-release:
	${CARGO} build --release -p nydusify

nydusify-test:
	${CARGO} test -p nydusify

nydusify-clean:
	${CARGO} clean -p nydusify

nydusify-lint:
	${CARGO} clippy -p nydusify --all-targets -- -D warnings

docker-static:
	docker build -t nydus-rs-static --build-arg RUST_TARGET=${RUST_TARGET_STATIC} misc/musl-static
	docker run --rm ${CARGO_BUILD_GEARS} -e RUST_TARGET=${RUST_TARGET_STATIC} --workdir /nydus-rs -v ${current_dir}:/nydus-rs nydus-rs-static
