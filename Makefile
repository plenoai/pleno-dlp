# dlp-bench (issue #298): reproduces docs/comparison.md's methodology as
# a runnable target instead of a frozen snapshot. See bench/README.md.
#
# `make bench` is the one command a third party needs; the finer-grained
# targets exist so CI can cache the tool-download step separately from
# the (network-dependent) leaky-repo clone.

.PHONY: bench bench-fixtures bench-tools bench-run bench-offline bench-clean bench-docsync

# Full reproduction: fresh fixtures, pinned tool binaries, live 3-tool
# re-run against both the synthetic and leaky-repo corpora.
bench: bench-fixtures bench-tools bench-run

# Generates the synthetic recall corpus fresh every run (bench/gen) —
# fixtures are never committed, see bench/README.md.
bench-fixtures:
	go run ./bench/gen -out bench/fixtures/synthetic/generated

# Downloads trufflehog + gitleaks at the versions pinned in
# bench/harness/tools.go (checksum-verified). Skipped automatically by
# the harness if both are already on $PATH.
bench-tools:
	bash bench/scripts/fetch-tools.sh

bench-run:
	go run ./bench/harness

# Offline variant: skips the leaky-repo clone (needs network) — useful
# for iterating on the synthetic corpus without a network round-trip.
bench-offline:
	go run ./bench/harness -skip-leaky-repo

bench-clean:
	rm -rf bench/fixtures/synthetic/generated bench/fixtures/synthetic/labels.json bench/.cache bench/.tools bench/results/*.json bench/results/*.md

# Regenerates docs/comparison.md's "Live re-measurement" box from
# bench/results/results.json (issue #299) — run after `make bench`.
# .github/workflows/comparison-refresh.yml is the automated caller;
# this target is the equivalent local reproduction step.
bench-docsync:
	go run ./bench/docsync -trigger "local run ($$(date -u +%Y-%m-%dT%H:%M:%SZ))"

# --- native openai-pf engine (opf_native, ADR-0005) -------------------------
# Opt-in cgo build of the in-process privacy-filter.cpp PII engine. None of
# these targets run on the default pure-Go (CGO_ENABLED=0) path — the default
# release and CI stay free of C sources and a cgo toolchain.
.PHONY: opf-native-deps opf-native-lib opf-native-build opf-native-test opf-native-clean

OPF_NATIVE_SRC := build/opf-native
OPF_NATIVE_CDEPS := pkg/piiengine/opfnative/cdeps

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
OPF_NATIVE_CMAKE_FLAGS := -DGGML_METAL_EMBED_LIBRARY=ON
else
OPF_NATIVE_CMAKE_FLAGS := -DGGML_OPENMP=OFF
endif

# fetch + SHA-verify the pinned C sources (fail-closed on mismatch).
opf-native-deps:
	bash scripts/opf-native/fetch-deps.sh

# cmake configure+build static libs, then install .a + pf.h into cdeps/.
opf-native-lib: opf-native-deps
	cmake -S $(OPF_NATIVE_SRC)/privacy-filter.cpp -B $(OPF_NATIVE_SRC)/build \
		-DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DGGML_NATIVE=OFF \
		$(OPF_NATIVE_CMAKE_FLAGS)
	cmake --build $(OPF_NATIVE_SRC)/build --config Release -j
	mkdir -p $(OPF_NATIVE_CDEPS)/lib $(OPF_NATIVE_CDEPS)/include
	find $(OPF_NATIVE_SRC)/build -name '*.a' -exec cp {} $(OPF_NATIVE_CDEPS)/lib/ \;
	cp $(OPF_NATIVE_SRC)/privacy-filter.cpp/include/pf.h $(OPF_NATIVE_CDEPS)/include/

opf-native-build: opf-native-lib
	CGO_ENABLED=1 go build -tags opf_native -o bin/pleno-dlp-opf ./cmd/pleno-dlp

opf-native-test:
	CGO_ENABLED=1 go test -race -tags "opf_native,detector_unit" ./pkg/piiengine/opfnative/... ./pkg/detectors/openaipf/...

opf-native-clean:
	rm -rf $(OPF_NATIVE_SRC) $(OPF_NATIVE_CDEPS) bin/pleno-dlp-opf
