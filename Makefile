.PHONY: build
build:
	go build -trimpath -o bin/pleno-dlp ./cmd/pleno-dlp

# Opt-in in-process privacy-filter.cpp engine; requires cgo and CMake.
.PHONY: opf-native-deps opf-native-lib opf-native-build opf-native-test opf-native-clean

OPF_NATIVE_SRC := build/opf-native
OPF_NATIVE_CDEPS := pkg/piiengine/opfnative/cdeps
OPF_NATIVE_LDFLAGS ?=

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
	CGO_ENABLED=1 go build -trimpath -tags opf_native $(if $(OPF_NATIVE_LDFLAGS),-ldflags "$(OPF_NATIVE_LDFLAGS)") -o bin/pleno-dlp-opf ./cmd/pleno-dlp

opf-native-test: opf-native-lib
	CGO_ENABLED=1 go vet -tags=opf_native ./...
	CGO_ENABLED=1 go run honnef.co/go/tools/cmd/staticcheck@2025.1.1 -tags=opf_native ./...
	CGO_ENABLED=1 go test -race -tags "opf_native,detector_unit" ./... -count=1 -timeout 15m

opf-native-clean:
	rm -rf $(OPF_NATIVE_SRC) $(OPF_NATIVE_CDEPS) bin/pleno-dlp-opf
