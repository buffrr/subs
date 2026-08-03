# GPU image for subs-prover, built with risc0 CUDA acceleration.
#
# Built from the surrounding checkout, so the image always matches the commit
# it was built from. Build context is the repo root:
#
#   docker build -t ghcr.io/spacesprotocol/subs-prover-gpu:latest -f prover/Dockerfile .
#
# Push to a registry the GPU host can pull from. CI does this automatically —
# see .github/workflows/prover-image.yml.

# ----- Builder stage -----------------------------------------------------
FROM nvidia/cuda:12.4.0-devel-ubuntu22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive \
    CARGO_TERM_COLOR=always \
    PATH="/root/.cargo/bin:/root/.risc0/bin:${PATH}"

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        git \
        libssl-dev \
        pkg-config \
        clang \
        protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Rustup with no default toolchain; the repo's rust-toolchain.toml decides.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain none --profile minimal

WORKDIR /build

# Materialize the toolchain from rust-toolchain.toml before anything slow, so a
# toolchain change busts this layer rather than the compile layer below. This
# also has to precede rzup: rustup was installed with no default toolchain, so
# until a rust-toolchain.toml is in scope, any cargo/rustc shim call fails.
COPY rust-toolchain.toml ./
RUN rustc --version && cargo --version

# risc0 toolchain for guest-program build scripts in libveritas. Pin via
# RISC0_VERSION for reproducible builds; empty means "latest".
#
# risc0-groth16 is installed explicitly: `subs-prover compress` runs
# ProverOpts::groth16(), so without that component the binary builds fine and
# then fails at runtime on the pod. Bare `rzup install` happens to include it,
# but the pinned branch below would not.
ARG RISC0_VERSION=
RUN curl -L https://risczero.com/install | bash \
    && if [ -n "${RISC0_VERSION}" ]; then \
           rzup install rust "${RISC0_VERSION}" && rzup install cpp; \
       else \
           rzup install; \
       fi \
    && rzup install risc0-groth16

# Target GPU architectures for the risc0 CUDA kernels.
#
# risc0's build scripts hardcode `-arch=native`, which asks nvcc to detect the
# local GPU. Build machines have none, so nvcc falls back to a default below
# sm_60 and the compile dies on "CUDA atomics are only supported for sm_60 and
# up". Those scripts skip `-arch=native` when NVCC_PREPEND_FLAGS is set, so
# setting it is both how the arch gets chosen and how the broken default is
# avoided.
#
# The default builds SASS for sm_80 (A100) plus compute_80 PTX, which the
# driver JITs onto anything newer — RTX 4090 / L40S (sm_89) and H100 / H200
# (sm_90) all run from it. That keeps this to one SASS target: each additional
# one recompiles every kernel, and these kernels dominate the build.
#
# The cost is a one-off JIT pause the first time a non-A100 pod starts. Add an
# explicit gencode for a card you run constantly to skip it, e.g.
#   --build-arg CUDA_ARCHS="-gencode arch=compute_90,code=sm_90 -gencode arch=compute_80,code=compute_80"
ARG CUDA_ARCHS="-gencode arch=compute_80,code=sm_80 -gencode arch=compute_80,code=compute_80"
ENV NVCC_PREPEND_FLAGS="${CUDA_ARCHS}"

# Cargo needs every workspace member present to resolve the manifest, even
# though subs-prover only depends on types/. git stays installed above because
# the workspace pulls certrelay and spaces_testutil as git dependencies.
# See .dockerignore for exclusions.
COPY . .

# --locked so the committed Cargo.lock is enforced rather than merely
# preferred; without it the image can silently resolve different versions than
# the commit it claims to be built from.
RUN cargo build --locked --release -p subs-prover --features cuda --bin subs-prover

# ----- Runtime stage -----------------------------------------------------
#
# `base`, not `runtime`: the binary's only CUDA dependency is libcuda.so.1,
# which the NVIDIA container runtime injects from the host driver and which no
# CUDA image ships. risc0/sppark compile their own kernels and use the driver
# API, so nothing links cudart, cuBLAS, cuFFT, cuSPARSE, cuSOLVER or NCCL —
# the entire ~1.3 GB of math libraries in `runtime` was unused. `base` still
# sets NVIDIA_VISIBLE_DEVICES / NVIDIA_DRIVER_CAPABILITIES, which is what makes
# the runtime inject the driver, so it cannot be reduced to plain ubuntu.
#
# Verified by reading DT_NEEDED off the published amd64 binary:
#   ld-linux-x86-64.so.2  libc.so.6  libcuda.so.1
#   libgcc_s.so.1         libm.so.6  libstdc++.so.6
FROM nvidia/cuda:12.4.0-base-ubuntu22.04

ENV DEBIAN_FRONTEND=noninteractive

# libstdc++6 / libgcc-s1 are pulled in explicitly rather than relied on: they
# are the binary's remaining non-libc dependencies and `base` is thinner than
# `runtime`, so leaving them implicit is a needless bet.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
        libstdc++6 \
        libgcc-s1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/subs-prover /usr/local/bin/subs-prover

EXPOSE 8888

# subs-prover reads PROVER_AUTH_TOKEN at startup; when set, it enforces
# `Authorization: Bearer <token>` on all routes, /health included — a
# successful health probe doubles as an end-to-end auth check. Leaving it
# unset serves an unauthenticated prover, so always set it when the pod is
# publicly reachable.
ENV RUST_LOG=subs_prover=info,tower_http=info

ENTRYPOINT ["/usr/local/bin/subs-prover"]
CMD ["--server", "--server-port", "8888"]