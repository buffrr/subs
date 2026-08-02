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
ARG RISC0_VERSION=
RUN curl -L https://risczero.com/install | bash \
    && if [ -n "${RISC0_VERSION}" ]; then \
           rzup install rust "${RISC0_VERSION}" && rzup install cpp; \
       else \
           rzup install; \
       fi

# Cargo needs every workspace member present to resolve the manifest, even
# though subs-prover only depends on types/. git stays installed above because
# the workspace pulls certrelay and spaces_testutil as git dependencies.
# See .dockerignore for exclusions.
COPY . .

RUN cargo build --release -p subs-prover --features cuda --bin subs-prover

# ----- Runtime stage -----------------------------------------------------
FROM nvidia/cuda:12.4.0-runtime-ubuntu22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
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