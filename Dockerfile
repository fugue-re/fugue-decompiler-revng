FROM rust:trixie

SHELL ["/bin/bash", "-c"]

RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends \
      cmake ninja-build clang clang-format \
      libc++-dev libc++abi-dev libclang-rt-19-dev \
      python3 python3-venv python3-dev \
      libboost-all-dev libarchive-dev libzstd-dev libsqlite3-dev \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*

ENV REVNG_BUILD_CACHE=/opt/revng-cache

WORKDIR /work
COPY . .

RUN cargo build --bin revng-fugue

RUN printf '\x89\x37\x89\x57\x08\xc7\x47\x10\x00\x00\x00\x00\xc3' > /tmp/stub.bin \
 && /work/target/debug/revng-fugue --raw --base 0x1000 --arch x86_64 -a 0x1000 /tmp/stub.bin \
      > /tmp/decompiled.c \
 && cat /tmp/decompiled.c \
 && grep -q 'offset_0 = ' /tmp/decompiled.c \
 && grep -q 'offset_8 = ' /tmp/decompiled.c \
 && grep -q 'offset_16 = ' /tmp/decompiled.c

ENTRYPOINT ["/work/target/debug/revng-fugue"]
