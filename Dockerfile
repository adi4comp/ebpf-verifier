FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt update
RUN apt -yq --no-install-suggests --no-install-recommends install nano build-essential cmake \
    libboost-dev libboost-filesystem-dev libboost-program-options-dev libyaml-cpp-dev git \
    ca-certificates clang llvm linux-tools-6.10.0-linuxkit linux-tools-linuxkit libelf-dev linux-tools-generic libbpf-dev

WORKDIR /verifier
COPY . /verifier/
RUN mkdir build
WORKDIR /verifier/build
RUN cp -r /usr/include/asm-generic /usr/include/asm
RUN cmake .. -DCMAKE_BUILD_TYPE=Release
RUN make -j $(nproc)
WORKDIR /verifier
# ENTRYPOINT ["./check"]
