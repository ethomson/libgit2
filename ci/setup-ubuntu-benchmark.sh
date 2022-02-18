#!/bin/sh

set -x

sudo apt-get update
sudo apt-get install -y --no-recommends \
	cargo \
        cmake \
        gcc \
        git \
        krb5-user \
        libkrb5-dev \
        libssl-dev \
        libz-dev \
        make \
        ninja-build \
        pkgconf
cargo install hyperfine
