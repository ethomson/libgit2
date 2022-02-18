#!/bin/sh

set -ex

sudo apt-get update
sudo apt-get install -y --no-install-recommends \
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
krb5-config --vendor
krb5-config --libs-gssapi
cargo install hyperfine
