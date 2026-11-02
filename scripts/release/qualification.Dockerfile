# Disposable test environment; this is not the milestone 33 runtime image.
FROM ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852 AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 sudo dbus-daemon gnome-keyring libsecret-tools libglib2.0-bin openssl ca-certificates binutils \
    && rm -rf /var/lib/apt/lists/* \
    && printf 'ubuntu ALL=(nobody,daemon) NOPASSWD: ALL\n' > /etc/sudoers.d/epochgrid-fixture
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
USER ubuntu
WORKDIR /workspace

# Local baseline builds can mount the pinned Rust toolchain into /opt/rust.
FROM runtime AS builder
USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential perl git pkg-config \
    && rm -rf /var/lib/apt/lists/*
ENV PATH=/opt/rust/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
USER ubuntu
