# Disposable verification environment, never a product/runtime image.
ARG UBUNTU_VERSION=26.04
FROM ubuntu:${UBUNTU_VERSION}
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 sudo dbus-daemon gnome-keyring libsecret-tools openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && (id ubuntu >/dev/null 2>&1 || useradd -m -u 1000 ubuntu) \
    && printf 'ubuntu ALL=(nobody) NOPASSWD: ALL\n' > /etc/sudoers.d/epochgrid-fixture
RUN printf 'ubuntu ALL=(daemon) NOPASSWD: ALL\n' > /etc/sudoers.d/epochgrid-diagnostics-fixture
USER ubuntu
WORKDIR /workspace
