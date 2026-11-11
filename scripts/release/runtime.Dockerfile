# Runtime only: the build context is assembled from a verified Linux bundle.
FROM ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libgcc-s1 \
    && mkdir -p /usr/share/epochgrid \
    && dpkg-query -W -f='${Package}=${Version}\n' > /usr/share/epochgrid/os-packages.txt \
    && rm -rf /var/lib/apt/lists/*
COPY bin/ /usr/local/bin/
COPY BUILD.json LICENSE THIRD_PARTY_NOTICES README.md /usr/share/epochgrid/
ENV EPOCHGRID_PROFILE=production
ENV HOME=/state
USER 65532:65532
WORKDIR /state
STOPSIGNAL SIGINT
ENTRYPOINT ["/usr/local/bin/epochgrid-service"]
CMD ["--help"]
