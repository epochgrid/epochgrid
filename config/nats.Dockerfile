FROM scratch
COPY nats-server /nats-server
COPY LICENSE /LICENSE
USER 65532:65532
ENTRYPOINT ["/nats-server"]
CMD ["-c", "/etc/nats/nats.conf"]
