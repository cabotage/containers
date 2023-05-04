FROM registry:2.8.1

COPY custom-entrypoint.sh /custom-entrypoint.sh
ENTRYPOINT ["/custom-entrypoint.sh"]

CMD ["/etc/docker/registry/config.yml"]
