FROM registry:2.8.3

COPY custom-entrypoint.sh /custom-entrypoint.sh
ENTRYPOINT ["/custom-entrypoint.sh"]

CMD ["/etc/docker/registry/config.yml"]
