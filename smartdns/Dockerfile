#
# Dockerfile for smartdns
#

FROM alpine:latest

ARG DL_URL="https://github.com/pymumu/smartdns/releases/download/Release34/smartdns.11.2021.08.07-1628.x86_64-linux-all.tar.gz"

RUN set -ex \
    && apk --update add --no-cache \
       ca-certificates \
    && wget $DL_URL \
    && tar zxvf smartdns.*.tar.gz \
    && mv smartdns/usr/sbin/smartdns /bin/smartdns \
    && mv smartdns/etc/smartdns/smartdns.conf /etc/smartdns.conf \
    && rm -rf smartdns* \
    && rm -rf /var/cache/apk

COPY docker-entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

WORKDIR /smartdns

ENTRYPOINT ["/entrypoint.sh"]