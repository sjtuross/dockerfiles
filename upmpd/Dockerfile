FROM alpine:latest

RUN set -ex \
    && apk --no-cache add mpd --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing/ \
    && apk --no-cache add upmpdcli --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing/ \
    && mkdir /config \
	&& cp /etc/mpd.conf /config \
	&& cp /etc/upmpdcli.conf /config

VOLUME [ "/config" ]

COPY entrypoint.sh /

ENTRYPOINT /entrypoint.sh
