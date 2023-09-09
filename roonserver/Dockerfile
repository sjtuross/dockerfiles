FROM debian:11-slim

RUN apt-get update \
        && apt-get -y upgrade \
        && apt-get -y install bash curl bzip2 ffmpeg cifs-utils alsa-utils libicu67

ENV ROON_DATAROOT /data
ENV ROON_ID_DIR /data

VOLUME [ "/app", "/data", "/music", "/backup" ]

COPY RoonServerLegacy_linuxx64.tar.bz2 run.sh /

ENTRYPOINT /run.sh
