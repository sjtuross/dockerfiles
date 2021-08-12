FROM arm64v8/debian:stretch-slim

WORKDIR /home

ARG VERSION=Release34

RUN apt-get update \
    && apt-get install wget -y \
    && cd /home \
    && wget --no-check-certificate https://github.com/pymumu/smartdns/releases/download/${VERSION}/smartdns-arm \
    && chmod +x smartdns-arm \
    && mkdir config

ADD smartdns.conf /home/config/smartdns.conf
ADD start.sh /home/start.sh

RUN chmod +x start.sh

CMD ["/home/start.sh"]