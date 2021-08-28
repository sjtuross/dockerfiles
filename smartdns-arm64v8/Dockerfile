FROM arm64v8/debian:buster-slim

WORKDIR /home

ARG VERSION=Release35

RUN apt-get update \
    && apt-get install wget -y \
    && cd /home \
    && wget --no-check-certificate https://github.com/pymumu/smartdns/releases/download/${VERSION}/smartdns-arm \
    && chmod +x smartdns-arm \
    && mkdir config

ADD smartdns.conf /home/config/smartdns.conf
ADD start.sh /home/start.sh

RUN chmod +x start.sh

EXPOSE 53

CMD ["/home/start.sh"]