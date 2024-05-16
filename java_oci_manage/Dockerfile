FROM eclipse-temurin:17-jdk-jammy

ARG VERSION=4.9.8

WORKDIR /app

RUN wget -O gz_client_bot.tar.gz  https://github.com/semicons/java_oci_manage/releases/download/v${VERSION}/gz_client_bot.tar.gz \
  && tar -zxvf gz_client_bot.tar.gz --exclude=client_config \
  && tar -zxvf gz_client_bot.tar.gz --skip-old-files client_config \
  && rm -rf gz_client_bot.tar.gz \
  && chmod +x sh_client_bot.sh

ENTRYPOINT [ "/app/sh_client_bot.sh" ]
