FROM alpine:3.10 as main-linux-armv7
RUN apk -U add wget
RUN wget -O natapp https://cdn.natapp.cn/assets/downloads/clients/2_3_9/natapp_linux_arm/natapp?version=20220415 \
    && chmod +x natapp && cp natapp /usr/local/bin/ && rm natapp*

FROM alpine:3.10 as main-linux-arm64
RUN apk -U add wget
RUN wget -O natapp https://cdn.natapp.cn/assets/downloads/clients/2_3_9/natapp_linux_arm64/natapp?version=20220415 \
    && chmod +x natapp && cp natapp /usr/local/bin/ && rm natapp*

FROM alpine:3.10 as main-linux-amd64
RUN apk -U add wget
RUN wget -O natapp https://cdn.natapp.cn/assets/downloads/clients/2_3_9/natapp_linux_amd64/natapp?version=20220415 \
    && chmod +x natapp && cp natapp /usr/local/bin/ && rm natapp*

FROM main-${TARGETOS}-${TARGETARCH}${TARGETVARIANT}
CMD ["-h"]
ENTRYPOINT ["/usr/local/bin/natapp"]
