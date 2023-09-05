FROM alpine:latest as main-linux-armv7
RUN apk -U add wget
RUN wget -O squeeze2upnp-static https://raw.githubusercontent.com/philippe44/LMS-uPnP/master/plugin/Bin/squeeze2upnp-linux-arm-static \
    && chmod +x squeeze2upnp-static && cp squeeze2upnp-static /usr/local/bin/ && rm squeeze2upnp-static*

FROM alpine:latest as main-linux-arm64
RUN apk -U add wget
RUN wget -O squeeze2upnp-static https://raw.githubusercontent.com/philippe44/LMS-uPnP/master/plugin/Bin/squeeze2upnp-linux-aarch64-static \
    && chmod +x squeeze2upnp-static && cp squeeze2upnp-static /usr/local/bin/ && rm squeeze2upnp-static*

FROM alpine:latest as main-linux-amd64
RUN apk -U add wget
RUN wget -O squeeze2upnp-static https://raw.githubusercontent.com/philippe44/LMS-uPnP/master/plugin/Bin/squeeze2upnp-linux-x86_64-static \
    && chmod +x squeeze2upnp-static && cp squeeze2upnp-static /usr/local/bin/ && rm squeeze2upnp-static*

FROM main-${TARGETOS}-${TARGETARCH}${TARGETVARIANT}
CMD ["-x", "/config/config.xml"]
ENTRYPOINT ["/usr/local/bin/squeeze2upnp-static", "-Z"]
