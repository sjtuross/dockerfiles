FROM linuxserver/qbittorrent:libtorrentv1 as main-linux-armv7
RUN curl -o /app/qbittorrent-nox -L \
    "https://github.com/Ghost-chu/qbittorrent-nox-static/releases/download/manual-4_5_x_RC_1_2-fasthash/armv7-qbittorrent-nox"

FROM linuxserver/qbittorrent:libtorrentv1 as main-linux-arm64
RUN curl -o /app/qbittorrent-nox -L \
    "https://github.com/Ghost-chu/qbittorrent-nox-static/releases/download/manual-4_5_x_RC_1_2-fasthash/aarch64-qbittorrent-nox"

FROM linuxserver/qbittorrent:libtorrentv1 as main-linux-amd64
RUN curl -o /app/qbittorrent-nox -L \
    "https://github.com/Ghost-chu/qbittorrent-nox-static/releases/download/manual-4_5_x_RC_1_2-fasthash/x86_64-qbittorrent-nox"

FROM main-${TARGETOS}-${TARGETARCH}${TARGETVARIANT}
