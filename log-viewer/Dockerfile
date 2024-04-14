FROM openjdk:8-jre-alpine
EXPOSE 8111

RUN wget -P /tmp https://github.com/sevdokimov/log-viewer/releases/download/v1.0.7/log-viewer-1.0.7.tar.gz
RUN mkdir -p /opt
RUN tar zxfv /tmp/log-viewer-1.0.7.tar.gz -C /opt
RUN rm -f /tmp/log-viewer-1.0.7.tar.gz

# move expanded directory to a nicer location
RUN mv /opt/log-viewer-1.0.7 /opt/logviewer

# existing scripts is not sh-friendly, rewritten
COPY logviewer.sh /opt/logviewer/

WORKDIR /opt/logviewer
CMD /opt/logviewer/logviewer.sh
