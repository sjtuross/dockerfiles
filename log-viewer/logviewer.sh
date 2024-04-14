#!/usr/bin/env sh
SCRIPT_DIR="$( cd "$( dirname "$0" )" && pwd )"
java -ea \
   -Dlog-viewer.config-file=$SCRIPT_DIR/config.conf \
   -jar $SCRIPT_DIR/lib/log-viewer-cli-1.0.7.jar startup
