FROM python:3-alpine

WORKDIR /app

COPY ./requirements.txt /app/requirements.txt

RUN apk add --no-cache --virtual .build-deps gcc libxml2-dev libxslt-dev musl-dev py3-pip tzdata wget \
    && wget -O /app/dav_115_302.py https://raw.githubusercontent.com/ChenyangGao/p115client/main/examples/dav_115_302.py \
    && pip3 install --no-cache-dir -r /app/requirements.txt \
    && apk del .build-deps gcc musl-dev

ENV TZ=Asia/Shanghai

EXPOSE 8000

ENTRYPOINT ["python", "dav_115_302.py", "--cookies-path", "115-cookies.txt"]
