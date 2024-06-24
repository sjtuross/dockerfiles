FROM python:3.11-slim

WORKDIR /app

COPY ./requirements.txt /app/requirements.txt
COPY ./emby115.py /app/emby115.py

RUN pip install --no-cache-dir -r requirements.txt && rm requirements.txt

EXPOSE 5115

ENV PYTHONUNBUFFERED=1
ENV TZ=Asia/Shanghai

CMD [ "gunicorn", "-w", "4", "-b", "0.0.0.0:5115", "emby115:app" ]
