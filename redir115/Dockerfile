FROM python:3.11-slim

WORKDIR /app

COPY ./requirements.txt /app/requirements.txt
COPY ./redir115.py /app/redir115.py

RUN pip install --no-cache-dir -r requirements.txt && rm requirements.txt

EXPOSE 5302

CMD [ "gunicorn", "-w", "4", "-b", "0.0.0.0:5302", "redir115:app" ]
