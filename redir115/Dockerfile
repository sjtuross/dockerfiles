FROM python:3.11-slim

WORKDIR /app

COPY ./requirements.txt /app/requirements.txt
COPY ./redir115.py /app/redir115.py

RUN pip install --no-cache-dir -r requirements.txt && rm requirements.txt

EXPOSE 5302

CMD ["python", "-u", "redir115.py"]
