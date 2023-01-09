# syntax=docker/dockerfile:1
FROM ubuntu:latest
WORKDIR /app
ENV APP_SECRET_KEY=JiMbXvrbFgE

RUN apt update -y
RUN apt install python3 -y
RUN apt install python3-pip -y
RUN apt install nginx -y

COPY banners ./banners
COPY templates ./templates
COPY src/__init__.py ./src/__init__.py
COPY requirements.txt .
COPY default /etc/nginx/sites-available/default
COPY certs /etc/nginx/ssl

RUN python3 -m pip install -r requirements.txt
RUN python3 src/__init__.py

CMD service nginx start; uwsgi --socket 127.0.0.1:29000 --wsgi-file /app/src/__init__.py --callable app
EXPOSE 80 443