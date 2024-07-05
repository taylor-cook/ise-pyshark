FROM python:3-alpine
# FROM python:3-alpine

WORKDIR /app
COPY . .
# RUN pip install --upgrade pip

# RUN apt-get install -y tshark; pip install requests; pip install pyshark; pip install user_agents

RUN apk update && apk add --no-cache \
    tshark \
    && rm -rf /var/cache/apk/*

RUN pip install requests; pip install pyshark; pip install user_agents

CMD ["python", "isepy.py"]