FROM debian:wheezy-slim
RUN apt-get update && apt-get install -y build-essential git