FROM ubuntu:22.04 as ubuntu

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive \
    TZ=Europe/Brussels \ 
    apt-get install  -y \
    python3 python3-pip

RUN pip3 install --upgrade pip

ADD pandora/requirements.txt /src/requirements.txt
RUN pip install -r /src/requirements.txt


