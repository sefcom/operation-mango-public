ARG BASE=ubuntu:22.04
FROM ${BASE} as base
MAINTAINER Clasm

ENV DEBIAN_FRONTEND=noninteractive

USER root
RUN apt-get update && apt-get -y install software-properties-common dirmngr apt-transport-https lsb-release ca-certificates

FROM base as python_build
RUN add-apt-repository ppa:deadsnakes/ppa -y
RUN apt-get update && apt-get -o APT::Immediate-Configure=0 install -y \
    git sudo virtualenvwrapper python3.11-dev python3.11-venv python3-pip build-essential libxml2-dev \
    libxslt1-dev git libffi-dev cmake libreadline-dev libtool debootstrap \
    debian-archive-keyring libglib2.0-dev libpixman-1-dev qtdeclarative5-dev \
    binutils-multiarch nasm libc6 libgcc1 libstdc++6 \
    libtinfo5 zlib1g vim openssl libssl-dev openjdk-8-jdk graphviz graphviz-dev\
    && rm -rf /var/lib/apt/lists/*

FROM python_build as angr_repo

#RUN . /angr/bin/activate && pip install py-spy rich docker toml kubernetes

FROM angr_repo as mango_repo

RUN mkdir /operation-mango
COPY . /operation-mango
RUN cd / && python3.11 -m venv angr
WORKDIR /operation-mango

RUN touch /operation-mango/setup.cfg
RUN . /angr/bin/activate && pip install -e .
RUN . /angr/bin/activate && pip install -e pipeline
RUN cd /angr/lib/python3.11/site-packages && git apply /operation-mango/docker/live_def.patch

WORKDIR /operation-mango
RUN ln -s /angr/bin/mango /usr/local/bin/mango
RUN ln -s /angr/bin/env_resolve /usr/local/bin/env_resolve
RUN ln -s /angr/bin/mango-pipeline /usr/local/bin/mango-pipeline

COPY ./docker/entrypoint.py /
RUN chmod +x /entrypoint.py
