FROM ubuntu:trusty

MAINTAINER Ingmar Steen <iksteen@gmail.com>

RUN apt-get update && \
	DEBIAN_FRONTEND=noninteractive apt-get install -qy \
		git nasm build-essential python cmake \
		python-dev python-pip python-virtualenv python-setuptools \
		binutils-aarch64-linux-gnu binutils-arm-none-eabi \
		libffi-dev libssl-dev && \
	apt-get clean && \
	rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN groupadd -r pwnypack && \
	useradd -m -r -g pwnypack pwnypack && \
	install -d -o pwnypack -g pwnypack /virtualenv /projects

USER pwnypack

RUN virtualenv /virtualenv && /virtualenv/bin/pip install -U pip setuptools && \
	git clone -b latest https://github.com/edibledinos/pwnypack /tmp/pwnypack && \
	/virtualenv/bin/pip install --no-binary capstone,keystone-engine /tmp/pwnypack/[all] && \
	rm -rf /tmp/pwnypack ~/.cache

RUN git clone https://github.com/edibledinos/pwnypack-examples.git /projects && \
	rm -rf /projects/.git

VOLUME ["/projects"]
WORKDIR /projects
CMD /virtualenv/bin/pwny shell
