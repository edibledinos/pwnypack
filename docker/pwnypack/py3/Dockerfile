FROM ubuntu:trusty

MAINTAINER Ingmar Steen <iksteen@gmail.com>

RUN apt-get update && \
	DEBIAN_FRONTEND=noninteractive apt-get install -qy \
		git nasm build-essential python python3 cmake \
		python3-dev python3-pip python3-setuptools \
		binutils-aarch64-linux-gnu binutils-arm-none-eabi \
		libffi-dev libssl-dev && \
	apt-get clean && \
	rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN /usr/bin/pip3 install virtualenv && \
	groupadd -r pwnypack && \
	useradd -m -r -g pwnypack pwnypack && \
	install -d -o pwnypack -g pwnypack /virtualenv /projects

USER pwnypack

RUN virtualenv -p /usr/bin/python3 /virtualenv && /virtualenv/bin/pip install -U pip setuptools && \
	git clone -b latest https://github.com/edibledinos/pwnypack /tmp/pwnypack && \
	/virtualenv/bin/pip install --no-binary capstone,keystone-engine /tmp/pwnypack/[all] && \
	rm -rf /tmp/pwnypack ~/.cache

RUN git clone https://github.com/edibledinos/pwnypack-examples.git /projects && \
	rm -rf /projects/.git

VOLUME ["/projects"]
WORKDIR /projects
CMD /virtualenv/bin/pwny shell
