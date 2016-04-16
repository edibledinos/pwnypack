FROM ubuntu:trusty

MAINTAINER Ingmar Steen <iksteen@gmail.com>

RUN apt-get update && \
	DEBIAN_FRONTEND=noninteractive apt-get install -qy \
		git nasm build-essential python \
		python-dev python-pip python-virtualenv python-setuptools && \
	apt-get clean && \
	rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN virtualenv /virtualenv && /virtualenv/bin/pip install -U pip setuptools

RUN git clone https://github.com/edibledinos/pwnypack /pwnypack && \
	/virtualenv/bin/pip install --no-binary capstone /pwnypack/[all] && \
	rm -rf /pwnypack

RUN groupadd -r pwnypack && useradd -m -r -g pwnypack pwnypack && \
	mkdir /projects && \
	git clone https://github.com/edibledinos/pwnypack-examples.git /projects/examples && \
	rm -rf /projects/examples/.git && \
	chown -R pwnypack:pwnypack /projects
VOLUME ["/projects"]

WORKDIR /projects
USER pwnypack
CMD /virtualenv/bin/pwny shell
