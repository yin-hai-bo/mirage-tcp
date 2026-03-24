FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        cmake \
        curl \
        gdb \
        iproute2 \
        iptables \
        iputils-ping \
        make \
        netcat-openbsd \
        net-tools \
        tcpdump \
    && rm -rf /var/lib/apt/lists/*

CMD ["/bin/bash"]
