# Dockerfile
FROM ubuntu:22.04

ENV GO_VERSION=1.23.3
ENV GOOS=linux
ENV GOARCH=amd64

RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    git \
    gcc \
    libc6-dev \
    make \
    build-essential \
    ca-certificates \
    lsb-release \
    sudo \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN wget -P /tmp "https://go.dev/dl/go${GO_VERSION}.linux-arm64.tar.gz"

RUN tar -C /usr/local -xzf "/tmp/go${GO_VERSION}.linux-arm64.tar.gz"
RUN rm "/tmp/go${GO_VERSION}.linux-arm64.tar.gz"

ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH
RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"

# # Create a non-root user and add it to the sudo group
RUN useradd -m -s /bin/bash go_user && \
    echo "go_user ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# # Switch to the non-root user
USER go_user

WORKDIR /app
