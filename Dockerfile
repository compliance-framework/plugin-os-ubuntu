# Dockerfile
FROM golang:1.23.2

# Install sudo
RUN apt-get update && apt-get install -y sudo && rm -rf /var/lib/apt/lists/*

# Create a non-root user and add it to the sudo group
RUN useradd -m -s /bin/bash go_user && \
    echo "go_user ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Switch to the non-root user
USER go_user

# Set the working directory
WORKDIR /app
