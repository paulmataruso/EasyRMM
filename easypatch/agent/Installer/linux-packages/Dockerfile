# Builds the EasyPatch agent .deb and .rpm packages from an already published agent. Used by
# scripts/build-linux-packages.sh; the build itself runs with networking disabled.
# The base image is pinned by digest and rpm and cpio by version.
FROM ubuntu:26.04@sha256:065aa8626841f16057b78b027b464cd59c4fac36c204c72dcbf48d66f5fa8a96

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends rpm=6.0.1-1build1 cpio=2.15+dfsg-2.1ubuntu0.1 \
 && rm -rf /var/lib/apt/lists/*
