# Builds the EasyPatch agent .deb and .rpm packages from an already published agent. Used by
# scripts/build-linux-packages.sh; the build itself runs with networking disabled.
# The base image is pinned by digest and rpm and cpio by version.
FROM ubuntu:26.04@sha256:d66b366dac61b575bee2aef07e9c26e8070096fbe84a3d4d3eb0da069b5d76db

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends rpm=6.0.1-1build1 cpio=2.15+dfsg-2.1ubuntu0.1 \
 && rm -rf /var/lib/apt/lists/*
