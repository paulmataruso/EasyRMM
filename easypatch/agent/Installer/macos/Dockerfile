# Builds the experimental EasyPatch macOS agent installer (a flat .pkg product archive, the format productbuild makes)
# from an already published agent. Used by scripts/build-macos-packages.sh; the build itself runs with networking
# disabled. The base image is pinned by digest, Ubuntu packages by version, and bomutils (mkbom, lsbom, dumpbom: not
# packaged for Ubuntu) by commit and SHA-256 of its source archive.
FROM ubuntu:26.04@sha256:065aa8626841f16057b78b027b464cd59c4fac36c204c72dcbf48d66f5fa8a96 AS bomutils

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends g++-15=15.2.0-16ubuntu1 make=4.4.1-3 \
 && rm -rf /var/lib/apt/lists/*

# github.com/hogliux/bomutils master as of 2024-10-28 (GPL-2.0-or-later). Its lsbom crashes on every BOM since
# commit 704739c (it reads the "Paths" test the wrong way round); the sed restores the original test.
ADD --checksum=sha256:286e49560a3f84650b5a60ca0f22f775c0526aa4fb199db7a66f4d310378d4dd \
    https://github.com/hogliux/bomutils/archive/c247002e2f49878bab32dd0fcf805810ae0992cb.tar.gz /tmp/bomutils.tar.gz
RUN mkdir /tmp/bomutils \
 && tar -xzf /tmp/bomutils.tar.gz -C /tmp/bomutils --strip-components=1 \
 && sed -i 's/if (strstr(name.c_str(),"Paths") == 0) {/if (name == "Paths") {/' /tmp/bomutils/src/lsbom.cpp \
 && grep -q 'if (name == "Paths") {' /tmp/bomutils/src/lsbom.cpp \
 && make -C /tmp/bomutils CXX=g++-15 build/bin/mkbom build/bin/lsbom build/bin/dumpbom \
 && install -m 0755 /tmp/bomutils/build/bin/mkbom /tmp/bomutils/build/bin/lsbom /tmp/bomutils/build/bin/dumpbom /usr/local/bin/

FROM ubuntu:26.04@sha256:065aa8626841f16057b78b027b464cd59c4fac36c204c72dcbf48d66f5fa8a96

ARG DEBIAN_FRONTEND=noninteractive
# python3 runs check-pkg.py, the structural check of every package built.
RUN apt-get update \
 && apt-get install -y --no-install-recommends xar=1.8.0.498-3 cpio=2.15+dfsg-2.1ubuntu0.1 python3=3.14.3-0ubuntu2 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=bomutils /usr/local/bin/mkbom /usr/local/bin/lsbom /usr/local/bin/dumpbom /usr/local/bin/
