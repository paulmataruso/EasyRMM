# Builds the EasyPatch agent MSI on Linux: the same WiX Toolset 5.0.2 used on Windows, run under Wine with the
# Windows .NET runtime. Used by scripts/build-msi-linux.sh; the build itself runs with networking disabled.
#
# Every input is pinned: the base image by digest, Ubuntu packages by version, and downloads by hash. The WiX
# packages are the nuget.org packages signed by the WiX Toolset (.NET Foundation); their hashes were taken after
# `dotnet nuget verify --all` succeeded. The runtime hash is Microsoft's published SHA-512.
FROM ubuntu:26.04@sha256:065aa8626841f16057b78b027b464cd59c4fac36c204c72dcbf48d66f5fa8a96

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl unzip \
      wine=10.0~repack-12ubuntu1 wine64=10.0~repack-12ubuntu1 \
      msitools=0.106+repack-2 \
 && rm -rf /var/lib/apt/lists/*

ARG DOTNET_RUNTIME_VERSION=10.0.15
ARG DOTNET_RUNTIME_SHA512=06f0bedd59ae4ac722ada805a6d6bbf605bcdc790c71f59b7003878072902b5cde5dec8c40c0baa81192660d4748e9d79afdbdcb0c0ea9d6b821d0a044c4c6dd
ARG WIX_VERSION=5.0.2
ARG WIX_SHA256=f30ef0c74e2a986126539c5780be93ac24e8136eaf723b1937b26272703ae173
ARG WIX_UTIL_SHA256=dda1cc1b4d3b2305b1246f167c6af6fcded5000be84b3bbff3dda4f442bf4740

WORKDIR /opt/download
RUN curl -fsSLo dotnet.zip "https://builds.dotnet.microsoft.com/dotnet/Runtime/${DOTNET_RUNTIME_VERSION}/dotnet-runtime-${DOTNET_RUNTIME_VERSION}-win-x64.zip" \
 && echo "${DOTNET_RUNTIME_SHA512}  dotnet.zip" | sha512sum -c - \
 && curl -fsSLo wix.nupkg "https://api.nuget.org/v3-flatcontainer/wix/${WIX_VERSION}/wix.${WIX_VERSION}.nupkg" \
 && echo "${WIX_SHA256}  wix.nupkg" | sha256sum -c - \
 && curl -fsSLo util.nupkg "https://api.nuget.org/v3-flatcontainer/wixtoolset.util.wixext/${WIX_VERSION}/wixtoolset.util.wixext.${WIX_VERSION}.nupkg" \
 && echo "${WIX_UTIL_SHA256}  util.nupkg" | sha256sum -c - \
 && unzip -q dotnet.zip -d /opt/dotnet \
 && unzip -q wix.nupkg -d /opt/wix \
 && unzip -q util.nupkg -d /opt/wix-util \
 && rm -rf /opt/download

ENV WINEDEBUG=-all WINEPREFIX=/opt/wineprefix XDG_RUNTIME_DIR=/tmp
# Initialize the Wine prefix and wait for wineserver to save it before the layer is committed.
RUN wineboot --init >/dev/null 2>&1 \
 && wine /opt/dotnet/dotnet.exe /opt/wix/tools/net6.0/any/wix.dll --version \
 && /usr/lib/x86_64-linux-gnu/wine/wineserver -w

WORKDIR /tmp
