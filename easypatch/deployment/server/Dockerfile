# syntax=docker/dockerfile:1
# EasyPatch server image: the API (default entrypoint) and the background worker, built from one source tree.
# Build context: repository root.  docker build -f deployment/server/Dockerfile -t easypatch-server .

FROM mcr.microsoft.com/dotnet/sdk:10.0.404-alpine3.24 AS build
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
WORKDIR /src

# Restore first (cached unless project files change).
COPY global.json Directory.Build.props Directory.Packages.props ./
COPY shared/EasyPatch.Contracts/EasyPatch.Contracts.csproj shared/EasyPatch.Contracts/
COPY backend/Core/EasyPatch.Core.csproj backend/Core/
COPY backend/Infrastructure/EasyPatch.Infrastructure.csproj backend/Infrastructure/
COPY backend/API/EasyPatch.Api.csproj backend/API/
COPY backend/Worker/EasyPatch.Worker.csproj backend/Worker/
RUN dotnet restore backend/API/EasyPatch.Api.csproj \
 && dotnet restore backend/Worker/EasyPatch.Worker.csproj

COPY shared/ shared/
COPY backend/Core/ backend/Core/
COPY backend/Infrastructure/ backend/Infrastructure/
COPY backend/API/ backend/API/
COPY backend/Worker/ backend/Worker/
RUN dotnet publish backend/API/EasyPatch.Api.csproj -c Release --no-restore -o /out/api /p:UseAppHost=false \
 && dotnet publish backend/Worker/EasyPatch.Worker.csproj -c Release --no-restore -o /out/worker /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0.15-alpine3.24 AS runtime
# tzdata: IANA time zones for maintenance windows. No other packages are added.
RUN apk add --no-cache tzdata \
 && mkdir -p /app/keys /app/agent-packages /app/winget \
 && chown app:app /app/keys /app/winget
COPY --from=build /out/api /app/api
COPY --from=build /out/worker /app/worker

ENV ASPNETCORE_HTTP_PORTS=8080 \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_EnableDiagnostics=0 \
    EasyPatch__DataProtectionKeysPath=/app/keys \
    EasyPatch__AgentPackagesPath=/app/agent-packages \
    EasyPatch__WingetCachePath=/app/winget
WORKDIR /app/api
USER app
EXPOSE 8080
VOLUME ["/app/keys"]
ENTRYPOINT ["dotnet", "/app/api/EasyPatch.Api.dll"]
