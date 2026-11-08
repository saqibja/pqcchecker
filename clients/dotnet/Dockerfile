# .NET SslStream client on Linux (TLS via the system OpenSSL). RUNTIME_IMAGE picks the base:
# the default .NET 10 image (Ubuntu 24.04, OpenSSL 3.0) or Ubuntu 26.04 (OpenSSL 3.5).
# Build context: ./clients
ARG RUNTIME_IMAGE=mcr.microsoft.com/dotnet/runtime:10.0.14@sha256:4f1f30cf0bb4ab0c8b2daa84613051683456f8df4a9bf7c812e20d74962992ac

FROM mcr.microsoft.com/dotnet/sdk:10.0.403@sha256:212fe4cb74627d5adf9817a4088906ae3edff1bd853bb27565d4b46731efe61e AS build
WORKDIR /src
COPY dotnet/pqcc.csproj dotnet/Program.cs ./
RUN dotnet publish -c Release -o /app

FROM ${RUNTIME_IMAGE}
COPY --from=build /app /app
RUN printf '#!/bin/sh\nexec dotnet /app/pqcc-dotnet.dll "$@"\n' > /usr/local/bin/pqcc-client \
 && chmod 755 /usr/local/bin/pqcc-client
