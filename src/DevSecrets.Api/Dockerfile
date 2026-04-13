FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

# Copy solution and project files first for layer caching
COPY DevSecrets.sln Directory.Build.props Directory.Packages.props ./
COPY src/DevSecrets.Core/DevSecrets.Core.csproj src/DevSecrets.Core/
COPY src/DevSecrets.Api/DevSecrets.Api.csproj src/DevSecrets.Api/
RUN dotnet restore src/DevSecrets.Api/DevSecrets.Api.csproj

# Copy source and build
COPY src/ src/
RUN dotnet publish src/DevSecrets.Api/DevSecrets.Api.csproj -c Release -o /app/publish --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS runtime
WORKDIR /app

# Create non-root user
RUN groupadd -r devsecrets && useradd -r -g devsecrets -m devsecrets

# Create data directory for SQLite
RUN mkdir -p /app/data && chown devsecrets:devsecrets /app/data

COPY --from=build /app/publish .

USER devsecrets
EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080
ENV ConnectionStrings__Default="Data Source=/app/data/devsecrets.db"

ENTRYPOINT ["dotnet", "DevSecrets.Api.dll"]
