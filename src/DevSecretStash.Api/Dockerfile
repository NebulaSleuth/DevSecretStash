FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

# Copy solution and project files first for layer caching
COPY DevSecretStash.sln Directory.Build.props Directory.Packages.props ./
COPY src/DevSecretStash.Core/DevSecretStash.Core.csproj src/DevSecretStash.Core/
COPY src/DevSecretStash.Api/DevSecretStash.Api.csproj src/DevSecretStash.Api/
RUN dotnet restore src/DevSecretStash.Api/DevSecretStash.Api.csproj

# Copy source and build
COPY src/ src/
RUN dotnet publish src/DevSecretStash.Api/DevSecretStash.Api.csproj -c Release -o /app/publish --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS runtime
WORKDIR /app

# Create non-root user
RUN groupadd -r devsecretstash && useradd -r -g devsecretstash -m devsecretstash

# Create data directory for SQLite
RUN mkdir -p /app/data && chown devsecretstash:devsecretstash /app/data

COPY --from=build /app/publish .

USER devsecretstash
EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080
ENV ConnectionStrings__Default="Data Source=/app/data/devsecretstash.db"

ENTRYPOINT ["dotnet", "DevSecretStash.Api.dll"]
