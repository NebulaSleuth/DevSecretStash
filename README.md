# Dev Secret Stash

**by Extrastrength Software LLC**

Securely sync .NET user-secrets across machines with end-to-end encryption.

Hosted free at **[devsecretstash.com](https://devsecretstash.com)** -- or self-host your own instance.

## Quick Start

```bash
# Install the CLI
dotnet tool install --global DevSecretStash

# Ensure dotnet tools are on your PATH (if 'dss' is not found)
# Add to your shell profile (~/.bashrc, ~/.zshrc, or ~/.profile) for persistence:
export PATH="$PATH:$HOME/.dotnet/tools"

# Create your free account
dss register

# Push secrets from any .NET project directory
dss push

# On another machine: login and pull
dss login
dss pull
```

That's it. Your secrets are encrypted on your machine before upload. The server never sees plaintext.

## How It Works

```
[Your Machine]                     [devsecretstash.com]                  [Another Machine]
secrets.json  -->  encrypt  -->  encrypted blob (SQLite)  -->  decrypt  -->  secrets.json
                   (AES-256-GCM)                                (AES-256-GCM)
```

- **AES-256-GCM** encrypts your secrets using a random master key
- **Argon2id** derives a key-encryption-key from your password to wrap the master key
- The server only stores encrypted blobs -- it cannot read your secrets
- Password changes re-wrap the master key without re-encrypting all secrets

## Website

**[devsecretstash.com](https://devsecretstash.com)** provides:

- **Landing page** -- overview, features, getting started guide
- **Documentation** -- CLI reference, security model, API docs
- **Account creation** -- sign up free from the browser or CLI
- **Dashboard** -- view and manage your synced secret collections
- **Swagger API** -- full REST API documentation at `/swagger`

## CLI Commands

| Command | Description |
|---------|-------------|
| `dss register` | Create a free account |
| `dss login` | Authenticate and cache credentials |
| `dss logout` | Clear cached credentials |
| `dss push [UserSecretsId]` | Encrypt and upload local secrets |
| `dss pull [UserSecretsId]` | Download and decrypt secrets locally |
| `dss status [UserSecretsId]` | Show sync status (local vs remote) |
| `dss list` | List all secret collections on the server |
| `dss config --server-url <url>` | Point CLI at a different server |

**Global options:** `--verbose` / `-v` for debug output.

If `UserSecretsId` is omitted, the CLI auto-detects it from a `.csproj` in the current directory.

The CLI defaults to `https://devsecretstash.com`. Use `dss config` to point at a self-hosted instance.

## Project Structure

```
DevSecretStash/
  src/
    DevSecretStash.Core/       # Encryption (AES-256-GCM, Argon2id), models, DTOs
    DevSecretStash.Api/        # ASP.NET Core: REST API + Razor Pages website
    DevSecretStash.Cli/        # dotnet global tool: CLI (dss)
  tests/
    DevSecretStash.Core.Tests/ # 25 unit tests
    DevSecretStash.Api.Tests/  # 26 integration tests
    DevSecretStash.Cli.Tests/  # 9 integration tests
```

## Azure Deployment

The API is designed to deploy to Azure App Service (Linux).

### App Service Setup

```bash
# Create resource group and App Service plan
az group create --name devsecretstash-rg --location eastus
az appservice plan create --name devsecretstash-plan --resource-group devsecretstash-rg \
  --is-linux --sku B1

# Create the web app
az webapp create --name devsecretstash --resource-group devsecretstash-rg \
  --plan devsecretstash-plan --runtime "DOTNETCORE:9.0"

# Configure settings
az webapp config appsettings set --name devsecretstash --resource-group devsecretstash-rg \
  --settings \
    Jwt__Key="YOUR-PRODUCTION-SECRET-KEY-MINIMUM-32-CHARS" \
    Jwt__Issuer="DevSecretStash" \
    ConnectionStrings__Default="Data Source=/home/site/data/devsecretstash.db"

# Custom domain
az webapp config hostname add --webapp-name devsecretstash \
  --resource-group devsecretstash-rg --hostname devsecretstash.com

# Deploy
dotnet publish src/DevSecretStash.Api -c Release -o ./publish
cd publish && zip -r ../deploy.zip . && cd ..
az webapp deploy --name devsecretstash --resource-group devsecretstash-rg \
  --src-path deploy.zip --type zip
```

### Docker Deployment (Alternative)

```bash
docker build -t devsecretstash-api -f src/DevSecretStash.Api/Dockerfile .
docker run -d -p 8080:8080 \
  -v dss-data:/app/data \
  -e Jwt__Key="your-production-secret-key-minimum-32-characters!" \
  devsecretstash-api
```

## Server Configuration

| Setting | Env Variable | Default |
|---------|-------------|---------|
| Database | `ConnectionStrings__Default` | `Data Source=devsecretstash.db` |
| JWT Key | `Jwt__Key` | *Change in production!* |
| JWT Issuer | `Jwt__Issuer` | `DevSecretStash` |
| Token lifetime | `Jwt__AccessTokenMinutes` | `15` |
| Refresh lifetime | `Jwt__RefreshTokenDays` | `30` |

## Publishing the CLI to NuGet.org

```bash
dotnet pack src/DevSecretStash.Cli/DevSecretStash.Cli.csproj -c Release -o ./nupkg

dotnet nuget push ./nupkg/DevSecretStash.0.1.0.nupkg \
  --api-key YOUR_NUGET_API_KEY \
  --source https://api.nuget.org/v3/index.json
```

Once published, anyone can install with `dotnet tool install --global DevSecretStash`.

## Security Model

| Layer | Mechanism | Purpose |
|-------|-----------|---------|
| Password auth | Argon2id (server-side) | Verify identity |
| Key wrapping | Argon2id (client-side) + AES-256-GCM | Protect master key |
| Secret encryption | AES-256-GCM | Encrypt before upload |
| Transport | HTTPS + HSTS | Protect in transit |
| Local credentials | chmod 600 (Linux/Mac) | Protect cached keys |
| API auth | JWT (15m) + refresh tokens (30d) | Stateless with rotation |
| Rate limiting | 10 attempts / 15 min | Prevent brute force |

The server **never** sees plaintext secrets. The encryption key never leaves your machine.

## Development

```bash
dotnet build           # Build all projects
dotnet test            # Run 60 tests
dotnet run --project src/DevSecretStash.Api   # Run server locally
dotnet run --project src/DevSecretStash.Cli -- --help  # CLI help
```

## License

MIT -- Dev Secret Stash by Extrastrength Software LLC
