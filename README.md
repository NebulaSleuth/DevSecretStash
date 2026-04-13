# DevSecretStash

Securely sync .NET user-secrets across machines with end-to-end encryption.

DevSecretStash consists of a **CLI tool** (dotnet global tool) and a **web service** (ASP.NET Core). Secrets are encrypted on your machine before upload — the server never sees plaintext.

## How It Works

```
[Your Machine]                    [DevSecretStash Server]                [Another Machine]
secrets.json  -->  encrypt  -->  encrypted blob (SQLite)  -->  decrypt  -->  secrets.json
                   (AES-256-GCM)                                (AES-256-GCM)
```

- **AES-256-GCM** encrypts your secrets using a master key
- **Argon2id** derives a key-encryption-key from your password to wrap the master key
- The server only stores encrypted blobs — it cannot read your secrets
- Password changes re-wrap the master key without re-encrypting all secrets

## Quick Start

### 1. Deploy the Server

**Option A: Docker**
```bash
docker build -t dss-api -f src/DevSecretStash.Api/Dockerfile .
docker run -d -p 8080:8080 \
  -v dss-data:/app/data \
  -e Jwt__Key="your-production-secret-key-minimum-32-characters!" \
  dss-api
```

**Option B: Run directly**
```bash
cd src/DevSecretStash.Api
dotnet run
# Server starts at https://localhost:5001 (dev) or http://localhost:5000
```

The server provides:
- REST API for CLI sync operations
- Web dashboard at `/` for managing collections in a browser
- Swagger docs at `/swagger` (development mode)

### 2. Install the CLI

**Option A: From local build**
```bash
# Pack the tool
dotnet pack src/DevSecretStash.Cli/DevSecretStash.Cli.csproj -c Release -o ./nupkg

# Install globally from the local package
dotnet tool install --global --add-source ./nupkg DevSecretStash
```

**Option B: From a NuGet feed**
```bash
# If published to NuGet.org:
dotnet tool install --global DevSecretStash

# If published to a private feed:
dotnet tool install --global DevSecretStash --add-source https://your-feed-url/v3/index.json
```

**Option C: From GitHub Packages**
```bash
dotnet nuget add source https://nuget.pkg.github.com/YOUR_ORG/index.json \
  --name github --username YOUR_USERNAME --password YOUR_PAT

dotnet tool install --global DevSecretStash --add-source github
```

### 3. Configure and Use

```bash
# Point CLI at your server
dss config --server-url https://your-server.example.com

# Create an account
dss register

# Push secrets from a .NET project directory (auto-detects UserSecretsId from .csproj)
cd /path/to/your/dotnet/project
dss push

# On another machine: install CLI, login, pull
dss login
dss pull
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `dss config --server-url <url>` | Set the server URL |
| `dss register` | Create a new account |
| `dss login` | Authenticate and cache credentials |
| `dss logout` | Clear cached credentials |
| `dss push [UserSecretsId]` | Encrypt and upload local secrets |
| `dss pull [UserSecretsId]` | Download and decrypt secrets locally |
| `dss status [UserSecretsId]` | Show sync status (local vs remote) |
| `dss list` | List all secret collections on the server |

**Global options:**
- `--verbose` / `-v` — Enable verbose output (shows HTTP requests/responses)

If `UserSecretsId` is omitted, the CLI scans the current directory for a `.csproj` file containing `<UserSecretsId>`.

## Web Dashboard

The server includes a browser-based dashboard at the root URL (`/`). Login with your DevSecretStash account to:

- View all your synced secret collections
- See version numbers and last-modified timestamps
- Delete collections you no longer need

## Project Structure

```
DevSecretStash/
  src/
    DevSecretStash.Core/       # Shared: encryption (AES-256-GCM, Argon2id), models, DTOs
    DevSecretStash.Api/        # ASP.NET Core server: REST API + Razor Pages dashboard
    DevSecretStash.Cli/        # dotnet global tool: CLI commands
  tests/
    DevSecretStash.Core.Tests/ # 25 unit tests (encryption, key management)
    DevSecretStash.Api.Tests/  # 26 integration tests (auth, CRUD, user isolation)
    DevSecretStash.Cli.Tests/  # 9 integration tests (full workflows)
```

## Server Configuration

Configuration via `appsettings.json` or environment variables:

| Setting | Env Variable | Default | Description |
|---------|-------------|---------|-------------|
| `ConnectionStrings:Default` | `ConnectionStrings__Default` | `Data Source=dss.db` | SQLite connection string |
| `Jwt:Key` | `Jwt__Key` | *(dev key)* | **Change in production!** Min 32 chars |
| `Jwt:Issuer` | `Jwt__Issuer` | `DevSecretStash` | JWT issuer/audience |
| `Jwt:AccessTokenMinutes` | `Jwt__AccessTokenMinutes` | `15` | Access token lifetime |
| `Jwt:RefreshTokenDays` | `Jwt__RefreshTokenDays` | `30` | Refresh token lifetime |

## Publishing the CLI to NuGet.org

To make the CLI installable anywhere via `dotnet tool install --global DevSecretStash`:

```bash
# 1. Pack
dotnet pack src/DevSecretStash.Cli/DevSecretStash.Cli.csproj -c Release -o ./nupkg

# 2. Get a NuGet.org API key from https://www.nuget.org/account/apikeys

# 3. Push
dotnet nuget push ./nupkg/DevSecretStash.0.1.0.nupkg \
  --api-key YOUR_NUGET_API_KEY \
  --source https://api.nuget.org/v3/index.json
```

Once published, anyone can install it:
```bash
dotnet tool install --global DevSecretStash
```

To update:
```bash
dotnet tool update --global DevSecretStash
```

## Private NuGet Feed (Alternative)

If you don't want to publish publicly, host a private feed:

**GitHub Packages:**
```bash
dotnet nuget push ./nupkg/DevSecretStash.0.1.0.nupkg \
  --api-key YOUR_GITHUB_PAT \
  --source https://nuget.pkg.github.com/YOUR_ORG/index.json
```

**Azure Artifacts:**
```bash
dotnet nuget push ./nupkg/DevSecretStash.0.1.0.nupkg \
  --api-key az \
  --source https://pkgs.dev.azure.com/YOUR_ORG/_packaging/YOUR_FEED/nuget/v3/index.json
```

**Self-hosted (BaGet):**
```bash
docker run -d -p 5555:80 loic-sharma/baget
dotnet nuget push ./nupkg/DevSecretStash.0.1.0.nupkg \
  --source http://localhost:5555/v3/index.json
```

## Security Model

| Layer | Mechanism | Purpose |
|-------|-----------|---------|
| Password auth | Argon2id (server-side) | Verify identity |
| Key wrapping | Argon2id (client-side) + AES-256-GCM | Protect master key with password |
| Secret encryption | AES-256-GCM | Encrypt secrets before upload |
| Transport | HTTPS (HSTS in production) | Protect data in transit |
| Local credentials | chmod 600 (Linux/Mac) | Protect cached master key on disk |
| API | JWT (15min) + refresh tokens (30d, rotation) | Stateless auth with revocation |
| Rate limiting | 10 attempts / 15 min per IP | Prevent brute force |

The server **never** sees your plaintext secrets. The encryption key never leaves your machine.

## Development

```bash
# Build
dotnet build

# Run tests (60 total)
dotnet test

# Run the API in development mode
dotnet run --project src/DevSecretStash.Api

# Run the CLI
dotnet run --project src/DevSecretStash.Cli -- --help
```

## License

MIT
