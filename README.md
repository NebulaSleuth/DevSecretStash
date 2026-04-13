# DevSecrets

Securely sync .NET user-secrets across machines with end-to-end encryption.

DevSecrets consists of a **CLI tool** (dotnet global tool) and a **web service** (ASP.NET Core). Secrets are encrypted on your machine before upload — the server never sees plaintext.

## How It Works

```
[Your Machine]                    [DevSecrets Server]                [Another Machine]
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
docker build -t devsecrets-api -f src/DevSecrets.Api/Dockerfile .
docker run -d -p 8080:8080 \
  -v devsecrets-data:/app/data \
  -e Jwt__Key="your-production-secret-key-minimum-32-characters!" \
  devsecrets-api
```

**Option B: Run directly**
```bash
cd src/DevSecrets.Api
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
dotnet pack src/DevSecrets.Cli/DevSecrets.Cli.csproj -c Release -o ./nupkg

# Install globally from the local package
dotnet tool install --global --add-source ./nupkg DevSecrets
```

**Option B: From a NuGet feed**
```bash
# If published to NuGet.org:
dotnet tool install --global DevSecrets

# If published to a private feed:
dotnet tool install --global DevSecrets --add-source https://your-feed-url/v3/index.json
```

**Option C: From GitHub Packages**
```bash
dotnet nuget add source https://nuget.pkg.github.com/YOUR_ORG/index.json \
  --name github --username YOUR_USERNAME --password YOUR_PAT

dotnet tool install --global DevSecrets --add-source github
```

### 3. Configure and Use

```bash
# Point CLI at your server
devsecrets config --server-url https://your-server.example.com

# Create an account
devsecrets register

# Push secrets from a .NET project directory (auto-detects UserSecretsId from .csproj)
cd /path/to/your/dotnet/project
devsecrets push

# On another machine: install CLI, login, pull
devsecrets login
devsecrets pull
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `devsecrets config --server-url <url>` | Set the server URL |
| `devsecrets register` | Create a new account |
| `devsecrets login` | Authenticate and cache credentials |
| `devsecrets logout` | Clear cached credentials |
| `devsecrets push [UserSecretsId]` | Encrypt and upload local secrets |
| `devsecrets pull [UserSecretsId]` | Download and decrypt secrets locally |
| `devsecrets status [UserSecretsId]` | Show sync status (local vs remote) |
| `devsecrets list` | List all secret collections on the server |

**Global options:**
- `--verbose` / `-v` — Enable verbose output (shows HTTP requests/responses)

If `UserSecretsId` is omitted, the CLI scans the current directory for a `.csproj` file containing `<UserSecretsId>`.

## Web Dashboard

The server includes a browser-based dashboard at the root URL (`/`). Login with your DevSecrets account to:

- View all your synced secret collections
- See version numbers and last-modified timestamps
- Delete collections you no longer need

## Project Structure

```
DevSecrets/
  src/
    DevSecrets.Core/       # Shared: encryption (AES-256-GCM, Argon2id), models, DTOs
    DevSecrets.Api/        # ASP.NET Core server: REST API + Razor Pages dashboard
    DevSecrets.Cli/        # dotnet global tool: CLI commands
  tests/
    DevSecrets.Core.Tests/ # 25 unit tests (encryption, key management)
    DevSecrets.Api.Tests/  # 26 integration tests (auth, CRUD, user isolation)
    DevSecrets.Cli.Tests/  # 9 integration tests (full workflows)
```

## Server Configuration

Configuration via `appsettings.json` or environment variables:

| Setting | Env Variable | Default | Description |
|---------|-------------|---------|-------------|
| `ConnectionStrings:Default` | `ConnectionStrings__Default` | `Data Source=devsecrets.db` | SQLite connection string |
| `Jwt:Key` | `Jwt__Key` | *(dev key)* | **Change in production!** Min 32 chars |
| `Jwt:Issuer` | `Jwt__Issuer` | `DevSecrets` | JWT issuer/audience |
| `Jwt:AccessTokenMinutes` | `Jwt__AccessTokenMinutes` | `15` | Access token lifetime |
| `Jwt:RefreshTokenDays` | `Jwt__RefreshTokenDays` | `30` | Refresh token lifetime |

## Publishing the CLI to NuGet.org

To make the CLI installable anywhere via `dotnet tool install --global DevSecrets`:

```bash
# 1. Pack
dotnet pack src/DevSecrets.Cli/DevSecrets.Cli.csproj -c Release -o ./nupkg

# 2. Get a NuGet.org API key from https://www.nuget.org/account/apikeys

# 3. Push
dotnet nuget push ./nupkg/DevSecrets.0.1.0.nupkg \
  --api-key YOUR_NUGET_API_KEY \
  --source https://api.nuget.org/v3/index.json
```

Once published, anyone can install it:
```bash
dotnet tool install --global DevSecrets
```

To update:
```bash
dotnet tool update --global DevSecrets
```

## Private NuGet Feed (Alternative)

If you don't want to publish publicly, host a private feed:

**GitHub Packages:**
```bash
dotnet nuget push ./nupkg/DevSecrets.0.1.0.nupkg \
  --api-key YOUR_GITHUB_PAT \
  --source https://nuget.pkg.github.com/YOUR_ORG/index.json
```

**Azure Artifacts:**
```bash
dotnet nuget push ./nupkg/DevSecrets.0.1.0.nupkg \
  --api-key az \
  --source https://pkgs.dev.azure.com/YOUR_ORG/_packaging/YOUR_FEED/nuget/v3/index.json
```

**Self-hosted (BaGet):**
```bash
docker run -d -p 5555:80 loic-sharma/baget
dotnet nuget push ./nupkg/DevSecrets.0.1.0.nupkg \
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
dotnet run --project src/DevSecrets.Api

# Run the CLI
dotnet run --project src/DevSecrets.Cli -- --help
```

## License

MIT
