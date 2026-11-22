# Hermes Backend

Self-hosted, personalized threat intelligence: simulated vulnerability scanning over an iTop CMDB,
correlation with threat news, a deterministic scoring engine plus an LLM judge, iTop tickets and
notification events.

## Requirements

- Python 3.12.16 and [uv](https://docs.astral.sh/uv/)
- Docker (PostgreSQL 18 + pgvector, Semgrep, test services)
- Linux or WSL2

## Development

```bash
uv sync          # install dependencies
make verify      # quality gate
make up          # local stack: writes the Docker secret files from your env file, then docker compose up
```

Copy `.env.example` to `.env` and set at least `POSTGRES_PASSWORD`, `MIGRATOR_DB_PASSWORD`, `APP_DB_PASSWORD` and
`RETENTION_DB_PASSWORD` before `make up`.

## License

Apache-2.0
