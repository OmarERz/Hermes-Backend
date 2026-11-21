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
```

## License

Apache-2.0
