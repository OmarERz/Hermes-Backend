"""Routers of the API (docs/13 API-06)."""

from fastapi import APIRouter

from api.routes import catalog, config, findings, operations, sources

routers: list[APIRouter] = [config.router, catalog.router, findings.router, operations.router, sources.router]
