"""Composition root of the Slack module (D-085): wires `notifications_slack` to the backend's `core`.

It is the only package allowed to import both; nothing imports it (import-linter). `python -m slack_app` runs the
Slack service; `python -m slack_app migrate` runs the module's own Alembic chain.
"""
