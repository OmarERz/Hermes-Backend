"""Integration test setup: keep testcontainers' Ryuk reaper off.

Ryuk would run a container with the Docker socket mounted read-write and a control port open on all interfaces.
Tests clean up their own containers through context managers instead.
"""

from testcontainers.core.config import testcontainers_config

testcontainers_config.ryuk_disabled = True
testcontainers_config.ryuk_image = (
    "testcontainers/ryuk:0.8.1@sha256:bf3f74a47dee0acda89aba4b2fc9c7fdcf994a084db02a2d06566f07baae022e"
)
