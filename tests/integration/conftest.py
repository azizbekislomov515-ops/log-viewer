"""Integration tests touch the real Docker daemon / journal; they skip when unavailable."""

from collections.abc import Iterator
from typing import Any

import pytest

LOCAL_IMAGES = ("alpine:latest", "busybox:latest")  # never pulled: tests stay offline


@pytest.fixture
def docker_client() -> Iterator[Any]:
    docker = pytest.importorskip("docker")
    try:
        client = docker.from_env(timeout=10)
        client.ping()
    except Exception as exc:
        pytest.skip(f"Docker not reachable: {exc}")
    yield client
    client.close()


@pytest.fixture
def local_image(docker_client: Any) -> str:
    tags = {t for image in docker_client.images.list() for t in image.tags}
    for name in LOCAL_IMAGES:
        if name in tags:
            return name
    pytest.skip(f"none of {LOCAL_IMAGES} present locally (tests do not pull images)")
