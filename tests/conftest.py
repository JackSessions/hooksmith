import pytest

from hooksmith.demo import demo_dir


@pytest.fixture
def demo():
    return demo_dir()
