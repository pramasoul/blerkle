import pytest

import logging

from blerkle import BLERK

# Configure logging
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.StreamHandler()])  # StreamHandler logs to console

# Now you can use logging in your tests
def test_example():
    logging.debug("This is a debug message.")


@pytest.fixture
def bk():
    return BLERK()


def test_create(bk):
    assert type(bk) == BLERK

def test_ingest(bk):
    n = 10
    assert bk.ingest('t10.b3sum') == n
    assert sum(len(l) for l in bk.file_list_from_directory.values()) == n
    assert sum(len(l) for l in bk.file_path_list_from_hash.values()) == n
    
@pytest.mark.slow
def test_ingest_pig(bk):
    n = 314113
    assert bk.ingest('/lake/archive/b3sums/frs_1t1.b3sum') == n
    assert sum(len(l) for l in bk.file_list_from_directory.values()) == n
    assert sum(len(l) for l in bk.file_path_list_from_hash.values()) == n
