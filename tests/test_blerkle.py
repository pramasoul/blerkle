import pytest

import logging

from blerkle import BLERK
from binascii import hexlify, unhexlify
from blake3 import blake3


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

def to_test_ingest(bk, bsname, n):
    assert bk.ingest(bsname) == n

    # OLD
    assert sum(len(l) for l in bk.file_list_from_directory.values()) == n
    assert sum(len(l) for l in bk.file_path_list_from_hash.values()) == n
    
def test_ingest(bk):
    to_test_ingest(bk, 't10.b3sum', 10)

@pytest.mark.slow
def test_ingest_pig(bk):
    to_test_ingest(bk, '/lake/archive/b3sums/frs_1t1.b3sum', 314113)

def test_hash_up_leaf_node(bk):
    assert bk.hash_up_node(b'foobar') == b'foobar'

def test_hash_up_interior_node(bk):
    node = (None, {'foo': b'abc', 'bar': b'def'}) # two leaves
    assert bk.hash_up_node(node) == blake3(b'abcdef').digest()

def test_hash_up_more(bk):
    node = (None, # not hashed-up yet
            {'foo': b'abc', # leaf
             'bar': b'def', # leaf
             'baz': (None, # not hashed-up yet
                     {'one': b'some one', # leaf
                      'two': b'some two', # leaf
                      },
                     ),
             })
    baz_hash = blake3(b'some onesome two').digest()
    expected = blake3(b''.join(sorted([b'abc', b'def', baz_hash]))).digest()

    assert bk.hash_up_node(node) == expected


def test_demo_blake3():
    v = blake3(b'abcdef').digest()
    # echo -n 'abcdef' | b3sum
    assert hexlify(v) == b'b34b56076712fd7fb9c067245a6c85e16174b3ef2e35df7b56b7f164e5c36446'

