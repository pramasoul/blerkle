import pytest

import logging

from blerkle import BLERK
from binascii import hexlify, unhexlify
from blake3 import blake3
from pprint import pformat

# Configure logging
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.StreamHandler()])  # StreamHandler logs to console

# Now you can use logging in your tests
def test_example():
    logging.debug("This is a debug message.")


CONTENT = "content"


def test_create_file(tmp_path):
    d = tmp_path / "sub"
    d.mkdir()
    p = d / "hello.txt"
    p.write_text(CONTENT, encoding="utf-8")
    assert p.read_text(encoding="utf-8") == CONTENT
    assert len(list(tmp_path.iterdir())) == 1

small_bfile_text =\
r"""0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef /foo
123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0 /bar
23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01 /baz/one
3456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012 /baz/two
"""
small_unrooted_bfile_text =\
r"""0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef foo
123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0 bar
23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01 baz/one
3456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012 baz/two
"""
@pytest.fixture
def small_bfile_path(tmp_path):
    file_path = tmp_path / "small.b3sum"
    file_path.write_text(small_bfile_text, encoding="utf-8")
    return file_path

def test_small_bfile_path(small_bfile_path):
    assert small_bfile_path.read_text(encoding="utf-8") == small_bfile_text

@pytest.fixture
def small_unrooted_bfile_path(tmp_path):
    file_path = tmp_path / "small_unrooted.b3sum"
    file_path.write_text(small_unrooted_bfile_text, encoding="utf-8")
    return file_path

@pytest.fixture
def bk():
    return BLERK()

@pytest.fixture
def short_bsum_file(small_bfile_path):
    #return 't10.b3sum', 10
    return small_bfile_path, 4

@pytest.fixture
def long_bsum_file():
    return '/lake/archive/b3sums/frs_1t1.b3sum', 314113

@pytest.fixture
def bk_short_ingested(bk, short_bsum_file):
    n = bk.ingest(short_bsum_file[0])
    return bk, n

def test_create(bk):
    assert type(bk) == BLERK
    assert isinstance(bk, BLERK)

def to_test_ingest(bk, bsname, n):
    assert bk.ingest(bsname) == n

    # OLD
    assert sum(len(l) for l in bk.file_list_by_directory.values()) == n
    assert sum(len(l) for l in bk.file_path_list_by_hash.values()) == n
    
def test_ingest(bk, short_bsum_file):
    fname, n = short_bsum_file
    to_test_ingest(bk, fname, n)

def test_unrooted_ingest(bk, small_unrooted_bfile_path):
    assert bk.ingest(small_unrooted_bfile_path) == 4
    #logging.debug(f"bk.file_tree {bk.file_tree}")
    #assert False

def test_bk_short_ingested(bk_short_ingested):
    bk, n = bk_short_ingested
    assert isinstance(bk, BLERK)
    #logging.debug(f"bk.file_tree {bk.file_tree}")
    #assert False

@pytest.mark.skip(reason="incorporated into test_pig")
def test_ingest_pig(bk, long_bsum_file):
    #to_test_ingest(bk, '/lake/archive/b3sums/frs_1t1.b3sum', 314113)
    fname, n = long_bsum_file
    to_test_ingest(bk, fname, n)

def test_demo_blake3():
    v = blake3(b'abcdef').digest()
    # echo -n 'abcdef' | b3sum
    assert hexlify(v) == b'b34b56076712fd7fb9c067245a6c85e16174b3ef2e35df7b56b7f164e5c36446'

def test_hash_up_leaf_node(bk):
    assert bk.hash_up_node(b'foobar') == b'foobar'

def test_hash_up_interior_node(bk):
    node = [None, {'foo': b'abc', 'bar': b'def'}] # two leaves
    assert bk.hash_up_node(node) == blake3(b'abcdef').digest()

@pytest.fixture
def small_node():
    node = [None, # not hashed-up yet
            {'foo': b'abc', # leaf
             'bar': b'def', # leaf
             'baz': [None, # not hashed-up yet
                     {'one': b'some one', # leaf
                      'two': b'some two', # leaf
                      },
                     ],
             }]
    return node

def test_hash_up_more(bk, small_node):
    node = small_node
    baz_hash = blake3(b'some onesome two').digest()
    expected = blake3(b''.join(sorted([b'abc', b'def', baz_hash]))).digest()
    assert bk.hash_up_node(node) == expected

def test_hash_up_short(bk_short_ingested):
    bk, n = bk_short_ingested
    logging.debug(f"bk.file_tree {pformat(bk.file_tree, width=132)}")
    root_hash = bk.hash_up()
    logging.debug(f"bk.file_tree {pformat(bk.file_tree, width=132)}")
    #for line in small_bfile_text.splitlines():
    #    logging.info(line.split()[0])
    hashes = [unhexlify(line.split()[0]) for line in small_bfile_text.splitlines()]
    baz_hash = blake3(b''.join(sorted([hashes[2], hashes[3]]))).digest()
    logging.debug(f"baz_hash {hexlify(baz_hash)}")
    top_hash = blake3(b''.join(sorted([hashes[0], hashes[1], baz_hash]))).digest()
    expected = blake3(top_hash).digest()
    logging.debug(f"expected {hexlify(expected)}")
    assert hexlify(root_hash) == hexlify(expected)

@pytest.mark.skip(reason="FIXME")
def test_depth_first_traverse(bk, small_node):
    for node in bk.depth_first_traverse(small_node):
        logging.debug(f"node {node}")
    root_hash = bk.hash_up()
    assert sum(1 for node in bk.depth_first_traverse(small_node)) == 99
    

@pytest.mark.slow
def test_pig(bk, long_bsum_file):
    fname, n = long_bsum_file
    to_test_ingest(bk, fname, n)
    # Weak: from a run, so no proof of correctness
    expected = b'512c443b85fe8675c7961ee8a2a7b65ab8529ee903336010a645842db8f877f9'
    assert hexlify(bk.hash_up()) == expected
    

