import logging
import os

from binascii import hexlify, unhexlify
from blake3 import blake3
from collections import defaultdict

class BLERK:
    def __init__(self):
        self.file_list_by_directory = defaultdict(list)
        self.file_path_list_by_hash = defaultdict(list)
        # A file tree has non-leaf nodes of [hash, dict of descendents by name]
        #  where hash can be None if not hashed_up yet, or a hash value if so
        # It has leaf nodes that are just the hash value of the file named
        self.file_tree = [None, {}]

    def ingest(self, fname: str) -> int:
        file_list_by_directory = self.file_list_by_directory
        file_path_list_by_hash = self.file_path_list_by_hash
        file_tree = self.file_tree
        with open(fname, 'rb') as f:
            #c53463deeea9c10dd85bfbc9ffa3ee99922c9efcd1da416a0f5a6eb84fa80e29  /lake/archive/copied_so_in_DDT/from_roto_stash/1t1/OPRAH/E0BW5533.TIF
            line_number = 0
            for line in f:
                line_number += 1
                if line[0] == ord('\\'):
                    # strange defect that appears in some b3sum output lines
                    logging.info(f"line {line_number}: line starting with `\\` which I am removing: {line}")
                    line = line[1:]

                try:
                    hex_file_hash, _, file_path = line.strip().partition(b' ')
                    assert _ == b' '
                    file_hash = unhexlify(hex_file_hash)
                    assert len(file_hash) == 32
                    
                    descent = file_path.split(b'/')
                    file_name = descent.pop()

                    # Note: There is a caching speedup for input sorted on pathname to implement
                    tree_node = file_tree
                    #logging.debug(f"descent {descent}")
                    for dname in descent:
                        if dname not in tree_node[1]:
                            tree_node[1][dname] = [None, {}]
                        tree_node = tree_node[1][dname]
                    tree_node[1][file_name] = file_hash

                    # OLD
                    dir_name = b'/'.join(descent)
                    #dir_name, _, file_name = os.path.normpath(file_path).rpartition(b'/')

                    # WRONG if just filename: assert _ == b'/'
                    #logging.debug(f"hash {hexlify(file_hash)}, dir {dir_name}, file {file_name}")
                except Exception as e:
                    logging.warning(f"line {line_number}: {e}\n in <<{line}>>")
                else:
                    file_list_by_directory[dir_name].append(file_name)
                    file_path_list_by_hash[file_hash].append(file_path)

            self.file_list_by_directory = file_list_by_directory
            self.file_path_list_by_hash = file_path_list_by_hash
            self.file_tree = file_tree
            #logging.debug(f"{self.file_list_by_directory}")

        return line_number
        
    def depth_first_traverse(self, node):
        if isinstance(node, tuple):
            for a_node in node[1].values():
                yield from self.depth_first_traverse(a_node)
        yield node

    def hash_up(self):
        return self.hash_up_node(self.file_tree)

    def hash_up_node(self, node):
        if not isinstance(node, list):
            logging.debug(f"hash_up_node: leaf node {hexlify(node)}")
            return node
        # FIXME: avoid recalc of node hash_up when can
        up_hash_value = blake3(b''.join(sorted(self.hash_up_node(a_node)
                                               for a_node in node[1].values()))).digest()
        node[0] = up_hash_value
        logging.debug(f"hash_up_node: interior node {hexlify(node[0])}")
        return up_hash_value
    
    def build_node_list_by_hash(self):
        self.node_list_by_hash = defaultdict(list)
        
