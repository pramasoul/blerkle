import logging
import os

from binascii import hexlify, unhexlify
from blake3 import blake3
from collections import defaultdict
from dataclasses import dataclass, field

@dataclass
class FileTreeNode:
    hash_value: bytearray = b""
    children: dict[list] = field(default_factory=lambda: defaultdict(list))
    n_leaves: int = 0

class BLERK:
    def __init__(self):
        self.file_list_by_directory = defaultdict(list)
        self.file_path_list_by_hash = defaultdict(list)
        # A file tree has non-leaf nodes of [hash, dict of descendents by name]
        #  where hash can be None if not hashed_up yet, or a hash value if so
        # It has leaf nodes that are just the hash value of the file named
        self.file_tree = FileTreeNode()

    def ingest(self, fname: str) -> int:
        file_list_by_directory = self.file_list_by_directory
        file_path_list_by_hash = self.file_path_list_by_hash
        file_tree = self.file_tree
        with open(fname, 'rb') as f:
            #c53463deeea9c10dd85bfbc9ffa3ee99922c9efcd1da416a0f5a6eb84fa80e29  /lake/archive/copied_so_in_DDT/from_roto_stash/1t1/OPRAH/E0BW5533.TIF
            line_number = 0
            for line in f:
                line_number += 1
                while line[0] == ord('\\'):
                    # strange defect that appears in some b3sum output lines
                    logging.info(f"line {line_number}: line starting with `\\` which I am removing: {line}")
                    line = line[1:]

                try:
                    # two spaces separate hash in hex from file path, in b3sum output
                    hex_file_hash, _, file_path = line.strip().partition(b'  ')
                    assert _ == b'  '
                    file_hash = unhexlify(hex_file_hash)
                    assert len(file_hash) == 32
                    
                    descent = file_path.split(b'/')
                    file_name = descent.pop()

                    # Descend from the root node to this leaf
                    # Note: There is a caching speedup for input sorted on pathname to implement
                    tree_node = file_tree
                    tree_node.n_leaves += 1
                    #logging.debug(f"descent {descent}")

                    # Descend the path, creating nodes where necessary
                    for dname in descent:
                        if dname not in tree_node.children:
                            tree_node.children[dname] = FileTreeNode()
                        tree_node = tree_node.children[dname]
                        tree_node.n_leaves += 1

                    # Place the leaf value (the hash value from the output of the b3sum command)
                    tree_node.children[file_name] = file_hash
                except Exception as e:
                    logging.warning(f"line {line_number}: {e}\n in <<{line}>>")

            self.file_tree = file_tree
        return line_number
        
    def depth_first_traverse(self, node):
        if isinstance(node, FileTreeNode):
            for a_node in node.children.values():
                yield from self.depth_first_traverse(a_node)
        yield node

    def hash_up(self):
        return self.hash_up_node(self.file_tree)

    def hash_up_node(self, node):
        if not isinstance(node, FileTreeNode):
            logging.debug(f"hash_up_node: leaf node {node}")
            return node
        # FIXME: avoid recalc of node hash_up when can
        up_hash_value = blake3(b''.join(sorted(self.hash_up_node(a_node)
                                               for a_node in node.children.values()))).digest()
        node.hash_value = up_hash_value
        logging.debug(f"hash_up_node: interior node {hexlify(node.hash_value)}")
        return up_hash_value
    
    def build_node_list_by_hash(self):
        node_list_by_hash = defaultdict(list)
        for node in self.depth_first_traverse(self.file_tree):
            if isinstance(node, FileTreeNode):
                hv = node.hash_value
            elif isinstance(node, bytes):
                hv = node
            else:
                raise ValueError
            node_list_by_hash[hv].append(node)
        self.node_list_by_hash = node_list_by_hash
        return self.node_list_by_hash

    def check_node_list_by_hash(self):
        for node_list in self.node_list_by_hash.values():
            assert len(node_list) > 0
            assert type(node_list[0]) in (FileTreeNode, bytes)
            if len(node_list) > 1:
                if isinstance(node_list[0], bytes):
                    assert all(isinstance(node, bytes) for node in node_list)
                elif isinstance(node_list[0], FileTreeNode):
                    assert all(isinstance(node, FileTreeNode) for node in node_list)
                    assert all(node.n_leaves == node_list[0].n_leaves
                           for node in node_list[1:])

    def build_nodes_of_same_hashup_list(self):
        self.nodes_of_same_hashup_list = sorted((node_list
                                                 for node_list in self.node_list_by_hash.values() 
                                                 if len(node_list) > 1
                                                 and isinstance(node_list[0], FileTreeNode)),
                                                key=lambda v: len(v),
                                                reverse=True)
    
                
