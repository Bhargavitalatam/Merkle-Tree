import hashlib
from dataclasses import dataclass

def sha256_pair(left: bytes, right: bytes) -> bytes:
    """Hash two child digests together to produce a parent node hash."""
    return hashlib.sha256(left + right).digest()

@dataclass
class MerkleNode:
    hash: bytes
    left: "MerkleNode | None" = None
    right: "MerkleNode | None" = None

class MerkleTree:
    def __init__(self, leaves: list[bytes]):
        """
        Build a Merkle tree from a list of raw data items.
        Each item is hashed to form a leaf node.
        If the number of leaves is odd, duplicate the last leaf (standard convention).
        """
        if not leaves:
            raise ValueError("Leaves list cannot be empty")
        
        # Hash all raw data items to form standard SHA-256 leaf hashes
        leaf_hashes = [hashlib.sha256(item).digest() for item in leaves]
        leaf_nodes = [MerkleNode(hash=h) for h in leaf_hashes]
        
        # levels will store lists of MerkleNodes at each level of the tree,
        # starting from the leaf level up to the root level.
        self.levels: list[list[MerkleNode]] = []
        self.root_node = self._build(leaf_nodes)

    def _build(self, nodes: list[MerkleNode]) -> MerkleNode:
        """
        Recursively pair up nodes and hash each pair until one root remains.
        """
        self.levels.append(nodes)
        
        if len(nodes) == 1:
            return nodes[0]
            
        next_level = []
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            if i + 1 < len(nodes):
                right = nodes[i+1]
            else:
                # Duplicate the last node at this level for the sibling
                right = MerkleNode(hash=left.hash, left=left.left, right=left.right)
            
            parent_hash = sha256_pair(left.hash, right.hash)
            parent_node = MerkleNode(hash=parent_hash, left=left, right=right)
            next_level.append(parent_node)
            
        return self._build(next_level)

    @property
    def root(self) -> bytes:
        """Return the Merkle root hash."""
        return self.root_node.hash

    def get_proof(self, index: int) -> list[dict]:
        """
        Generate a Merkle proof for the leaf at the given index.
        Returns a list of {"hash": bytes, "position": "left" | "right"} dicts,
        ordered from leaf-level sibling up to the child of the root.
        """
        if index < 0 or index >= len(self.levels[0]):
            raise IndexError("Leaf index out of range")
            
        proof = []
        curr_idx = index
        
        # Traverses from the leaf level up to the level just below the root
        for level_idx in range(len(self.levels) - 1):
            level = self.levels[level_idx]
            
            if curr_idx % 2 == 0:
                # Our node is at an even index: its sibling is at index + 1
                if curr_idx + 1 < len(level):
                    sibling_hash = level[curr_idx + 1].hash
                else:
                    # Odd number of nodes: the sibling is a duplicate of our node
                    sibling_hash = level[curr_idx].hash
                position = "right"
            else:
                # Our node is at an odd index: its sibling is at index - 1
                sibling_hash = level[curr_idx - 1].hash
                position = "left"
                
            proof.append({"hash": sibling_hash, "position": position})
            curr_idx //= 2
            
        return proof

def verify_proof(
    leaf_data: bytes,
    proof: list[dict],
    expected_root: bytes,
) -> bool:
    """
    Verify a Merkle proof without access to the full tree.
    Hash the leaf, then iteratively combine with each sibling hash in the proof.
    Return True if the recomputed root matches expected_root.
    """
    curr_hash = hashlib.sha256(leaf_data).digest()
    for step in proof:
        sibling_hash = step["hash"]
        position = step["position"]
        if position == "left":
            curr_hash = sha256_pair(sibling_hash, curr_hash)
        else:
            curr_hash = sha256_pair(curr_hash, sibling_hash)
    return curr_hash == expected_root
