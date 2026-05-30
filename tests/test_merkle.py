import pytest
import hashlib
from src.crypto_utils import rlp_encode, keccak256, int_to_bytes
from src.part1_tree import MerkleTree, MerkleNode, sha256_pair, verify_proof
from src.part3_verify import (
    bytes_to_nibbles,
    compact_encode,
    compact_decode,
    build_mpt,
    verify_mpt_proof,
    get_mpt_proof
)

# =====================================================================
# 1. BINARY MERKLE TREE TESTS
# =====================================================================

def test_sha256_pair():
    """Verify sha256_pair correctly concatenates and double-hashes/single-hashes child values."""
    left = b"alice"
    right = b"bob"
    expected = hashlib.sha256(left + right).digest()
    assert sha256_pair(left, right) == expected

def test_merkle_tree_construction_even():
    """Test standard bottom-up tree builder over even counts of leaves."""
    items = [b"alice", b"bob", b"carol", b"dave"]
    tree = MerkleTree(items)
    
    # 4 leaves → Levels: Level 0 (4 items), Level 1 (2 items), Level 2 (1 root)
    assert len(tree.levels) == 3
    assert len(tree.levels[0]) == 4
    assert len(tree.levels[1]) == 2
    assert len(tree.levels[2]) == 1
    
    # Check that root matches manual computation
    h_a = hashlib.sha256(b"alice").digest()
    h_b = hashlib.sha256(b"bob").digest()
    h_c = hashlib.sha256(b"carol").digest()
    h_d = hashlib.sha256(b"dave").digest()
    
    h_ab = sha256_pair(h_a, h_b)
    h_cd = sha256_pair(h_c, h_d)
    h_abcd = sha256_pair(h_ab, h_cd)
    
    assert tree.root == h_abcd

def test_merkle_tree_construction_odd():
    """Test odd leaves count duplication convention."""
    items = [b"alice", b"bob", b"carol"]
    tree = MerkleTree(items)
    
    # 3 leaves → should duplicate 'carol' node during Level 1 construction
    assert len(tree.levels) == 3
    assert len(tree.levels[0]) == 3
    
    h_a = hashlib.sha256(b"alice").digest()
    h_b = hashlib.sha256(b"bob").digest()
    h_c = hashlib.sha256(b"carol").digest()
    
    h_ab = sha256_pair(h_a, h_b)
    h_cc = sha256_pair(h_c, h_c) # Duplicated leaf
    h_abcc = sha256_pair(h_ab, h_cc)
    
    assert tree.root == h_abcc

def test_merkle_tree_empty_leaves():
    """Assert empty leaf lists raise a ValueError."""
    with pytest.raises(ValueError):
        MerkleTree([])

def test_proof_generation_and_verification():
    """Test core get_proof and standalone verify_proof logic."""
    items = [b"alice", b"bob", b"carol", b"dave"]
    tree = MerkleTree(items)
    
    # Test valid leaf (carol)
    proof = tree.get_proof(2)
    assert len(proof) == 2 # 4 leaves → path has 2 sibling steps
    assert verify_proof(b"carol", proof, tree.root) is True
    
    # Tampering tests
    assert verify_proof(b"mallory", proof, tree.root) is False # Tampered leaf data
    
    tampered_proof = list(proof)
    tampered_proof[0] = {"hash": b"\x00" * 32, "position": tampered_proof[0]["position"]}
    assert verify_proof(b"carol", tampered_proof, tree.root) is False # Tampered proof sibling hash
    
    # Index out of bounds
    with pytest.raises(IndexError):
        tree.get_proof(4)
    with pytest.raises(IndexError):
        tree.get_proof(-1)

# =====================================================================
# 2. RLP & KECCAK-256 COMPLIANCE TESTS
# =====================================================================

def test_rlp_encoding_bytes_short():
    """Test short RLP bytes encoding (<55 bytes)."""
    assert rlp_encode(b"dog") == b"\x83dog"
    assert rlp_encode(b"") == b"\x80"

def test_rlp_encoding_string_short():
    """Test short string RLP encoding."""
    assert rlp_encode("dog") == b"\x83dog"

def test_rlp_encoding_int():
    """Test integer RLP conversion rules."""
    assert rlp_encode(0) == b"\x80" # 0 is serialized as empty bytes string
    assert rlp_encode(15) == b"\x0f" # Integers < 128 are mapped directly
    assert rlp_encode(1024) == b"\x82\x04\x00" # 1024 = 0x0400 (length 2 bytes)

def test_rlp_encoding_list():
    """Test list RLP list grouping rules."""
    assert rlp_encode([]) == b"\xc0"
    assert rlp_encode(["dog"]) == b"\xc4\x83dog" # c0 + 4, dog = 83dog

def test_keccak256_hashing():
    """Verify Keccak-256 hash outputs match expected standards."""
    # Keccak-256 of empty bytes
    assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    # Keccak-256 of 'test'
    assert keccak256(b"test").hex() == "9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658"

# =====================================================================
# 3. MERKLE PATRICIA TRIE (MPT) OFFLINE TESTS
# =====================================================================

def test_bytes_to_nibbles():
    """Test byte-to-nibble unpacking logic."""
    assert bytes_to_nibbles(b"\x12\x34") == [1, 2, 3, 4]

def test_compact_encoding_even_leaf():
    """Test compact path encoding for even-length leaf node paths."""
    # even length (4 nibbles), is_leaf=True → prefix 0x20
    assert compact_encode([1, 2, 3, 4], is_leaf=True) == b"\x20\x12\x34"

def test_compact_encoding_odd_leaf():
    """Test compact path encoding for odd-length leaf node paths."""
    # odd length (3 nibbles), is_leaf=True → prefix 0x3 + first nibble
    assert compact_encode([1, 2, 3], is_leaf=True) == b"\x31\x23"

def test_compact_encoding_even_extension():
    """Test compact path encoding for even-length extension paths."""
    # even length (4 nibbles), is_leaf=False → prefix 0x00
    assert compact_encode([1, 2, 3, 4], is_leaf=False) == b"\x00\x12\x34"

def test_compact_encoding_odd_extension():
    """Test compact path encoding for odd-length extension paths."""
    # odd length (3 nibbles), is_leaf=False → prefix 0x1 + first nibble
    assert compact_encode([1, 2, 3], is_leaf=False) == b"\x11\x23"

def test_compact_decoding():
    """Test compact path decodings restore original paths correctly."""
    # Leaf path odd len
    path, is_leaf = compact_decode(b"\x31\x23")
    assert path == [1, 2, 3]
    assert is_leaf is True
    
    # Extension path even len
    path, is_leaf = compact_decode(b"\x00\x12\x34")
    assert path == [1, 2, 3, 4]
    assert is_leaf is False

def test_mpt_trie_construction_and_verification_offline():
    """Test MPT trie construction, proof generation, and verification 100% offline."""
    # We construct a mock transaction dataset containing 3 small transaction payloads
    tx1 = b"tx1payload"
    tx2 = b"tx2payload"
    tx3 = b"tx3payload"
    
    # Reconstruct trie keys (RLP-encoded indices) and values
    kv_pairs = []
    for idx, tx_bytes in enumerate([tx1, tx2, tx3]):
        key = rlp_encode(idx)
        kv_pairs.append((bytes_to_nibbles(key), tx_bytes))
        
    kv_pairs.sort(key=lambda x: x[0])
    
    # Build trie
    node_db = {}
    root_node = build_mpt(kv_pairs, node_db)
    
    # Compute root
    root_hash = keccak256(rlp_encode(root_node))
    
    # Generate proof for index 1 (tx2)
    proof = []
    target_key = rlp_encode(1)
    target_nibbles = bytes_to_nibbles(target_key)
    
    # Walk down the mock trie to collect proof nodes
    curr_node = root_node
    curr_nibbles = target_nibbles
    while curr_node != b"" and curr_node is not None:
        serialized = rlp_encode(curr_node)
        proof.append(serialized)
        
        if len(curr_node) == 17:
            next_nibble = curr_nibbles[0]
            child_ref = curr_node[next_nibble]
            if child_ref == b"":
                break
            if isinstance(child_ref, list):
                curr_node = child_ref
            else:
                curr_node = rlp_decode_list(node_db[child_ref])
            curr_nibbles = curr_nibbles[1:]
        elif len(curr_node) == 2:
            encoded_path, child_or_val = curr_node
            path_nibbles, is_leaf = compact_decode(encoded_path)
            curr_nibbles = curr_nibbles[len(path_nibbles):]
            if is_leaf:
                break
            else:
                if isinstance(child_or_val, list):
                    curr_node = child_or_val
                else:
                    curr_node = rlp_decode_list(node_db[child_or_val])
        else:
            break
            
    # Verify using light client function (offline)
    is_valid = verify_mpt_proof(root_hash, 1, tx2, proof)
    assert is_valid is True
    
    # Verification with tampered values must fail
    assert verify_mpt_proof(root_hash, 1, tx1, proof) is False # Wrong transaction
    assert verify_mpt_proof(root_hash, 0, tx2, proof) is False # Wrong key index

def rlp_decode_list(data: bytes) -> list:
    """Mock helper for offline tests."""
    from src.part3_verify import rlp_decode_list as original_decoder
    return original_decoder(data)
