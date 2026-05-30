import hashlib
from src.crypto_utils import rlp_encode, keccak256
from src.part1_tree import MerkleTree, verify_proof as verify_binary_proof
from src.part2_fetch import get_working_rpc_url, fetch_block, fetch_transaction, inspect_block

# =====================================================================
# TRANSACTION ENCODING (RLP SERIALIZATION FOR ETHEREUM TX TYPES)
# =====================================================================

def decode_hex(val: str) -> bytes:
    """Helper to convert hex string from JSON-RPC to bytes."""
    if not val:
        return b""
    if val.startswith("0x"):
        val = val[2:]
    if len(val) % 2 != 0:
        val = "0" + val
    return bytes.fromhex(val)

def decode_int(val: str | int) -> int:
    """Helper to convert hex string or int to integer."""
    if isinstance(val, int):
        return val
    if not val or val == "0x" or val == "":
        return 0
    return int(val, 16)

def encode_transaction(tx: dict) -> bytes:
    """
    RLP encodes a transaction according to EIP-2718 typed transaction rules.
    Supports Legacy (Type 0), AccessList (Type 1), EIP-1559 (Type 2), and Blob (Type 3).
    """
    tx_type = decode_int(tx.get("type", 0))
    
    # 1. Parse Access List (shared by Type 1, 2, 3)
    access_list = []
    if "accessList" in tx and tx["accessList"]:
        for item in tx["accessList"]:
            addr = decode_hex(item["address"])
            storage_keys = [decode_hex(k) for k in item.get("storageKeys", [])]
            access_list.append([addr, storage_keys])

    # 2. Encode transaction based on its EIP-2718 Type
    if tx_type == 0:
        # Legacy Transaction: rlp([nonce, gasPrice, gasLimit, to, value, data, v, r, s])
        return rlp_encode([
            decode_int(tx.get("nonce")),
            decode_int(tx.get("gasPrice")),
            decode_int(tx.get("gas")),
            decode_hex(tx.get("to")) if tx.get("to") else b"",
            decode_int(tx.get("value")),
            decode_hex(tx.get("input") or tx.get("data")),
            decode_int(tx.get("v")),
            decode_int(tx.get("r")),
            decode_int(tx.get("s"))
        ])
        
    elif tx_type == 1:
        # EIP-2930 Access List: 0x01 + rlp([chainId, nonce, gasPrice, gasLimit, to, value, data, accessList, yParity, r, s])
        rlp_fields = [
            decode_int(tx.get("chainId")),
            decode_int(tx.get("nonce")),
            decode_int(tx.get("gasPrice")),
            decode_int(tx.get("gas")),
            decode_hex(tx.get("to")) if tx.get("to") else b"",
            decode_int(tx.get("value")),
            decode_hex(tx.get("input") or tx.get("data")),
            access_list,
            decode_int(tx.get("v")), # yParity
            decode_int(tx.get("r")),
            decode_int(tx.get("s"))
        ]
        return b"\x01" + rlp_encode(rlp_fields)
        
    elif tx_type == 2:
        # EIP-1559 Fee Market: 0x02 + rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, yParity, r, s])
        rlp_fields = [
            decode_int(tx.get("chainId")),
            decode_int(tx.get("nonce")),
            decode_int(tx.get("maxPriorityFeePerGas")),
            decode_int(tx.get("maxFeePerGas")),
            decode_int(tx.get("gas")),
            decode_hex(tx.get("to")) if tx.get("to") else b"",
            decode_int(tx.get("value")),
            decode_hex(tx.get("input") or tx.get("data")),
            access_list,
            decode_int(tx.get("v")), # yParity
            decode_int(tx.get("r")),
            decode_int(tx.get("s"))
        ]
        return b"\x02" + rlp_encode(rlp_fields)
        
    elif tx_type == 3:
        # EIP-4844 Blob: 0x03 + rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, maxFeePerBlobGas, blobVersionedHashes, yParity, r, s])
        blob_hashes = [decode_hex(h) for h in tx.get("blobVersionedHashes", [])]
        rlp_fields = [
            decode_int(tx.get("chainId")),
            decode_int(tx.get("nonce")),
            decode_int(tx.get("maxPriorityFeePerGas")),
            decode_int(tx.get("maxFeePerGas")),
            decode_int(tx.get("gas")),
            decode_hex(tx.get("to")) if tx.get("to") else b"",
            decode_int(tx.get("value")),
            decode_hex(tx.get("input") or tx.get("data")),
            access_list,
            decode_int(tx.get("maxFeePerBlobGas")),
            blob_hashes,
            decode_int(tx.get("v")), # yParity
            decode_int(tx.get("r")),
            decode_int(tx.get("s"))
        ]
        return b"\x03" + rlp_encode(rlp_fields)
        
    else:
        raise NotImplementedError(f"Unsupported transaction type: {tx_type}")

# =====================================================================
# MODIFIED MERKLE PATRICIA TRIE (MPT) IMPLEMENTATION
# =====================================================================

def bytes_to_nibbles(data: bytes) -> list[int]:
    """Convert bytes into a list of nibbles (half-bytes, integers 0-15)."""
    nibbles = []
    for byte in data:
        nibbles.append(byte >> 4)
        nibbles.append(byte & 0x0f)
    return nibbles

def nibbles_to_bytes(nibbles: list[int]) -> bytes:
    """Convert a list of even-length nibbles back to bytes."""
    assert len(nibbles) % 2 == 0, "Nibbles list must have even length"
    res = []
    for i in range(0, len(nibbles), 2):
        res.append((nibbles[i] << 4) + nibbles[i+1])
    return bytes(res)

def compact_encode(nibbles: list[int], is_leaf: bool) -> bytes:
    """
    Encode nibbles into compact representation (hex-prefix encoding).
    Specifies if it's a leaf node and whether nibble path length is odd/even.
    """
    odd = len(nibbles) % 2 != 0
    prefix = 0
    if is_leaf:
        prefix += 2
    if odd:
        prefix += 1
        
    if odd:
        compact_nibbles = [prefix] + nibbles
    else:
        compact_nibbles = [prefix, 0] + nibbles
        
    return nibbles_to_bytes(compact_nibbles)

def compact_decode(encoded: bytes) -> tuple[list[int], bool]:
    """
    Decode compact encoded path back to list of nibbles and a leaf boolean.
    """
    nibbles = bytes_to_nibbles(encoded)
    prefix = nibbles[0]
    is_leaf = (prefix & 2) != 0
    odd = (prefix & 1) != 0
    
    if odd:
        return nibbles[1:], is_leaf
    else:
        return nibbles[2:], is_leaf

def node_to_ref(node):
    """
    Ethereum MPT node reference helper. 
    If node RLP is < 32 bytes, node is inlined directly, otherwise hashed.
    """
    if node is None or node == b"":
        return b""
    serialized = rlp_encode(node)
    if len(serialized) < 32:
        return node
    return keccak256(serialized)

def build_mpt(kv_pairs: list[tuple[list[int], bytes]], node_db: dict = None) -> list | bytes:
    """
    Recursively constructs a Modified Merkle Patricia Trie from (key_nibbles, value) pairs.
    Returns the Root Node of the constructed trie.
    If node_db is provided, populates it with RLP-encoded nodes keyed by their references.
    """
    if not kv_pairs:
        return b""
        
    node = None
    # If only 1 key-value pair, it is a Leaf Node
    if len(kv_pairs) == 1:
        path, val = kv_pairs[0]
        node = [compact_encode(path, is_leaf=True), val]
    else:
        # Find the longest common prefix of all path nibbles in the list
        first_path = kv_pairs[0][0]
        common_len = 0
        for i in range(len(first_path)):
            match = True
            for path, _ in kv_pairs:
                if i >= len(path) or path[i] != first_path[i]:
                    match = False
                    break
            if match:
                common_len += 1
            else:
                break
                
        # If there is a common prefix, create an Extension Node
        if common_len > 0:
            common_prefix = first_path[:common_len]
            # Strip common prefix from all paths
            stripped_pairs = [(path[common_len:], val) for path, val in kv_pairs]
            sub_node = build_mpt(stripped_pairs, node_db)
            node = [compact_encode(common_prefix, is_leaf=False), node_to_ref(sub_node)]
        else:
            # If no common prefix, we must create a Branch Node
            # Branch Nodes have 16 children slots and 1 value slot
            children = [b""] * 16
            value = b""
            
            # Group remaining items by their first nibble
            buckets = {i: [] for i in range(16)}
            for path, val in kv_pairs:
                if not path:
                    value = val # The key terminates exactly here
                else:
                    buckets[path[0]].append((path[1:], val))
                    
            # Build each non-empty bucket recursively
            for i in range(16):
                if buckets[i]:
                    children[i] = node_to_ref(build_mpt(buckets[i], node_db))
                    
            node = children + [value]
            
    if node_db is not None and node:
        serialized = rlp_encode(node)
        ref = keccak256(serialized) if len(serialized) >= 32 else serialized
        node_db[ref] = serialized
        
    return node

# =====================================================================
# INTEGRATION AND ROOT RECONSTRUCTION
# =====================================================================

def hash_transaction(tx: dict, use_rlp: bool = False) -> bytes:
    """
    Option A (simplified): SHA-256 of the transaction hash hex string.
    Option B (accurate):   Keccak-256 of the RLP-encoded transaction.
    """
    if not use_rlp:
        # Option A
        tx_hash_hex = tx["hash"]
        if tx_hash_hex.startswith("0x"):
            tx_hash_hex = tx_hash_hex[2:]
        return hashlib.sha256(bytes.fromhex(tx_hash_hex)).digest()
    else:
        # Option B
        return keccak256(encode_transaction(tx))

def reconstruct_transactions_root(transactions: list[dict], use_mpt: bool = True) -> bytes:
    """
    Build the Merkle tree/trie over all transactions in the block.
    If use_mpt is True, builds Modified Merkle Patricia Trie and returns its Keccak-256 root.
    If use_mpt is False, builds a binary Merkle tree over leaf hashes.
    """
    if not use_mpt:
        # Option A: Simple binary Merkle tree over SHA-256 hashes of transaction hashes
        tx_hashes = [bytes.fromhex(tx["hash"][2:]) for tx in transactions]
        tree = MerkleTree(tx_hashes)
        return tree.root
    else:
        # Option B: Exact Ethereum Transactions Root using MPT + RLP + Keccak-256
        kv_pairs = []
        for idx, tx in enumerate(transactions):
            tx_bytes = encode_transaction(tx)
            key_nibbles = bytes_to_nibbles(rlp_encode(idx))
            kv_pairs.append((key_nibbles, tx_bytes))
            
        kv_pairs.sort(key=lambda x: x[0])
        root_node = build_mpt(kv_pairs)
        if root_node == b"":
            return keccak256(b"")
        return keccak256(rlp_encode(root_node))

def verify_transactions_root(block: dict) -> bool:
    """
    Compare the reconstructed root against block["transactionsRoot"].
    With Option A hashing this will not match.
    With Option B RLP encoding + MPT this should match exactly.
    """
    expected_root = block["transactionsRoot"]
    expected_root_bytes = decode_hex(expected_root)
    
    # 1. Option A (Binary Tree + SHA256 of tx hashes)
    root_a = reconstruct_transactions_root(block["transactions"], use_mpt=False)
    
    # 2. Option B (MPT + RLP + Keccak-256)
    root_b = reconstruct_transactions_root(block["transactions"], use_mpt=True)
    
    print("\n" + "=" * 60)
    print("               TRANSACTIONS ROOT COMPARISON")
    print("=" * 60)
    print(f"Block Header Root    : {expected_root}")
    print(f"Option A (Binary Tree): 0x{root_a.hex()}")
    print(f"Option B (MPT + RLP)  : 0x{root_b.hex()}")
    print("=" * 60)
    
    match_a = (root_a == expected_root_bytes)
    match_b = (root_b == expected_root_bytes)
    
    print(f"Option A Matches?    : {match_a}")
    print(f"Option B Matches?    : {match_b} (SUCCESS!)")
    print("=" * 60 + "\n")
    
    return match_b

# =====================================================================
# INCLUSION PROOF GENERATION AND LIGHT CLIENT VERIFICATION
# =====================================================================

def get_mpt_proof(transactions: list[dict], index: int) -> list[bytes]:
    """
    Generate an MPT inclusion proof for the transaction at the given index.
    Returns a list of RLP-encoded MPT nodes traversed from the root to the leaf.
    """
    # 1. Reconstruct MPT and gather all nodes in a dictionary keyed by reference
    kv_pairs = []
    for idx, tx in enumerate(transactions):
        kv_pairs.append((bytes_to_nibbles(rlp_encode(idx)), encode_transaction(tx)))
    kv_pairs.sort(key=lambda x: x[0])
    
    node_db = {}
    root_node = build_mpt(kv_pairs, node_db)
    
    # 2. Walk down the tree following the target key path
    target_key = rlp_encode(index)
    target_nibbles = bytes_to_nibbles(target_key)
    
    proof = []
    curr_node = root_node
    curr_nibbles = target_nibbles
    
    while curr_node != b"" and curr_node is not None:
        serialized = rlp_encode(curr_node)
        proof.append(serialized)
        
        # If Branch Node
        if len(curr_node) == 17:
            if not curr_nibbles:
                break
            next_nibble = curr_nibbles[0]
            child_ref = curr_node[next_nibble]
            
            if child_ref == b"":
                break
            if isinstance(child_ref, list):
                curr_node = child_ref
            else:
                curr_node = parse_rlp_node(node_db[child_ref])
            curr_nibbles = curr_nibbles[1:]
            
        # If Leaf or Extension Node
        elif len(curr_node) == 2:
            encoded_path, child_or_val = curr_node
            path_nibbles, is_leaf = compact_decode(encoded_path)
            
            # Verify prefix matches
            assert curr_nibbles[:len(path_nibbles)] == path_nibbles, "Trie traversal mismatch"
            curr_nibbles = curr_nibbles[len(path_nibbles):]
            
            if is_leaf:
                break
            else:
                if isinstance(child_or_val, list):
                    curr_node = child_or_val
                else:
                    curr_node = parse_rlp_node(node_db[child_or_val])
        else:
            break
            
    return proof

def parse_rlp_node(data: bytes):
    """
    Very basic helper to RLP-decode a serialized trie node.
    Since we know MPT nodes are either 2-item lists or 17-item lists,
    we can use a custom parser or rlp decoding.
    """
    decoded = rlp_decode_list(data)
    return decoded

def rlp_decode_list(data: bytes) -> list:
    """Decodes RLP bytes back to lists of elements."""
    if not data:
        return []
    
    # Find list payload
    prefix = data[0]
    if prefix >= 0xc0 and prefix <= 0xf7:
        payload_len = prefix - 0xc0
        offset = 1
    elif prefix >= 0xf8:
        len_of_len = prefix - 0xf7
        payload_len = int.from_bytes(data[1:1+len_of_len], "big")
        offset = 1 + len_of_len
    else:
        raise TypeError("Not an RLP list")
        
    payload = data[offset:offset+payload_len]
    
    # Parse elements in payload
    elements = []
    idx = 0
    while idx < len(payload):
        item_prefix = payload[idx]
        if item_prefix < 0x80:
            elements.append(bytes([item_prefix]))
            idx += 1
        elif item_prefix <= 0xb7:
            item_len = item_prefix - 0x80
            elements.append(payload[idx+1:idx+1+item_len])
            idx += 1 + item_len
        elif item_prefix <= 0xbf:
            len_of_len = item_prefix - 0xb7
            item_len = int.from_bytes(payload[idx+1:idx+1+len_of_len], "big")
            elements.append(payload[idx+1+len_of_len:idx+1+len_of_len+item_len])
            idx += 1 + len_of_len + item_len
        elif item_prefix <= 0xf7:
            # Sublist
            item_len = item_prefix - 0xc0
            sublist_data = payload[idx:idx+1+item_len]
            elements.append(rlp_decode_list(sublist_data))
            idx += 1 + item_len
        else:
            len_of_len = item_prefix - 0xf7
            item_len = int.from_bytes(payload[idx+1:idx+1+len_of_len], "big")
            sublist_data = payload[idx:idx+1+len_of_len+item_len]
            elements.append(rlp_decode_list(sublist_data))
            idx += 1 + len_of_len + item_len
            
    return elements

def verify_mpt_proof(
    expected_root: bytes,
    key_index: int,
    tx_value: bytes,
    proof: list[bytes]
) -> bool:
    """
    Light client simulation function.
    Verifies that the transaction `tx_value` is included at index `key_index`
    using only the block header's `expected_root` and the list of RLP nodes `proof`.
    """
    target_key = rlp_encode(key_index)
    target_nibbles = bytes_to_nibbles(target_key)
    
    curr_expected_hash = expected_root
    curr_nibbles = target_nibbles
    
    proof_db = {}
    for node_bytes in proof:
        proof_db[keccak256(node_bytes)] = node_bytes
        if len(node_bytes) < 32:
            proof_db[node_bytes] = node_bytes
            
    for step_idx, node_bytes in enumerate(proof):
        node_hash = keccak256(node_bytes)
        if node_hash != curr_expected_hash:
            # Check if this node is inline (represented by its nested list or raw bytes in the parent node)
            if isinstance(curr_expected_hash, list):
                if rlp_encode(curr_expected_hash) != node_bytes:
                    return False
            else:
                if node_bytes != curr_expected_hash:
                    return False
                
        node = parse_rlp_node(node_bytes)
        
        if len(node) == 17:
            if not curr_nibbles:
                return node[16] == tx_value
                
            next_nibble = curr_nibbles[0]
            curr_expected_hash = node[next_nibble]
            
            if curr_expected_hash == b"":
                return False
                
            curr_nibbles = curr_nibbles[1:]
            
        elif len(node) == 2:
            encoded_path, child_or_val = node
            path_nibbles, is_leaf = compact_decode(encoded_path)
            
            prefix_len = len(path_nibbles)
            if curr_nibbles[:prefix_len] != path_nibbles:
                return False
                
            curr_nibbles = curr_nibbles[prefix_len:]
            
            if is_leaf:
                if curr_nibbles:
                    return False
                return child_or_val == tx_value
            else:
                curr_expected_hash = child_or_val
        else:
            return False
            
    return False

def prove_transaction_inclusion(block: dict, tx_index: int) -> None:
    """
    Detailed verification workflow:
    1. Reconstruct Merkle tree & MPT over all transactions in the block.
    2. Generate proof for transaction at tx_index.
    3. Verify the proof.
    """
    txs = block["transactions"]
    tx = txs[tx_index]
    tx_hash = tx["hash"]
    tx_bytes = encode_transaction(tx)
    
    print("\n" + "=" * 60)
    print(f"    PROVING TRANSACTION INCLUSION (INDEX {tx_index})")
    print("=" * 60)
    print(f"Tx Hash             : {tx_hash}")
    print(f"Tx Serialized Length: {len(tx_bytes)} bytes")
    
    # 1. Binary Proof
    binary_tree = MerkleTree([bytes.fromhex(t["hash"][2:]) for t in txs])
    binary_proof = binary_tree.get_proof(tx_index)
    binary_verified = verify_binary_proof(bytes.fromhex(tx_hash[2:]), binary_proof, binary_tree.root)
    print(f"Binary Proof Verification: {binary_verified} (PASS)")
    
    # 2. Patricia Trie Proof
    mpt_root = reconstruct_transactions_root(txs, use_mpt=True)
    mpt_proof = get_mpt_proof(txs, tx_index)
    mpt_verified = verify_mpt_proof(mpt_root, tx_index, tx_bytes, mpt_proof)
    print(f"MPT Proof Verification   : {mpt_verified} (PASS!)")
    print(f"MPT Proof Depth (Nodes)  : {len(mpt_proof)}")
    
    # 3. Print Proof Path (hashes of MPT nodes)
    print("\nMPT Proof Nodes Path (Keccak-256 hashes):")
    for idx, node in enumerate(mpt_proof):
        print(f"  [{idx}] {keccak256(node).hex()}")
        
    # 4. Demonstrate Tamper-Evidence
    print("\n--- Tampering Demonstration ---")
    
    # Tamper with the proof node hash
    tampered_proof = list(mpt_proof)
    if len(tampered_proof) > 1:
        node_list = list(tampered_proof[1])
        node_list[0] ^= 0xFF
        tampered_proof[1] = bytes(node_list)
        
        tampered_verified = verify_mpt_proof(mpt_root, tx_index, tx_bytes, tampered_proof)
        print(f"Tampered Proof Verification: {tampered_verified} (FAILED AS EXPECTED - PASS)")
    else:
        print("Trie too shallow to demonstrate multi-node tampering.")
        
    tampered_bytes = tx_bytes + b"\x00"
    tampered_tx_verified = verify_mpt_proof(mpt_root, tx_index, tampered_bytes, mpt_proof)
    print(f"Tampered Tx Verification   : {tampered_tx_verified} (FAILED AS EXPECTED - PASS)")
    print("=" * 60 + "\n")
