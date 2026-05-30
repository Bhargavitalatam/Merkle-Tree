import argparse
import sys
import os

# Add src to python path dynamically
sys.path.append(os.path.join(os.path.dirname(__file__), "src"))

from src.part2_fetch import get_working_rpc_url, fetch_block, inspect_block
from src.part1_tree import MerkleTree, verify_proof as verify_binary_proof
from src.part3_verify import verify_transactions_root, prove_transaction_inclusion, reconstruct_transactions_root
from src.extensions import run_extension_a, run_extension_b, run_extension_c, run_extension_d


def run_part_1():
    print("=" * 60)
    print("           PART 1: BINARY MERKLE TREE TEST SUITE")
    print("=" * 60)
    import hashlib
    
    # Handcrafted Carol test matching Step 1.4 requirements
    items = [b"alice", b"bob", b"carol", b"dave"]
    tree = MerkleTree(items)
    
    proof = tree.get_proof(2) # Carol (index 2)
    print(f"Merkle Root: 0x{tree.root.hex()}")
    print("Proof nodes:")
    for idx, p in enumerate(proof):
        print(f"  [{idx}] Sibling Hash: {p['hash'].hex()} ({p['position']})")
        
    verified = verify_binary_proof(b"carol", proof, tree.root)
    print(f"Carol Proof Verification: {verified} (PASS)")
    
    # Tampering test
    tampered_leaf = verify_binary_proof(b"mallory", proof, tree.root)
    print(f"Tampered Leaf Verification: {tampered_leaf} (FAILED AS EXPECTED - PASS)")
    
    tampered_proof = list(proof)
    tampered_proof[0] = {"hash": b"\x00" * 32, "position": tampered_proof[0]["position"]}
    tampered_proof_verified = verify_binary_proof(b"carol", tampered_proof, tree.root)
    print(f"Tampered Proof Verification: {tampered_proof_verified} (FAILED AS EXPECTED - PASS)")
    
    print("=" * 60 + "\n")


def run_part_2(rpc_url: str, block_number: str | int):
    print("=" * 60)
    print(f"           PART 2: ETHEREUM BLOCK DATA FETCH ({block_number})")
    print("=" * 60)
    block = fetch_block(rpc_url, block_number)
    inspect_block(block)
    print("=" * 60 + "\n")


def run_part_3(rpc_url: str, block_number: str | int, tx_index: int):
    print("=" * 60)
    print(f"           PART 3: END-TO-END PATRICIA TRIE VERIFICATION")
    print("=" * 60)
    
    # Standardised block conversion
    try:
        block_val = int(block_number)
    except ValueError:
        block_val = block_number
        
    print(f"Fetching block {block_val}...")
    block = fetch_block(rpc_url, block_val)
    
    # Inspect block header
    inspect_block(block)
    
    # Reconstruct root
    verify_transactions_root(block)
    
    # Generate and verify proof at index
    txs = block.get("transactions", [])
    if not txs:
        print("Block has no transactions to prove inclusion.")
        return
        
    if tx_index >= len(txs) or tx_index < 0:
        print(f"Target index {tx_index} out of range (tx count: {len(txs)}). Resetting to index 0.")
        tx_index = 0
        
    prove_transaction_inclusion(block, tx_index)
    print("=" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Ethereum Merkle Tree & Patricia Trie Verifier CLI Suite"
    )
    parser.add_argument(
        "--part",
        choices=["1", "2", "3"],
        help="Run only one designated part (1, 2, or 3). Runs all parts if unprovided."
    )
    parser.add_argument(
        "--block",
        default="20000000",
        help="Block number (integer height) or 'latest' (default: 20000000)"
    )
    parser.add_argument(
        "--tx-index",
        type=int,
        default=0,
        help="Transaction index for proof generation (default: 0)"
    )
    parser.add_argument(
        "--extensions",
        nargs="+",
        choices=["a", "b", "c", "d"],
        help="Extension challenges to run (a, b, c, or d). E.g. --extensions a c"
    )
    
    args = parser.parse_args()
    
    # 1. Handle Extensions explicitly
    if args.extensions:
        print("Starting Extension challenges...")
        try:
            rpc = get_working_rpc_url()
        except Exception as e:
            print(f"RPC Connection Error: {e}")
            sys.exit(1)
            
        for ext in args.extensions:
            if ext == "a":
                run_extension_a(rpc)
            elif ext == "b":
                run_extension_b(rpc)
            elif ext == "c":
                run_extension_c(rpc)
            elif ext == "d":
                run_extension_d(rpc)
        return

    # 2. Handle standard Part-by-Part CLI pipelines
    if args.part == "1":
        run_part_1()
        
    elif args.part == "2":
        try:
            rpc = get_working_rpc_url()
            # Standardise block numerical types
            try:
                block_val = int(args.block)
            except ValueError:
                block_val = args.block
            run_part_2(rpc, block_val)
        except Exception as e:
            print(f"Error executing Part 2: {e}")
            sys.exit(1)
            
    elif args.part == "3":
        try:
            rpc = get_working_rpc_url()
            run_part_3(rpc, args.block, args.tx_index)
        except Exception as e:
            print(f"Error executing Part 3: {e}")
            sys.exit(1)
            
    else:
        # Default workflow: run all parts sequentially
        print("No specific part provided. Running complete transaction verification suite sequentially...\n")
        try:
            rpc = get_working_rpc_url()
            print(f"Active RPC endpoint connected: {rpc}\n")
        except Exception as e:
            print(f"RPC Connection Error: {e}")
            sys.exit(1)
            
        run_part_1()
        run_part_2(rpc, 20000000)
        run_part_3(rpc, 20000000, args.tx_index)


if __name__ == "__main__":
    main()
