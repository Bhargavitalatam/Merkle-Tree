import requests
import json
import time
import os

# Try to load environment variables from a .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Reordered to put highly reliable endpoints that support full block transaction lookups first
PUBLIC_RPC_URLS = [
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://rpc.ankr.com/eth",
    "https://cloudflare-eth.com"
]

def get_working_rpc_url() -> str:
    """
    Helper to find the first working RPC url from our list.
    Checks environment variables first, then validates that the endpoint 
    supports full transaction object lookups.
    """
    # 1. Check if custom RPC URL is configured in the environment
    env_rpc = os.environ.get("ETHEREUM_RPC_URL")
    urls_to_test = [env_rpc] + PUBLIC_RPC_URLS if env_rpc else PUBLIC_RPC_URLS
    
    for url in urls_to_test:
        if not url:
            continue
        try:
            # Check if we can fetch a recent block with full transactions
            payload = {
                "jsonrpc": "2.0",
                "method": "eth_getBlockByNumber",
                "params": ["latest", True],
                "id": 1
            }
            response = requests.post(url, json=payload, timeout=5)
            if response.status_code == 200:
                result_data = response.json()
                if "result" in result_data and result_data["result"] is not None:
                    # Successfully fetched full block object
                    return url
        except Exception:
            continue
    raise ConnectionError("Failed to connect to any configured or public Ethereum RPC endpoints that support full transaction objects.")

def to_hex_block_number(block_number: int | str) -> str:
    """Helper to convert int block numbers to standard RPC hex string format."""
    if isinstance(block_number, int):
        return hex(block_number)
    return block_number

def fetch_block(rpc_url: str, block_number: int | str = "latest") -> dict:
    """
    Fetch a full block (with transactions) from an Ethereum JSON-RPC endpoint.
    Returns the raw block dict including transactionsRoot and the transactions list.
    block_number can be an integer or "latest".
    """
    hex_num = to_hex_block_number(block_number)
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getBlockByNumber",
        "params": [hex_num, True], # True to fetch full transaction objects
        "id": 1
    }
    
    response = requests.post(rpc_url, json=payload, timeout=15)
    if response.status_code != 200:
        raise RuntimeError(f"RPC call failed with status code {response.status_code}")
        
    result_data = response.json()
    if "error" in result_data:
        raise RuntimeError(f"RPC Error: {result_data['error']['message']}")
        
    block = result_data.get("result")
    if not block:
        raise ValueError(f"Block not found for number: {block_number}")
        
    return block

def fetch_transaction(rpc_url: str, tx_hash: str) -> dict:
    """Fetch details of a single transaction by its hash."""
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getTransactionByHash",
        "params": [tx_hash],
        "id": 1
    }
    
    response = requests.post(rpc_url, json=payload, timeout=10)
    if response.status_code != 200:
        raise RuntimeError(f"RPC call failed with status code {response.status_code}")
        
    result_data = response.json()
    if "error" in result_data:
        raise RuntimeError(f"RPC Error: {result_data['error']['message']}")
        
    tx = result_data.get("result")
    if not tx:
        raise ValueError(f"Transaction not found for hash: {tx_hash}")
        
    return tx

def inspect_block(block: dict) -> None:
    """
    Print the block number, timestamp, transaction count,
    and most importantly the transactionsRoot.
    This root is what we will reconstruct and verify against.
    """
    block_num_hex = block.get("number", "0x0")
    block_num = int(block_num_hex, 16) if isinstance(block_num_hex, str) else block_num_hex
    
    timestamp_hex = block.get("timestamp", "0x0")
    timestamp = int(timestamp_hex, 16) if isinstance(timestamp_hex, str) else timestamp_hex
    readable_time = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(timestamp))
    
    txs = block.get("transactions", [])
    tx_count = len(txs)
    
    tx_root = block.get("transactionsRoot", "N/A")
    
    print("=" * 60)
    print("                 ETHEREUM BLOCK HEADER INSPECTOR")
    print("=" * 60)
    print(f"Block Number     : {block_num} ({block_num_hex})")
    print(f"Timestamp        : {readable_time} ({timestamp_hex})")
    print(f"Transaction Count: {tx_count}")
    print(f"Transactions Root: {tx_root}")
    print("=" * 60)

def fetch_transaction_proof(rpc_url: str, tx_hash: str) -> dict:
    """
    Fetch a transaction inclusion proof. Since standard JSON-RPC lacks
    eth_getTransactionProof, we query the transaction to find its block and index,
    fetch all transactions in that block, and return it for verification.
    """
    print(f"Fetching transaction details for {tx_hash}...")
    tx = fetch_transaction(rpc_url, tx_hash)
    
    block_num = tx.get("blockNumber")
    tx_index_hex = tx.get("transactionIndex")
    tx_index = int(tx_index_hex, 16)
    
    print(f"Transaction found in block {int(block_num, 16)} at index {tx_index}. Fetching full block...")
    block = fetch_block(rpc_url, block_num)
    
    return {
        "block": block,
        "tx_index": tx_index,
        "tx_hash": tx_hash,
        "transaction": tx
    }
