# 🔗 Ethereum Merkle Tree Verifier

A production-grade Python implementation of a binary Merkle Tree for verifying real Ethereum transactions — built from scratch using cryptographic hashing, live JSON-RPC block fetching, and end-to-end inclusion proof verification.

---

## 📖 Overview
Every Ethereum block header contains a single 32-byte value — the `transactionsRoot` — that is a cryptographic fingerprint of every transaction in the block. This project builds the data structure that generates and verifies that fingerprint: a binary Merkle Tree.

| Part | Module | Description |
| :--- | :--- | :--- |
| **Part 1** | `src/part1_tree.py` | Pure-Python `MerkleTree` class, proof generation, standalone verifier |
| **Part 2** | `src/part2_fetch.py` | Fetches real Ethereum blocks via JSON-RPC (Archive endpoints) |
| **Part 3** | `src/part3_verify.py` | Reconstructs transactions root, generates & verifies inclusion proofs |
| **Extensions** | `src/extensions.py` | RLP+Keccak-256, odd-leaf detection, light client simulation, historical blocks |

---

## 🏗 Architecture

### System Overview
- **Custom RLP & Keccak Engine**: Supports standard list, string, and integer serializers.
- **Hex Prefix Compact Pathing**: Leverages nibble conversion rules to compress Patricia Trie nodes.
- **Trie DB Caches**: Node references index serialised forms dynamically on-the-fly.

---

## 🗂 Project Structure
```text
ethereum-merkle-tree/
├── src/
│   ├── __init__.py
│   ├── part1_tree.py       # MerkleNode, MerkleTree, verify_proof()
│   ├── part2_fetch.py      # fetch_block(), inspect_block(), RPC helpers
│   ├── part3_verify.py     # hash_transaction(), prove_transaction_inclusion()
│   ├── extensions.py       # Extension A (RLP+Keccak), B, C, D
│   └── crypto_utils.py     # Compliant RLP and Keccak helper
├── tests/
│   ├── __init__.py
│   └── test_merkle.py      # Full Pytest suite (100% offline)
├── main.py                 # CLI entry point — orchestrates all parts
├── requirements.txt        # Pinned Python dependencies
├── Dockerfile              # python:3.11-slim container
├── docker-compose.yml      # Services: app + tests
├── .env.example            # Environment variable template
├── .gitignore
└── README.md
```

---

## 🚀 Quick Start

### 1 — Clone & Configure
```bash
git clone https://github.com/ramalokeshreddyp/ethereum-merkle-tree.git
cd ethereum-merkle-tree

# Copy env template
cp .env.example .env
```

### 2 — Local Setup (without Docker)
```bash
# Create virtual environment
python -m venv .venv

# Activate — Windows
.venv\Scripts\activate
# Activate — macOS/Linux
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run Part 1 only (no network required)
python main.py --part 1

# Run all parts (requires ETHEREUM_RPC_URL in .env, falls back to public pool if blank)
python main.py

# Run a specific block and transaction index
python main.py --part 3 --block 20000000 --tx-index 0

# Run extension challenges
python main.py --extensions a b c d
```

### 3 — Docker (recommended)
```bash
# Build image and run all parts
docker-compose up --build

# Run only the test suite
docker-compose run tests

# Run specific parts interactively
docker-compose run app python main.py --part 1
docker-compose run app python main.py --extensions a c
```

---

## 🧪 Testing
```bash
# Run the full test suite (offline, no RPC needed)
pytest tests/ -v

# With coverage report
pytest tests/ -v --cov=src --cov-report=term-missing
```

### Test Coverage Summary
| Test Class | What is covered |
| :--- | :--- |
| `test_sha256_pair` | Concatenation and single SHA-256 validation |
| `test_merkle_tree_construction_even` | Core bottom-up build over even counts of leaves |
| `test_merkle_tree_construction_odd` | Odd leaf duplication checks at multiple levels |
| `test_merkle_tree_empty_leaves` | Empty leaf list raises `ValueError` |
| `test_proof_generation_and_verification` | Standard `get_proof` and standalone `verify_proof` |
| `test_rlp_encoding` | RLP string, int, boolean, list serializers |
| `test_keccak256_hashing` | Cryptographic outputs match expected standards |
| `test_compact_encoding` | Compact encoding/decoding nibble manipulation |
| `test_mpt_trie_construction_and_verification_offline` | Full mock Patricia Trie build and verify offline |

---

## 🧩 Extension Challenges

| Extension | Description | CLI Flag |
| :--- | :--- | :--- |
| **A — RLP + Keccak-256** | Accurate Ethereum leaf hashing using rlp + pycryptodome | `--extensions a` |
| **B — Odd-Leaf Detection** | Finds a block with odd tx count; proves odd-leaf duplication logic | `--extensions b` |
| **C — Light Client Sim** | Verifies inclusion using only the block header + proof (no full block) | `--extensions c` |
| **D — Historical Block** | Fetches a block from ~6 months ago; verifies a transaction in history | `--extensions d` |

```bash
# Run all four extensions
python main.py --extensions a b c d
```

---

## 📐 CLI Reference
```text
usage: main.py [-h] [--part {1,2,3}] [--block BLOCK]
               [--tx-index TX_INDEX] [--extensions EXT [EXT ...]]

options:
  -h, --help              show this help message and exit
  --part {1,2,3}          Run only one part (default: all)
  --block BLOCK           Block number or 'latest' (default: 20000000)
  --tx-index TX_INDEX     Transaction index for proof (default: 0)
  --extensions a b c d    Extension challenges to run
```

---

## 🧠 Key Takeaway
The `transactionsRoot` in every Ethereum block header is a cryptographic commitment — a single 32-byte value that locks in every transaction in the block. Change any transaction and the root changes. Forge a root and the block's proof-of-stake signature becomes invalid.

Your Merkle tree implementation is the same data structure — conceptually — that secures billions of dollars of on-chain value. The difference between your implementation and Ethereum's is encoding details and trie structure, not the underlying idea.

---

## 📄 License
MIT © 2026
