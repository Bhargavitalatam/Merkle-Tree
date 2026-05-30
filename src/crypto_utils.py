import hashlib

try:
    from Crypto.Hash import keccak
    _HAS_PYCRYPTODOME = True
except ImportError:
    _HAS_PYCRYPTODOME = False


def keccak256(data: bytes) -> bytes:
    """
    Compute Keccak-256 hash of the input bytes.
    Uses pycryptodome if available, otherwise raises ImportError.
    """
    if _HAS_PYCRYPTODOME:
        k = keccak.new(digest_bits=256)
        k.update(data)
        return k.digest()
    else:
        raise ImportError(
            "pycryptodome is required for Keccak-256 hash computation. "
            "Please run 'pip install pycryptodome' to install it."
        )


def int_to_bytes(n: int) -> bytes:
    """Convert an integer to big-endian bytes of minimum length."""
    if n < 0:
        raise ValueError("RLP encoding only supports non-negative integers")
    if n == 0:
        return b""
    # Find minimum byte length required
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, byteorder="big")


def rlp_encode(input_data) -> bytes:
    """
    Encode python data types into Recursive Length Prefix (RLP) bytes.
    Supports: bytes, str, int, and list/tuple of these.
    """
    if isinstance(input_data, str):
        # Strings are encoded as UTF-8 bytes
        return rlp_encode(input_data.encode("utf-8"))
    
    elif isinstance(input_data, bool):
        # Booleans are encoded as integers (True = 1, False = 0)
        return rlp_encode(1 if input_data else 0)
        
    elif isinstance(input_data, int):
        # Integers are converted to big-endian bytes with no leading zeros
        return rlp_encode(int_to_bytes(input_data))
        
    elif isinstance(input_data, bytes):
        if len(input_data) == 1 and input_data[0] < 0x80:
            # Single byte in [0x00, 0x7f] is encoded as itself
            return input_data
        elif len(input_data) <= 55:
            # Short string: prefix 0x80 + length
            return bytes([0x80 + len(input_data)]) + input_data
        else:
            # Long string: prefix 0xb7 + length of length, then length, then string
            len_bytes = int_to_bytes(len(input_data))
            return bytes([0xb7 + len(len_bytes)]) + len_bytes + input_data
            
    elif isinstance(input_data, (list, tuple)):
        # Encode all items recursively
        payload = b"".join(rlp_encode(item) for item in input_data)
        if len(payload) <= 55:
            # Short list: prefix 0xc0 + length of payload
            return bytes([0xc0 + len(payload)]) + payload
        else:
            # Long list: prefix 0xf7 + length of length of payload, then length, then payload
            len_bytes = int_to_bytes(len(payload))
            return bytes([0xf7 + len(len_bytes)]) + len_bytes + payload
            
    else:
        raise TypeError(f"Type {type(input_data)} is not supported by RLP encoder")
