# PoW.py
import hashlib
import secrets

def merkle_root_from_transactions(tx_list):
    """
    Compute the Merkle root (SHA3_256) of a list of raw transaction strings.
    The Merkle tree is built by:
      - hashing each transaction (SHA3_256)
      - pairing them & hashing pair of hashes, etc.
    For simplicity, we'll do a classic Merkle approach:
    1. If there's an odd number of items at any level, repeat the last one.
    2. Combine pairs: new_hash = SHA3_256(left_hash + right_hash).
    3. Continue until single root remains.
    """
    # Convert each transaction -> sha3_256 -> bytes
    leaves = []
    for tx in tx_list:
        h = hashlib.sha3_256(tx.encode('utf-8')).digest()
        leaves.append(h)

    # Build the Merkle Tree
    while len(leaves) > 1:
        if len(leaves) % 2 == 1:  # odd, duplicate last
            leaves.append(leaves[-1])
        new_level = []
        for i in range(0, len(leaves), 2):
            combined = leaves[i] + leaves[i+1]
            new_level.append(hashlib.sha3_256(combined).digest())
        leaves = new_level

    # single root
    return leaves[0] if leaves else b'\x00'*32


def CheckPow(p, q, g, PoWLen, TxCnt, filename):
    """
    1) Read the file 'filename'.
    2) Expect first line: "Nonce: <some integer>"
    3) Then read next TxCnt * 7 lines for the transactions (each transaction is 7 lines).
    4) Compute Merkle root H_r of all TxCnt transactions.
    5) Compute H = SHA3_256( H_r || nonce ).
    6) If H's hex digest starts with PoWLen '0' hex digits, return H in hex.
       Otherwise, return "" (empty string).
    """
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
        if len(lines) < 1 + 7*TxCnt:
            return ""  # file format error or not enough lines

        # parse Nonce from first line
        first_line = lines[0].strip()
        if not first_line.startswith("Nonce: "):
            return ""

        nonce_str = first_line.split("Nonce: ")[1].strip()
        try:
            nonce_val = int(nonce_str)
        except:
            return ""

        # collect the transaction text lines
        # The next 7*TxCnt lines are the transactions
        tx_lines = lines[1:1 + 7*TxCnt]
        # combine them into TxCnt full transaction strings
        # We'll do it by grouping every 7 lines as one transaction
        all_txs = []
        for i in range(TxCnt):
            start_idx = i*7
            tx_str = "".join(tx_lines[start_idx:start_idx+7])
            all_txs.append(tx_str)

        # compute Merkle root
        H_r = merkle_root_from_transactions(all_txs)

        # compute the PoW hash
        nonce_bytes = nonce_val.to_bytes((nonce_val.bit_length()+7)//8, 'big', signed=False)
        preimage = H_r + nonce_bytes
        digest = hashlib.sha3_256(preimage).hexdigest()

        # check leading PoWLen '0' hex digits
        if digest.startswith("0"*PoWLen):
            return digest
        else:
            return ""

    except:
        return ""


def PoW(PoWLen, q, p, g, TxCnt, filename):
    """
    1) Read the TxCnt transactions from 'filename' (these do not have a Nonce line).
    2) Build Merkle root H_r from these transactions.
    3) Try random nonces until we get a hash that starts with PoWLen '0' hex digits.
    4) Return the entire block text, which is:
        Nonce: <theNonce>
        <all TxCnt transactions> (same lines)
    """
    with open(filename, 'r') as f:
        tx_lines = f.readlines()
    if len(tx_lines) < 7*TxCnt:
        # insufficient lines for TxCnt transactions
        return ""

    # Group lines into TxCnt transaction strings
    all_txs = []
    for i in range(TxCnt):
        start_idx = i*7
        tx_str = "".join(tx_lines[start_idx:start_idx+7])
        all_txs.append(tx_str)

    # compute Merkle root
    H_r = merkle_root_from_transactions(all_txs)

    # search for nonce
    while True:
        nonce_val = secrets.randbits(256)  # pick a large random nonce
        nonce_bytes = nonce_val.to_bytes((nonce_val.bit_length()+7)//8, 'big', signed=False)
        preimage = H_r + nonce_bytes
        digest_hex = hashlib.sha3_256(preimage).hexdigest()
        if digest_hex.startswith("0"*PoWLen):
            # success
            # Build the block string
            block_str = f"Nonce: {nonce_val}\n" + "".join(tx_lines)
            return block_str
    # (No explicit return needed; we loop until found.)
