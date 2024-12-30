import random
from Crypto.Hash import SHA3_256

TxLen = 9  # Each transaction has 9 lines

def compute_merkle_root(block_candidate, TxCnt):
    # Build a list of hashes for each transaction
    hash_list = []
    for i in range(TxCnt):
        tx_str = "".join(block_candidate[i*TxLen:(i+1)*TxLen])
        h = SHA3_256.new(tx_str.encode('utf-8')).digest()
        hash_list.append(h)

    # Build the Merkle tree
    j = 0
    t = TxCnt
    while t > 1:
        for i in range(j, j + t, 2):
            combined = hash_list[i] + hash_list[i+1]
            new_hash = SHA3_256.new(combined).digest()
            hash_list.append(new_hash)
        j += t
        t >>= 1

    # The Merkle root is the last hash
    return hash_list[-1]

def compute_block_pow(H_r, PrevPoW, PoWLen):
    # Try random nonces until PoW meets requirement
    while True:
        nonce = random.getrandbits(256)
        digest = H_r + PrevPoW.encode('utf-8') + nonce.to_bytes((nonce.bit_length()+7)//8, 'big')
        PoW = SHA3_256.new(digest).hexdigest()
        if PoW[:PoWLen] == "0" * PoWLen:
            return nonce, PoW

def AddBlock2Chain(PoWLen, TxCnt, block_candidate, PrevBlock):
    # If this is the first block, set "Previous PoW" to 20 zeros
    if len(PrevBlock) == 0:
        PrevPoW_str = "00000000000000000000"
    else:
        # Compute PoW of the previous block (mimicking PhaseIII_Test's "CheckBlock" logic)
        from Crypto.Hash import SHA3_256
        def check_prev_block(TxCnt, Block):
            B = Block[:]
            # The PrevPoW line
            line0 = B.pop(0).strip()
            prev_pow_str = line0.split(": ")[1]
            # The nonce line
            line1 = B.pop(0).strip()
            nonce_val = int(line1.split(": ")[1])
            # Build merkle
            hash_list = []
            for i in range(TxCnt):
                tx_str = "".join(B[i*TxLen : (i+1)*TxLen])
                h = SHA3_256.new(tx_str.encode('utf-8')).digest()
                hash_list.append(h)
            j = 0
            t = TxCnt
            while t > 1:
                for i in range(j, j + t, 2):
                    combined = hash_list[i] + hash_list[i+1]
                    new_hash = SHA3_256.new(combined).digest()
                    hash_list.append(new_hash)
                j += t
                t >>= 1

            H_r_ = hash_list[-1]
            digest_ = H_r_ + prev_pow_str.encode('utf-8') + nonce_val.to_bytes((nonce_val.bit_length()+7)//8,'big')
            PoW_ = SHA3_256.new(digest_).hexdigest()
            return PoW_

        PrevPoW_str = check_prev_block(TxCnt, PrevBlock)

    # Compute Merkle root of the candidate
    H_r = compute_merkle_root(block_candidate, TxCnt)

    # Find nonce that yields the required PoW
    nonce, new_block_pow = compute_block_pow(H_r, PrevPoW_str, PoWLen)

    # Build the new block lines
    block_lines = []
    block_lines.append("Previous PoW: " + PrevPoW_str + "\n")
    block_lines.append("Nonce: " + str(nonce) + "\n")
    block_lines.extend(block_candidate)

    # Return the block as a single string and also return the PoW of this newly created block
    return "".join(block_lines), new_block_pow
