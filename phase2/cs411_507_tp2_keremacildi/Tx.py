# Tx.py
import secrets
import DS  # DS.py from the same folder

def gen_random_tx(q, p, g):
    """
    Generate a single random Bitcoin-like transaction string
    with a valid signature from the payer.
    """
    # 1) KeyGen for payer & payee
    (alpha_payer, beta_payer) = DS.KeyGen(q, p, g)
    (alpha_payee, beta_payee) = DS.KeyGen(q, p, g)

    # 2) Random 128-bit serial number
    serial_num = secrets.randbits(128)

    # 3) Amount in [1..1_000_000]
    amount = secrets.randbelow(1_000_000) + 1

    # 4) Construct the message to sign (payer must sign):
    #    "Serial number: X\n"
    #    "Amount: Y\n"
    #    "Payee public key (beta): X\n"
    #    "Payer public key (beta): X\n"
    msg_to_sign = (
        f"Serial number: {serial_num}\n"
        f"Amount: {amount}\n"
        f"Payee public key (beta): {beta_payee}\n"
        f"Payer public key (beta): {beta_payer}\n"
    )
    msg_bytes = msg_to_sign.encode('utf-8')

    # 5) Sign with payer's private key alpha_payer
    (s, h) = DS.SignGen(msg_bytes, q, p, g, alpha_payer)

    # 6) Build the final transaction text
    tx_text = (
        "**** Bitcoin transaction ****\n"
        f"Signature (s): {s}\n"
        f"Signature (h): {h}\n"
        f"Serial number: {serial_num}\n"
        f"Amount: {amount}\n"
        f"Payee public key (beta): {beta_payee}\n"
        f"Payer public key (beta): {beta_payer}\n"
    )
    return tx_text


def gen_random_txblock(q, p, g, TxCnt, filename):
    """
    Generate TxCnt random transactions and write them to 'filename'.
    TxCnt is typically 64 for Phase II.
    Each transaction has 7 lines (plus the "**** Bitcoin transaction ****" line).
    """
    with open(filename, 'w') as f:
        for _ in range(TxCnt):
            tx_str = gen_random_tx(q, p, g)
            f.write(tx_str)
