import secrets
import DS  # Make sure DS.py is in the same directory
           # and that DS is properly implemented

def gen_random_tx(q, p, g):
    # Generate keys for payer and payee
    (alpha_payer, beta_payer) = DS.KeyGen(q, p, g)
    (alpha_payee, beta_payee) = DS.KeyGen(q, p, g)

    # Serial number: 128-bit integer
    serial_num = secrets.randbits(128)

    # Amount in [1, 1000000]
    amount = secrets.randbelow(1000000) + 1

    # The message to sign: Serial number, Amount, Payee beta, Payer beta (as per instructions)
    # The transaction is in the format:
    # *** Bitcoin transaction ***
    # Signature (s):
    # Signature (h):
    # Serial number:
    # Amount:
    # Payee public key (beta):
    # Payer public key (beta):

    # According to instructions, the signed message fields are:
    # Serial number, Amount, Payee public key (beta), Payer public key (beta)
    # Each separated by newline and a trailing newline as given in "PhaseI_Test.py" check.
    msg_to_sign = f"Serial number: {serial_num}\nAmount: {amount}\nPayee public key (beta): {beta_payee}\nPayer public key (beta): {beta_payer}\n"
    msg_bytes = msg_to_sign.encode('utf-8')

    # Sign the message with payer's private key
    (s, h) = DS.SignGen(msg_bytes, q, p, g, alpha_payer)

    # Construct the final transaction string
    # Note: Carefully follow formatting given in instructions
    tx = ("*** Bitcoin transaction ***\n"
          f"Signature (s): {s}\n"
          f"Signature (h): {h}\n"
          f"Serial number: {serial_num}\n"
          f"Amount: {amount}\n"
          f"Payee public key (beta): {beta_payee}\n"
          f"Payer public key (beta): {beta_payer}\n")

    return tx
