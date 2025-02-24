from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import secrets
import struct

# --- Mask Generation Function (MGF1) ---
def mgf1(seed: bytes, mask_len: int, hash_func=SHA256) -> bytes:
    """Generates a mask using MGF1 with SHA-256."""
    h_len = hash_func.digest_size
    mask = b''
    counter = 0
    while len(mask) < mask_len:
        c = struct.pack(">I", counter)  # 4-byte counter
        mask += hash_func.new(seed + c).digest()
        counter += 1
    return mask[:mask_len]

# --- OAEP Padding ---
def oaep_encode(message: bytes, key_size: int, hash_func=SHA256) -> bytes:
    """Encodes message using OAEP with SHA-256."""
    h_len = hash_func.digest_size
    k = key_size // 8  # Convert bits to bytes

    if len(message) > k - 2 * h_len - 2:
        raise ValueError("Message too long for this key size")

    l_hash = hash_func.new(b"").digest()  # Hash of an empty label
    ps = b'\x00' * (k - len(message) - 2 * h_len - 2)
    db = l_hash + ps + b'\x01' + message
    seed = secrets.token_bytes(h_len)

    db_mask = mgf1(seed, k - h_len - 1, hash_func)
    masked_db = bytes(x ^ y for x, y in zip(db, db_mask))

    seed_mask = mgf1(masked_db, h_len, hash_func)
    masked_seed = bytes(x ^ y for x, y in zip(seed, seed_mask))

    return b'\x00' + masked_seed + masked_db

# --- OAEP Unpadding ---
def oaep_decode(encoded: bytes, key_size: int, hash_func=SHA256) -> bytes:
    """Decodes OAEP-padded message."""
    h_len = hash_func.digest_size
    k = key_size // 8

    if len(encoded) != k:
        raise ValueError("Invalid ciphertext length")

    _, masked_seed, masked_db = encoded[0], encoded[1:h_len+1], encoded[h_len+1:]
    
    seed_mask = mgf1(masked_db, h_len, hash_func)
    seed = bytes(x ^ y for x, y in zip(masked_seed, seed_mask))

    db_mask = mgf1(seed, k - h_len - 1, hash_func)
    db = bytes(x ^ y for x, y in zip(masked_db, db_mask))

    l_hash = hash_func.new(b"").digest()
    if db[:h_len] != l_hash:
        raise ValueError("Decoding error: Hash mismatch")

    index = db.find(b'\x01', h_len)
    if index == -1:
        raise ValueError("Decoding error: Separator not found")

    return db[index+1:]

# --- RSA Key Generation ---
def generate_rsa_keypair(bits=3072):
    """Generates a 3072-bit RSA key pair."""
    key = RSA.generate(bits)
    return key

# --- RSA Encryption ---
def rsa_encrypt(message: bytes, public_key: RSA.RsaKey) -> bytes:
    """Encrypts a message using RSA-OAEP."""
    key_size = public_key.size_in_bits()
    padded_message = oaep_encode(message, key_size)
    m_int = int.from_bytes(padded_message, 'big')
    c_int = pow(m_int, public_key.e, public_key.n)
    return c_int.to_bytes(key_size // 8, 'big')

# --- RSA Decryption ---
def rsa_decrypt(ciphertext: bytes, private_key: RSA.RsaKey) -> bytes:
    """Decrypts an RSA-OAEP encrypted message."""
    key_size = private_key.size_in_bits()
    c_int = int.from_bytes(ciphertext, 'big')
    m_int = pow(c_int, private_key.d, private_key.n)
    decrypted_padded = m_int.to_bytes(key_size // 8, 'big')
    return oaep_decode(decrypted_padded, key_size)

# --- Test the Implementation ---
if __name__ == "__main__":
    # Generate key pair
    key_pair = generate_rsa_keypair()
    public_key = key_pair.publickey()

    # Message to encrypt
    message = b"Hello, RSA-OAEP!"

    # Encrypt
    ciphertext = rsa_encrypt(message, public_key)
    print("Ciphertext (hex):", ciphertext.hex())

    # Decrypt
    decrypted_message = rsa_decrypt(ciphertext, key_pair)
    print("Decrypted:", decrypted_message.decode())


"""
Implementation Steps
Key Generation: Generate a 3072-bit RSA key pair.
OAEP Encoding (Encryption Side):
Apply MGF1 (Mask Generation Function) using SHA-256.
Construct the OAEP padded message.
RSA Encryption: Use modular exponentiation to encrypt the padded message.
RSA Decryption: Use modular exponentiation to decrypt the ciphertext.
OAEP Decoding (Decryption Side):
Reverse the masking process.
Extract the original message.
Testing: Verify encryption and decryption work consistently.
Key Considerations
Use secure random number generation (e.g., secrets module in Python).
Implement MGF1 properly, as it’s crucial for OAEP security.
Ensure proper padding and unpadding to prevent decryption errors.
Code Structure
I’ll start with a Python implementation using pycryptodome for basic RSA operations while implementing OAEP manually.
"""