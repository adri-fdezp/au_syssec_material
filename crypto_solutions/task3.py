from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto import Random

# Key Generation
def generate_key_pair():
    key = RSA.generate(3072)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Signing
def sign_message(private_key, message):
    key = RSA.import_key(private_key)
    h = SHA256.new(message)
    signature = pss.new(key).sign(h)
    return signature

# Verification
def verify_signature(public_key, message, signature):
    key = RSA.import_key(public_key)
    h = SHA256.new(message)
    verifier = pss.new(key)
    try:
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# Example Usage
if __name__ == "__main__":
    private_key, public_key = generate_key_pair()
    message = b"Hello, RSA-PSS!"
    
    signature = sign_message(private_key, message)
    print(f"Signature: {signature.hex()}")
    
    is_valid = verify_signature(public_key, message, signature)
    print(f"Signature valid: {is_valid}")