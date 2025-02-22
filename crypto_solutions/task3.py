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


"""
Certainly! Below is the entire explanation and implementation in text format for easy copying:

---

### Task 3: Implementing RSA-PSS

Implementing RSA-PSS (Probabilistic Signature Scheme) is a complex task that involves several steps, including key generation, message signing, and signature verification. Below is a high-level overview of how you can implement RSA-PSS using Python, leveraging libraries like `pycryptodome` for cryptographic primitives and `os` for secure random number generation.

---

### Key Generation

1. **Generate RSA Key Pair**: Use a secure random number generator to generate two large prime numbers \( p \) and \( q \). Compute \( n = p \times q \) and \( \phi(n) = (p-1)(q-1) \). Choose a public exponent \( e \) (commonly 65537) and compute the private exponent \( d \) such that \( d \times e \equiv 1 \mod \phi(n) \).

2. **Ensure Security**: Ensure that the primes \( p \) and \( q \) are of sufficient size (1536 bits each for a 3072-bit modulus) and that they are generated using a cryptographically secure random number generator.

---

### Signing

1. **Message Encoding**: Use the PSS encoding scheme to encode the message. This involves hashing the message, generating a random salt, and applying a mask generation function (MGF).

2. **Signature Generation**: Compute the signature \( s \) as \( s = m^d \mod n \), where \( m \) is the encoded message.

---

### Verification

1. **Signature Decoding**: Decode the signature \( s \) to retrieve the encoded message \( m \).

2. **Message Verification**: Verify that the decoded message matches the original message by re-encoding it and comparing the results.

---

### Python Implementation

Below is a Python implementation using the `pycryptodome` library:

```python
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
```

---

### Explanation

1. **Key Generation**: The `generate_key_pair` function generates a 3072-bit RSA key pair using `Crypto.PublicKey.RSA.generate`.

2. **Signing**: The `sign_message` function signs a message using the private key. It first hashes the message using SHA-256, then uses the PSS scheme to create the signature.

3. **Verification**: The `verify_signature` function verifies the signature using the public key. It hashes the message and uses the PSS scheme to verify the signature.

---

### Security Considerations

- **Random Number Generation**: The `Crypto.Random` module is used for secure random number generation, which is crucial for generating secure primes and salts.
- **Key Size**: A 3072-bit modulus is used to achieve a 128-bit security level.
- **Padding Scheme**: The PSS padding scheme is used to prevent signature forgery attacks.

---

### Disclosure

This implementation uses the `pycryptodome` library for cryptographic operations, which is a well-known and widely used library in the Python ecosystem. The use of this library is disclosed as per university guidelines.

---

### References

- [RFC8017](https://datatracker.ietf.org/doc/html/rfc8017#section-8.1)
- [IEEE P1363 Specification](https://web.archive.org/web/20170810025803/http://grouper.ieee.org/groups/1363/P1363a/contributions/pss-submission.pdf)
- [German Wikipedia on RSA-PSS](https://de.wikipedia.org/wiki/Probabilistic_Signature_Scheme)

---

This implementation should provide a solid foundation for understanding and implementing RSA-PSS in a secure manner.

--- 

You can copy the above text for your use. Let me know if you need further assistance!
"""