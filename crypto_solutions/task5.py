import requests
from Crypto.Util.number import bytes_to_long, long_to_bytes
import math

# Endpoint URLs
URL_endpoint = "http://127.0.0.1:5000/pk"
URL_auth = "http://127.0.0.1:5000/"

# Fetch the public key
response = requests.get(URL_endpoint)
if response.status_code == 200:
    public_key = response.json()
    print("Public key retrieved")
    N = int(public_key.get('N'))  # RSA modulus
    E = int(public_key.get('e'))  # RSA public exponent
else:
    print("Error: Unable to fetch public key")
    exit()

# Get the auth token cookie
response = requests.get(URL_auth)
if response.status_code == 200:
    auth_token = response.cookies.get('authtoken')
    print("Authtoken retrieved")
    if not auth_token:
        print("Auth token not found in the cookies.")
        exit()
else:
    print("Failed to retrieve the URL. Status code:", response.status_code)
    exit()

# Convert auth_token to an integer
auth_token_int = bytes_to_long(bytes.fromhex(auth_token))

# Function to check if the token is valid (Oracle)
def is_valid_token(token):
    cookies = {'authtoken': token}
    response = requests.get(URL_auth, cookies=cookies)
    return "Valid auth token" in response.text

# Perform the Bleichenbacher attack
def bleichenbacher_attack():
    k = (N.bit_length() + 7) // 8  # Byte length of N
    B = 2 ** (8 * (k - 2))  # Correct B calculation
    M = [(2 * B, 3 * B - 1)]
    
    # Step 1: Initial blinding
    s0 = 2  # Start with a small blinding factor
    c0 = (auth_token_int * pow(s0, E, N)) % N
    
    # Step 2: Searching for s1
    s = s0
    while True:
        new_token = (c0 * pow(s, E, N)) % N
        if is_valid_token(hex(new_token)[2:]):
            break
        s += 1  # Increment and test next s value
    
    print("Found valid s:", s)
    decrypted_int = (auth_token_int * pow(s, E, N)) % N
    decrypted_message = long_to_bytes(decrypted_int % N)
    return decrypted_message

# Start the attack
decrypted_message = bleichenbacher_attack()
if decrypted_message:
    print("Decrypted message:", decrypted_message)
else:
    print("Attack failed.")
