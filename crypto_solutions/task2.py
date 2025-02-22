import base64
import binascii
import json
import requests

url = "http://127.0.0.1:5000/"

# Get the auth token cookie
response = requests.get(url)
if response.status_code == 200:
    grade_cookie = response.cookies.get("grade")
    if not grade_cookie:
        print("Grade not found in the cookies.")
        exit()
    print("Grade retrieved")
else:
    print("Failed to retrieve the URL. Status code:", response.status_code)
    exit()

# Fix Base64 padding
def fix_padding(b64_string):
    return b64_string + "=" * (-len(b64_string) % 4)

# Decode the cookie
try:
    decoded = base64.urlsafe_b64decode(fix_padding(grade_cookie)).decode()
    data = json.loads(decoded)  # Load the JSON data
except (binascii.Error, json.JSONDecodeError) as e:
    print(f"Decoding error: {e}")
    exit()

# Decode the Base64 message with padding fix
try:
    msg_base64 = fix_padding(data["msg"])  # Ensure correct padding
    decoded_msg = binascii.unhexlify(msg_base64).decode()
except binascii.Error as e:
    print(f"Base64 decoding error: {e}")
    exit()

# Modify the grade from "7" to "12"
new_msg = decoded_msg.replace("02", "12")

# Convert new message to hex
new_msg_hex = binascii.hexlify(new_msg.encode()).decode()

# Print new forged message
print(f"New Forged Message: {new_msg}")