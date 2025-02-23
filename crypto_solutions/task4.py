import base64
import json
import binascii
import requests

url = "http://127.0.0.1:5000/"

# Get the cookie
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

# Decode Base64
decoded_bytes = base64.b64decode(grade_cookie)

# Interpret as JSON
try:
    decoded_json = json.loads(decoded_bytes)
except json.JSONDecodeError:
    decoded_json = decoded_bytes.decode(errors="ignore")

# Decode the message
msg_hex = decoded_json.get('msg')
msg_text = bytes.fromhex(msg_hex).decode()
print("Original msg:", msg_text)

# Create new msg 
new_msg = "You get a get a 12 in System Security. I am very proud of you."

# Convert new message to bytes and hex
new_msg_bytes = new_msg.encode()
new_msg_hex = binascii.hexlify(new_msg_bytes).decode()

# Print new forged message
print(f"New Forged Message: {new_msg}")

# Replace the message with structure JSON
decoded_json["msg"] = new_msg_hex

# Convert the JSON structure to base64
modified_cookie_json = json.dumps(decoded_json)
modified_cookie_base64 = base64.b64encode(modified_cookie_json.encode()).decode()

# Print the new cookie
print("New cookie:", modified_cookie_base64)

