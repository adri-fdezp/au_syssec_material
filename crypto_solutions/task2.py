import base64
import binascii

grade_cookie = "eyJtc2ciOiAiNTk2Zjc1MjA2NzY1NzQyMDYxMjA2ZjZlNmM3OTIwNjc2NTc0MjA2MTIwMzcyMDY5NmUyMDUzNzk3Mzc0NjU2ZDIwNTM2NTYzNzU3MjY5NzQ3OTJlMjA0OTIwNjE2ZDIwNzY2NTcyNzkyMDY0Njk3MzYxNzA3MDZmNjk2ZTc0NjU2NDIwNjI3OTIwNzk2Zjc1MmUiLCAic2lnbmF0dXJlIjogImJkNGM2..."

# Fix Base64 padding
def fix_padding(b64_string):
    return b64_string + '=' * (-len(b64_string) % 4)

decoded = base64.urlsafe_b64decode(fix_padding(grade_cookie))

# Print raw decoded content
print(decoded)

# Decode the message
hex_message = "596f75206765742061206f6e6c79206765742061203720696e2053797374656d2053656375726974792e204920616d2076657279206469736170706f696e74656420627920796f752e"
decoded_msg = binascii.unhexlify(hex_message).decode()
print(decoded_msg)

# Now let's change the grade from "7" to "12"
new_msg = decoded_msg.replace("7", "12")

# Convert new message to bytes and hex
new_msg_bytes = new_msg.encode()
new_msg_hex = binascii.hexlify(new_msg_bytes).decode()

# Print new forged message
print(f"New Forged Message: {new_msg}")
