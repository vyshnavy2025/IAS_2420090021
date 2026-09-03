import socket
import json
import struct
import math

HOST = "127.0.0.1"
PORT = 5001

# 2 x 2 Hill Cipher Key
# | 3 3 |
# | 2 5 |
KEY = [[3, 3],
       [2, 5]]


# ============================================================
# HILL CIPHER ENCRYPTION
# ============================================================

def encrypt(text):

    text = text.upper().replace(" ", "")

    # Keep only A-Z
    text = "".join(c for c in text if c.isalpha())

    # Make even length
    if len(text) % 2 != 0:
        text += "X"

    result = ""

    for i in range(0, len(text), 2):

        x1 = ord(text[i]) - ord("A")
        x2 = ord(text[i + 1]) - ord("A")

        y1 = (KEY[0][0] * x1 + KEY[0][1] * x2) % 26
        y2 = (KEY[1][0] * x1 + KEY[1][1] * x2) % 26

        result += chr(y1 + ord("A"))
        result += chr(y2 + ord("A"))

    return result


# ============================================================
# MODULAR INVERSE
# ============================================================

def mod_inverse(a, m):

    for i in range(1, m):

        if (a * i) % m == 1:
            return i

    return None


# ============================================================
# HILL CIPHER DECRYPTION
# ============================================================

def decrypt(ciphertext):

    a = KEY[0][0]
    b = KEY[0][1]
    c = KEY[1][0]
    d = KEY[1][1]

    determinant = (a * d - b * c) % 26

    inverse_det = mod_inverse(
        determinant,
        26
    )

    if inverse_det is None:
        return "Invalid key"

    inverse_key = [
        [(d * inverse_det) % 26,
         (-b * inverse_det) % 26],

        [(-c * inverse_det) % 26,
         (a * inverse_det) % 26]
    ]

    result = ""

    for i in range(0, len(ciphertext), 2):

        x1 = ord(ciphertext[i]) - ord("A")
        x2 = ord(ciphertext[i + 1]) - ord("A")

        y1 = (
            inverse_key[0][0] * x1 +
            inverse_key[0][1] * x2
        ) % 26

        y2 = (
            inverse_key[1][0] * x1 +
            inverse_key[1][1] * x2
        ) % 26

        result += chr(y1 + ord("A"))
        result += chr(y2 + ord("A"))

    return result


# ============================================================
# SEND DATA
# ============================================================

def send_data(sock, data):

    message = json.dumps(data).encode()

    sock.sendall(
        struct.pack(
            "!I",
            len(message)
        )
    )

    sock.sendall(message)


# ============================================================
# RECEIVE DATA
# ============================================================

def receive_data(sock):

    size_data = receive_exact(sock, 4)

    if not size_data:
        return None

    size = struct.unpack(
        "!I",
        size_data
    )[0]

    data = receive_exact(
        sock,
        size
    )

    if not data:
        return None

    return json.loads(
        data.decode()
    )


# ============================================================
# RECEIVE EXACT
# ============================================================

def receive_exact(sock, size):

    data = b""

    while len(data) < size:

        packet = sock.recv(
            size - len(data)
        )

        if not packet:
            return None

        data += packet

    return data


# ============================================================
# CLIENT
# ============================================================

print("=" * 60)
print("             HILL CIPHER CLIENT")
print("=" * 60)

client = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

try:

    client.connect(
        (HOST, PORT)
    )

    print("\n✓ Connected to server.")

except Exception as e:

    print("\nConnection error:", e)
    exit()


# ============================================================
# MENU
# ============================================================

while True:

    print("\n")
    print("=" * 50)
    print("CLIENT MENU")
    print("=" * 50)

    print("1. Encrypt and Send Message")
    print("2. Receive and Decrypt Message")
    print("3. Exit")

    choice = input(
        "\nEnter choice: "
    )

    # --------------------------------------------------------
    # SEND
    # --------------------------------------------------------

    if choice == "1":

        plaintext = input(
            "\nEnter plaintext: "
        )

        ciphertext = encrypt(
            plaintext
        )

        print("\nPlaintext:")
        print(plaintext)

        print("\nCiphertext:")
        print(ciphertext)

        send_data(
            client,
            {
                "operation": "SEND",
                "plaintext": plaintext,
                "ciphertext": ciphertext
            }
        )

        print(
            "\n✓ Message sent to server."
        )

    # --------------------------------------------------------
    # RECEIVE
    # --------------------------------------------------------

    elif choice == "2":

        send_data(
            client,
            {
                "operation": "REQUEST"
            }
        )

        data = receive_data(
            client
        )

        if data is None:

            print(
                "\nServer disconnected."
            )

            break

        if data["operation"] == "NO_MESSAGE":

            print(
                "\nNo message available."
            )

        else:

            ciphertext = data["ciphertext"]

            plaintext = decrypt(
                ciphertext
            )

            print("\nCiphertext:")
            print(ciphertext)

            print("\nPlaintext:")
            print(plaintext)

    # --------------------------------------------------------
    # EXIT
    # --------------------------------------------------------

    elif choice == "3":

        send_data(
            client,
            {
                "operation": "EXIT"
            }
        )

        break

    else:

        print(
            "\nInvalid choice!"
        )


client.close()

print("\nClient closed.")