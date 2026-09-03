import socket
import json
import struct

HOST = "0.0.0.0"
PORT = 5001

# Same 2 x 2 key
KEY = [[3, 3],
       [2, 5]]


# ============================================================
# HILL ENCRYPTION
# ============================================================

def encrypt(text):

    text = text.upper().replace(" ", "")

    text = "".join(
        c for c in text
        if c.isalpha()
    )

    if len(text) % 2 != 0:
        text += "X"

    result = ""

    for i in range(0, len(text), 2):

        x1 = ord(text[i]) - ord("A")
        x2 = ord(text[i + 1]) - ord("A")

        y1 = (
            KEY[0][0] * x1 +
            KEY[0][1] * x2
        ) % 26

        y2 = (
            KEY[1][0] * x1 +
            KEY[1][1] * x2
        ) % 26

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
# HILL DECRYPTION
# ============================================================

def decrypt(ciphertext):

    a = KEY[0][0]
    b = KEY[0][1]
    c = KEY[1][0]
    d = KEY[1][1]

    determinant = (
        a * d - b * c
    ) % 26

    inverse_det = mod_inverse(
        determinant,
        26
    )

    if inverse_det is None:
        return "Invalid key"

    inverse_key = [
        [
            (d * inverse_det) % 26,
            (-b * inverse_det) % 26
        ],

        [
            (-c * inverse_det) % 26,
            (a * inverse_det) % 26
        ]
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

    message = json.dumps(
        data
    ).encode()

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

    size_data = receive_exact(
        sock,
        4
    )

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
# SERVER
# ============================================================

print("=" * 60)
print("             HILL CIPHER SERVER")
print("=" * 60)

server = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

server.setsockopt(
    socket.SOL_SOCKET,
    socket.SO_REUSEADDR,
    1
)

server.bind(
    (HOST, PORT)
)

server.listen(1)

print(
    "\nWaiting for client..."
)

conn, address = server.accept()

print(
    "\n✓ Client connected:",
    address
)


last_ciphertext = None
last_plaintext = None


# ============================================================
# SERVER LOOP
# ============================================================

while True:

    print("\n")
    print("=" * 50)
    print("SERVER MENU")
    print("=" * 50)

    print("1. Receive Message from Client")
    print("2. Send Message to Client")
    print("3. Exit")

    choice = input(
        "\nEnter choice: "
    )

    # --------------------------------------------------------
    # RECEIVE
    # --------------------------------------------------------

    if choice == "1":

        print(
            "\nWaiting for client message..."
        )

        data = receive_data(
            conn
        )

        if data is None:
            break

        if data["operation"] == "SEND":

            last_plaintext = data["plaintext"]
            last_ciphertext = data["ciphertext"]

            print("\n")
            print("=" * 60)
            print("CLIENT → SERVER")
            print("=" * 60)

            print("\nPlaintext:")
            print(last_plaintext)

            print("\nCiphertext:")
            print(last_ciphertext)

            decrypted = decrypt(
                last_ciphertext
            )

            print("\nDecrypted Plaintext:")
            print(decrypted)

            print(
                "\n✓ Hill Cipher decryption successful."
            )

        elif data["operation"] == "EXIT":

            break

    # --------------------------------------------------------
    # SEND
    # --------------------------------------------------------

    elif choice == "2":

        plaintext = input(
            "\nEnter plaintext to send: "
        )

        ciphertext = encrypt(
            plaintext
        )

        print("\nPlaintext:")
        print(plaintext)

        print("\nCiphertext:")
        print(ciphertext)

        send_data(
            conn,
            {
                "operation": "SERVER_SEND",
                "ciphertext": ciphertext
            }
        )

        print(
            "\n✓ Message sent to client."
        )

    # --------------------------------------------------------
    # EXIT
    # --------------------------------------------------------

    elif choice == "3":

        try:

            send_data(
                conn,
                {
                    "operation": "EXIT"
                }
            )

        except:
            pass

        break

    else:

        print(
            "\nInvalid choice!"
        )


conn.close()
server.close()

print(
    "\nServer closed."
)