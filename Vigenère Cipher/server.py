import socket
import json
import struct

HOST = "0.0.0.0"
PORT = 5002

KEY = "SECURITY"


# ============================================================
# VIGENERE ENCRYPTION
# ============================================================

def encrypt(text, key):

    result = ""
    key = key.upper()
    key_index = 0

    for char in text:

        if char.isalpha():

            shift = ord(
                key[key_index % len(key)]
            ) - ord("A")

            if char.isupper():

                result += chr(
                    (ord(char) - ord("A") + shift) % 26
                    + ord("A")
                )

            else:

                result += chr(
                    (ord(char) - ord("a") + shift) % 26
                    + ord("a")
                )

            key_index += 1

        else:

            result += char

    return result


# ============================================================
# VIGENERE DECRYPTION
# ============================================================

def decrypt(ciphertext, key):

    result = ""
    key = key.upper()
    key_index = 0

    for char in ciphertext:

        if char.isalpha():

            shift = ord(
                key[key_index % len(key)]
            ) - ord("A")

            if char.isupper():

                result += chr(
                    (ord(char) - ord("A") - shift) % 26
                    + ord("A")
                )

            else:

                result += chr(
                    (ord(char) - ord("a") - shift) % 26
                    + ord("a")
                )

            key_index += 1

        else:

            result += char

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
print("              VIGENERE CIPHER SERVER")
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


# ============================================================
# SERVER MENU
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

            plaintext = data["plaintext"]
            ciphertext = data["ciphertext"]
            key = data["key"]

            print("\n")
            print("=" * 60)
            print("CLIENT → SERVER")
            print("=" * 60)

            print("\nPlaintext:")
            print(plaintext)

            print("\nKey:")
            print(key)

            print("\nCiphertext:")
            print(ciphertext)

            decrypted = decrypt(
                ciphertext,
                key
            )

            print("\nDecrypted Plaintext:")
            print(decrypted)

            print(
                "\n✓ Vigenere decryption successful."
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

        key = input(
            "Enter key (press Enter for SECURITY): "
        ).strip()

        if not key:
            key = KEY

        ciphertext = encrypt(
            plaintext,
            key
        )

        print("\nPlaintext:")
        print(plaintext)

        print("\nKey:")
        print(key)

        print("\nCiphertext:")
        print(ciphertext)

        # Wait for client to select option 2
        print(
            "\nWaiting for client to select Receive..."
        )

        request = receive_data(
            conn
        )

        if request is None:
            break

        if request["operation"] == "REQUEST":

            send_data(
                conn,
                {
                    "operation": "SERVER_SEND",
                    "ciphertext": ciphertext,
                    "key": key
                }
            )

            print(
                "\n✓ Message sent to client."
            )

        else:

            print(
                "\nClient did not request the message."
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