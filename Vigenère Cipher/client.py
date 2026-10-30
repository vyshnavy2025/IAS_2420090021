import socket
import json
import struct

HOST = "127.0.0.1"
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

            shift = ord(key[key_index % len(key)]) - ord("A")

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

            shift = ord(key[key_index % len(key)]) - ord("A")

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

    message = json.dumps(data).encode()

    sock.sendall(
        struct.pack("!I", len(message))
    )

    sock.sendall(message)


# ============================================================
# RECEIVE DATA
# ============================================================

def receive_data(sock):

    size_data = receive_exact(sock, 4)

    if not size_data:
        return None

    size = struct.unpack("!I", size_data)[0]

    data = receive_exact(sock, size)

    if not data:
        return None

    return json.loads(data.decode())


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
print("              VIGENERE CIPHER CLIENT")
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

        send_data(
            client,
            {
                "operation": "SEND",
                "plaintext": plaintext,
                "ciphertext": ciphertext,
                "key": key
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
            key = data["key"]

            plaintext = decrypt(
                ciphertext,
                key
            )

            print("\n")
            print("=" * 60)
            print("SERVER → CLIENT")
            print("=" * 60)

            print("\nCiphertext:")
            print(ciphertext)

            print("\nKey:")
            print(key)

            print("\nPlaintext:")
            print(plaintext)

            print(
                "\n✓ Vigenere decryption successful."
            )

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