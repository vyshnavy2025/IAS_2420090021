import socket
import struct
import json
import os

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from pypdf import PdfReader
from docx import Document


HOST = "0.0.0.0"
PORT = 5001

# Same key must be used on both sides
KEY = b"12345678901234567890123456789012"


# ============================================================
# AES ENCRYPTION
# ============================================================

def encrypt_aes(text):
    data = text.encode("utf-8")

    cipher = AES.new(KEY, AES.MODE_CBC)

    ciphertext = cipher.encrypt(
        pad(data, AES.block_size)
    )

    # IV + ciphertext
    return cipher.iv + ciphertext


# ============================================================
# AES DECRYPTION
# ============================================================

def decrypt_aes(data):
    iv = data[:16]
    ciphertext = data[16:]

    cipher = AES.new(
        KEY,
        AES.MODE_CBC,
        iv
    )

    plaintext = unpad(
        cipher.decrypt(ciphertext),
        AES.block_size
    )

    return plaintext.decode("utf-8")


# ============================================================
# EXTRACT TEXT
# ============================================================

def extract_text(path):

    extension = os.path.splitext(path)[1].lower()

    if extension == ".txt":

        with open(
            path,
            "r",
            encoding="utf-8",
            errors="replace"
        ) as f:
            return f.read()

    elif extension == ".pdf":

        reader = PdfReader(path)

        text = ""

        for page in reader.pages:

            page_text = page.extract_text()

            if page_text:
                text += page_text + "\n"

        return text

    elif extension == ".docx":

        document = Document(path)

        text = ""

        for paragraph in document.paragraphs:
            text += paragraph.text + "\n"

        return text

    else:

        print("\nOnly TXT, PDF and DOCX are supported.")
        return None


# ============================================================
# SEND HEADER
# ============================================================

def send_header(sock, data):

    message = json.dumps(data).encode()

    sock.sendall(
        struct.pack(
            "!I",
            len(message)
        )
    )

    sock.sendall(message)


# ============================================================
# RECEIVE HEADER
# ============================================================

def receive_header(sock):

    data = receive_exact(sock, 4)

    if not data:
        return None

    size = struct.unpack(
        "!I",
        data
    )[0]

    header = receive_exact(
        sock,
        size
    )

    if not header:
        return None

    return json.loads(
        header.decode()
    )


# ============================================================
# RECEIVE EXACT DATA
# ============================================================

def receive_exact(sock, size):

    data = b""

    while len(data) < size:

        packet = sock.recv(
            min(
                65536,
                size - len(data)
            )
        )

        if not packet:
            return None

        data += packet

    return data


# ============================================================
# DISPLAY PLAINTEXT
# ============================================================

def display_plaintext(title, text):

    print("\n")
    print("=" * 70)
    print(title)
    print("=" * 70)

    print(text)

    print("=" * 70)


# ============================================================
# DISPLAY CIPHERTEXT
# ============================================================

def display_ciphertext(title, ciphertext):

    print("\n")
    print("=" * 70)
    print(title)
    print("=" * 70)

    print(ciphertext.hex())

    print("=" * 70)


# ============================================================
# GET FILE PATH
# ============================================================

def get_file_path():

    print("\nEnter complete file path.")

    print(
        r'Example: C:\Users\vyshnavy\Downloads\sample.pdf'
    )

    path = input(
        "\nFile path: "
    ).strip()

    path = path.strip('"')

    if not os.path.isfile(path):

        print("\nERROR: File not found!")

        return None

    return path


# ============================================================
# SERVER RECEIVES FILE
# ============================================================

def receive_file(conn):

    print("\n")
    print("=" * 70)
    print("CLIENT → SERVER")
    print("=" * 70)

    header = receive_header(conn)

    if header is None:
        print("\nClient disconnected.")
        return False

    if header["operation"] == "EXIT":
        return False

    if header["operation"] != "CLIENT_SEND":
        print("\nInvalid request.")
        return True

    filename = header["filename"]
    size = header["size"]

    print("\nFile:", filename)
    print("Ciphertext size:", size, "bytes")

    ciphertext = receive_exact(
        conn,
        size
    )

    if ciphertext is None:
        print("\nReceiving failed.")
        return False

    # Show ciphertext
    display_ciphertext(
        "CLIENT AES CIPHERTEXT → SERVER",
        ciphertext
    )

    # Decrypt
    try:

        plaintext = decrypt_aes(
            ciphertext
        )

    except Exception as e:

        print(
            "\nAES decryption error:",
            e
        )

        return True

    # Show plaintext
    display_plaintext(
        "CLIENT PLAINTEXT → SERVER",
        plaintext
    )

    print(
        "\n✓ AES decryption successful."
    )

    print(
        "✓ No decrypted file was saved."
    )

    return True


# ============================================================
# SERVER SENDS FILE
# ============================================================

def send_file(conn):

    print("\n")
    print("=" * 70)
    print("SERVER → CLIENT")
    print("=" * 70)

    path = get_file_path()

    if path is None:
        return True

    filename = os.path.basename(path)

    # Extract actual text
    plaintext = extract_text(path)

    if plaintext is None:
        return True

    # Display plaintext
    display_plaintext(
        "SERVER PLAINTEXT",
        plaintext
    )

    # AES encrypt
    ciphertext = encrypt_aes(
        plaintext
    )

    # Display ciphertext
    display_ciphertext(
        "SERVER AES CIPHERTEXT",
        ciphertext
    )

    print(
        "\n✓ AES encryption successful."
    )

    # Tell client file is coming
    send_header(
        conn,
        {
            "operation": "SERVER_SEND",
            "filename": filename,
            "size": len(ciphertext)
        }
    )

    # Send ciphertext
    conn.sendall(ciphertext)

    print(
        "\n✓ Ciphertext sent to client."
    )

    print(
        "✓ Encrypted file was NOT saved."
    )

    return True


# ============================================================
# SERVER
# ============================================================

print("\n")
print("=" * 70)
print("                     AES SERVER")
print("                   PyCryptodome")
print("=" * 70)

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
# SERVER LOOP
# ============================================================

while True:

    print("\n")
    print("=" * 60)
    print("SERVER MENU")
    print("=" * 60)

    print("1. Receive File from Client")
    print("2. Send File to Client")
    print("3. Exit")

    choice = input(
        "\nEnter choice: "
    )

    # --------------------------------------------------------
    # RECEIVE
    # --------------------------------------------------------

    if choice == "1":

        print(
            "\nSelect option 1 on CLIENT."
        )

        if not receive_file(conn):
            break

    # --------------------------------------------------------
    # SEND
    # --------------------------------------------------------

    elif choice == "2":

        print(
            "\nSelect option 2 on CLIENT."
        )

        # Wait for client to announce RECEIVE mode
        header = receive_header(conn)

        if header is None:
            break

        if header["operation"] == "CLIENT_READY":

            send_file(conn)

        elif header["operation"] == "EXIT":

            break

        else:

            print(
                "\nClient did not select Receive File."
            )

    # --------------------------------------------------------
    # EXIT
    # --------------------------------------------------------

    elif choice == "3":

        try:

            send_header(
                conn,
                {
                    "operation": "SERVER_EXIT"
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