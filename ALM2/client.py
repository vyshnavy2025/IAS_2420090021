import socket
import struct
import json
import os

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from pypdf import PdfReader
from docx import Document


HOST = "127.0.0.1"
PORT = 5001

# Same key as server
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

        print(
            "\nOnly TXT, PDF and DOCX are supported."
        )

        return None


# ============================================================
# SEND HEADER
# ============================================================

def send_header(sock, data):

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
# RECEIVE HEADER
# ============================================================

def receive_header(sock):

    data = receive_exact(
        sock,
        4
    )

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
# RECEIVE EXACT
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

    print(
        ciphertext.hex()
    )

    print("=" * 70)


# ============================================================
# GET FILE
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

        print(
            "\nERROR: File not found!"
        )

        return None

    return path


# ============================================================
# CLIENT SEND FILE
# ============================================================

def send_file(sock):

    print("\n")
    print("=" * 70)
    print("CLIENT → SERVER")
    print("=" * 70)

    path = get_file_path()

    if path is None:
        return

    filename = os.path.basename(path)

    # Extract text
    plaintext = extract_text(path)

    if plaintext is None:
        return

    # Display plaintext
    display_plaintext(
        "CLIENT PLAINTEXT",
        plaintext
    )

    # Encrypt
    ciphertext = encrypt_aes(
        plaintext
    )

    # Display ciphertext
    display_ciphertext(
        "CLIENT AES CIPHERTEXT",
        ciphertext
    )

    # Send header
    send_header(
        sock,
        {
            "operation": "CLIENT_SEND",
            "filename": filename,
            "size": len(ciphertext)
        }
    )

    # Send ciphertext
    sock.sendall(ciphertext)

    print(
        "\n✓ Ciphertext sent to server."
    )

    # Server confirmation
    response = receive_header(
        sock
    )

    if response:

        print(
            "\n✓ Server decrypted successfully."
        )


# ============================================================
# CLIENT RECEIVE FILE
# ============================================================

def receive_file(sock):

    print("\n")
    print("=" * 70)
    print("CLIENT ← SERVER")
    print("=" * 70)

    # Tell server we are ready
    send_header(
        sock,
        {
            "operation": "CLIENT_READY"
        }
    )

    print(
        "\n✓ Client is ready to receive."
    )

    # Wait for server file
    header = receive_header(
        sock
    )

    if header is None:

        print(
            "\nServer disconnected."
        )

        return

    if header["operation"] == "SERVER_EXIT":

        print(
            "\nServer closed."
        )

        return

    if header["operation"] != "SERVER_SEND":

        print(
            "\nInvalid server response."
        )

        return

    filename = header["filename"]
    size = header["size"]

    print(
        "\nFile:",
        filename
    )

    print(
        "Ciphertext size:",
        size,
        "bytes"
    )

    # Receive ciphertext
    ciphertext = receive_exact(
        sock,
        size
    )

    if ciphertext is None:

        print(
            "\nReceiving failed."
        )

        return

    # Display ciphertext
    display_ciphertext(
        "SERVER AES CIPHERTEXT → CLIENT",
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

        return

    # Display plaintext
    display_plaintext(
        "SERVER PLAINTEXT → CLIENT",
        plaintext
    )

    print(
        "\n✓ AES decryption successful."
    )

    print(
        "✓ Decrypted file was NOT saved."
    )


# ============================================================
# CLIENT
# ============================================================

print("\n")
print("=" * 70)
print("                     AES CLIENT")
print("                   PyCryptodome")
print("=" * 70)


client = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

try:

    client.connect(
        (
            HOST,
            PORT
        )
    )

    print(
        "\n✓ Connected to server."
    )

except Exception as e:

    print(
        "\nConnection error:",
        e
    )

    exit()


# ============================================================
# CLIENT MENU
# ============================================================

while True:

    print("\n")
    print("=" * 60)
    print("CLIENT MENU")
    print("=" * 60)

    print(
        "1. Send File to Server"
    )

    print(
        "2. Receive File from Server"
    )

    print(
        "3. Exit"
    )

    choice = input(
        "\nEnter choice: "
    )

    if choice == "1":

        send_file(client)

    elif choice == "2":

        receive_file(client)

    elif choice == "3":

        send_header(
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

print(
    "\nClient closed."
)