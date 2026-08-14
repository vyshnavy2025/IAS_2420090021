# crypto.py

# ============================================================
# CAESAR CIPHER
# ============================================================

def caesar_encrypt(text, shift):
    result = ""

    for ch in text:
        if ch.isupper():
            result += chr((ord(ch) - ord('A') + shift) % 26 + ord('A'))
        elif ch.islower():
            result += chr((ord(ch) - ord('a') + shift) % 26 + ord('a'))
        else:
            result += ch

    return result


def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)


# ============================================================
# PLAYFAIR CIPHER
# ============================================================

def create_playfair_matrix(key):
    key = ''.join(ch for ch in key.upper() if ch.isalpha())
    key = key.replace('J', 'I')

    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"

    result = ""

    for ch in key + alphabet:
        if ch not in result:
            result += ch

    matrix = []

    for i in range(0, 25, 5):
        matrix.append(result[i:i + 5])

    return matrix


def find_position(matrix, ch):
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == ch:
                return row, col

    return None


def prepare_playfair_text(text):
    text = ''.join(ch for ch in text.upper() if ch.isalpha())
    text = text.replace('J', 'I')

    result = ""
    i = 0

    while i < len(text):
        a = text[i]

        if i + 1 >= len(text):
            result += a + 'X'
            i += 1

        else:
            b = text[i + 1]

            if a == b:
                result += a + 'X'
                i += 1
            else:
                result += a + b
                i += 2

    return result


def playfair_encrypt(text, key):
    matrix = create_playfair_matrix(key)
    text = prepare_playfair_text(text)

    result = ""

    for i in range(0, len(text), 2):

        a = text[i]
        b = text[i + 1]

        r1, c1 = find_position(matrix, a)
        r2, c2 = find_position(matrix, b)

        if r1 == r2:
            result += matrix[r1][(c1 + 1) % 5]
            result += matrix[r2][(c2 + 1) % 5]

        elif c1 == c2:
            result += matrix[(r1 + 1) % 5][c1]
            result += matrix[(r2 + 1) % 5][c2]

        else:
            result += matrix[r1][c2]
            result += matrix[r2][c1]

    return result


def playfair_decrypt(cipher, key):
    matrix = create_playfair_matrix(key)

    cipher = ''.join(ch for ch in cipher.upper() if ch.isalpha())
    cipher = cipher.replace('J', 'I')

    result = ""

    for i in range(0, len(cipher), 2):

        a = cipher[i]
        b = cipher[i + 1]

        r1, c1 = find_position(matrix, a)
        r2, c2 = find_position(matrix, b)

        if r1 == r2:
            result += matrix[r1][(c1 - 1) % 5]
            result += matrix[r2][(c2 - 1) % 5]

        elif c1 == c2:
            result += matrix[(r1 - 1) % 5][c1]
            result += matrix[(r2 - 1) % 5][c2]

        else:
            result += matrix[r1][c2]
            result += matrix[r2][c1]

    return result


# ============================================================
# SIMPLE DATA ENCRYPTION STANDARD - SDES
# ============================================================

P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]

P8 = [6, 3, 7, 4, 8, 5, 10, 9]

IP = [2, 6, 3, 1, 4, 8, 5, 7]

IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]

EP = [4, 1, 2, 3, 2, 3, 4, 1]

P4 = [2, 4, 3, 1]

S0 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 2]
]

S1 = [
    [0, 1, 2, 3],
    [2, 0, 1, 3],
    [3, 0, 1, 0],
    [2, 1, 0, 3]
]


def permutation(bits, order):
    return ''.join(bits[i - 1] for i in order)


def left_shift(bits, count):
    return bits[count:] + bits[:count]


def generate_keys(key):

    key = permutation(key, P10)

    left = key[:5]
    right = key[5:]

    left = left_shift(left, 1)
    right = left_shift(right, 1)

    key1 = permutation(left + right, P8)

    left = left_shift(left, 2)
    right = left_shift(right, 2)

    key2 = permutation(left + right, P8)

    return key1, key2


def sbox_lookup(bits, sbox):

    row = int(bits[0] + bits[3], 2)
    column = int(bits[1] + bits[2], 2)

    return format(sbox[row][column], '02b')


def fk(bits, key):

    left = bits[:4]
    right = bits[4:]

    expanded = permutation(right, EP)

    xor_result = ""

    for a, b in zip(expanded, key):
        xor_result += str(int(a) ^ int(b))

    left_sbox = xor_result[:4]
    right_sbox = xor_result[4:]

    sbox_output = (
        sbox_lookup(left_sbox, S0)
        + sbox_lookup(right_sbox, S1)
    )

    p4_result = permutation(sbox_output, P4)

    new_left = ""

    for a, b in zip(left, p4_result):
        new_left += str(int(a) ^ int(b))

    return new_left + right


def sdes_encrypt_byte(byte_value, key):

    bits = format(byte_value, '08b')

    key1, key2 = generate_keys(key)

    bits = permutation(bits, IP)

    bits = fk(bits, key1)

    bits = bits[4:] + bits[:4]

    bits = fk(bits, key2)

    bits = permutation(bits, IP_INV)

    return int(bits, 2)


def sdes_decrypt_byte(byte_value, key):

    bits = format(byte_value, '08b')

    key1, key2 = generate_keys(key)

    bits = permutation(bits, IP)

    bits = fk(bits, key2)

    bits = bits[4:] + bits[:4]

    bits = fk(bits, key1)

    bits = permutation(bits, IP_INV)

    return int(bits, 2)


def sdes_encrypt(data, key="1010000010"):

    result = bytearray()

    for byte in data:
        result.append(sdes_encrypt_byte(byte, key))

    return bytes(result)


def sdes_decrypt(data, key="1010000010"):

    result = bytearray()

    for byte in data:
        result.append(sdes_decrypt_byte(byte, key))

    return bytes(result)