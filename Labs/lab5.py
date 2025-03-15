#25
from sympy import mod_inverse, isprime, nextprime

import math
import random

def generate_keys(bits=512):
    """Генерация открытого и закрытого ключей RSA."""

    p = nextprime(random.getrandbits(bits // 2))
    q = nextprime(random.getrandbits(bits // 2))

    n = p * q
    phi_n = (p - 1) * (q - 1)

    e = 65537
    while math.gcd(e, phi_n) != 1:
        e = random.randrange(2, phi_n)

    d = mod_inverse(e, phi_n)

    return (e, n), (d, n)

def rsa_encrypt(message, public_key):
    """Шифрование сообщения с использованием RSA."""
    e, n = public_key
    message_blocks = [ord(c) for c in message]
    cipher_blocks = [pow(m, e, n) for m in message_blocks]
    return cipher_blocks

def rsa_decrypt(ciphertext, private_key):
    """Расшифровка RSA."""
    d, n = private_key
    message_blocks = [pow(c, d, n) for c in ciphertext]
    message = ''.join(chr(m) for m in message_blocks)
    return message

def factorize(n):
    """Факторизация числа n на простые множители p и q."""
    for i in range(2, math.isqrt(n) + 1):
        if n % i == 0:
            p, q = i, n // i
            if isprime(p) and isprime(q):
                return p, q
    raise ValueError("Не удалось факторизовать n на простые множители.")

def rsa_decrypt_given_public_key(ciphertext, e, n):
    """Расшифровка RSA с использованием только публичного ключа."""
    p, q = factorize(n)

    phi_n = (p - 1) * (q - 1)

    d = mod_inverse(e, phi_n)

    cipher_blocks = [
        int(str(ciphertext)[i:i+15])
        for i in range(0, len(str(ciphertext)), 15)
    ]

    message_blocks = [pow(c, d, n) for c in cipher_blocks]
    message = ''
    for m in message_blocks:
        for i in range(0, len(str(m)), 2):
            message += ''.join(''.join(chr(int(str(m)[i:i+2]))))


    return message

# Задача 5.1: Генерация ключей и шифрование/расшифрование
public_key, private_key = generate_keys(bits=64)
message = "I Love This World"
print("Оригинальное сообщение:", message)

ciphertext = rsa_encrypt(message, public_key)
print("Зашифрованное сообщение:", ciphertext)

plaintext = rsa_decrypt(ciphertext, private_key)
print("Расшифрованное сообщение:", plaintext)

# Задача 5.2: Расшифровка с использованием публичного ключа
n = 775975524244507
e = 92737
ciphertext = 1654779743873183751353006385094746930962016872987156778877162905951074293158614643211676

message_decoded = rsa_decrypt_given_public_key(ciphertext, e, n)
print("Расшифрованное сообщение из задачи 4.2:", message_decoded)
