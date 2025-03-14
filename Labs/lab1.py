#7
import random

def rotate_left(value, shift, bit_size=16):
    return ((value << shift) | (value >> (bit_size - shift))) & (2**bit_size - 1)
def rotate_right(value, shift, bit_size=16):
    return ((value >> shift) | (value << (bit_size - shift))) & (2**bit_size - 1)
def F1(m2, m3):
    m2_shifted = rotate_left(m2, 5)
    return (m2_shifted ^ m3) % (2**16)
def F2(m0, m1):
    m0_not = ~m0 & (2**16 - 1)
    m1_not_shifted = rotate_right(~m1 & (2**16 - 1), 12)
    return m0_not ^ m1_not_shifted
def generate_round_key(K5_64, i):
    shift_amount = 2 * i + 1
    shifted_key = K5_64 >> shift_amount
    lower_32 = shifted_key & (2**32 - 1)
    upper_32 = (shifted_key >> 32) & (2**32 - 1)
    xor_result = lower_32 ^ upper_32
    return xor_result & (2**16 - 1)
def feistel_round(m0, m1, m2, m3, key, round_num):
    k_i = generate_round_key(key, round_num)
    f1_result = F1(m2, m3)
    f2_result = F2(m0, m1)
    new_m0 = m0 ^ k_i ^ f1_result
    new_m1 = m1 ^ k_i ^ f2_result
    new_m2 = m2 ^ (k_i >> 3)
    new_m3 = m3 ^ (k_i >> 3)
    return new_m0, new_m1, new_m2, new_m3
def feistel_encrypt_block(block, key, rounds):
    m0, m1, m2, m3 = block
    for i in range(rounds):
        m0, m1, m2, m3 = feistel_round(m0, m1, m2, m3, key, i)
    return m0, m1, m2, m3
def encrypt_decrypt_OFB(data_blocks, key, iv, rounds=4):
    result_blocks = []
    feedback = iv

    for block in data_blocks:
        encrypted_feedback = feistel_encrypt_block(feedback, key, rounds)
        result_block = tuple(a ^ b for a, b in zip(block, encrypted_feedback))
        result_blocks.append(result_block)
        feedback = encrypted_feedback

    return result_blocks

def read_text_blocks(filename):
    with open(filename, 'r') as file:
        data = file.read().encode()
    blocks = []
    for i in range(0, len(data), 8):
        block = data[i:i+8]
        if len(block) < 8:
            block += bytes(8 - len(block))
        m0 = int.from_bytes(block[:2], 'big')
        m1 = int.from_bytes(block[2:4], 'big')
        m2 = int.from_bytes(block[4:6], 'big')
        m3 = int.from_bytes(block[6:], 'big')
        blocks.append((m0, m1, m2, m3))
    return blocks

def write_text_blocks(blocks, filename):
    with open(filename, 'wb') as file:
        for block in blocks:
            for part in block:
                file.write(part.to_bytes(2, 'big'))

key = random.getrandbits(64)
iv = (random.getrandbits(16), random.getrandbits(16), random.getrandbits(16), random.getrandbits(16))
plaintext_blocks = read_text_blocks('input.txt')
ciphertext_blocks = encrypt_decrypt_OFB(plaintext_blocks, key, iv, rounds=4)

decrypted_blocks = encrypt_decrypt_OFB(ciphertext_blocks, key, iv, rounds=4)

write_text_blocks(decrypted_blocks, 'output.txt')

print(f"Ключ шифрования: {key:016X}")
print("Инициализационный вектор (IV):", [f"{x:04X}" for x in iv])

print("\nИсходные блоки текста:")
for i, block in enumerate(plaintext_blocks):
    print(f"  Блок {i}: {[f'{x:04X}' for x in block]}")

print("\nЗашифрованные блоки:")
for i, block in enumerate(ciphertext_blocks):
    print(f"  Блок {i}: {[f'{x:04X}' for x in block]}")

print("\nРасшифрованные блоки:")
for i, block in enumerate(decrypted_blocks):
    print(f"  Блок {i}: {[f'{x:04X}' for x in block]}")
if plaintext_blocks == decrypted_blocks:
    print("\nРасшифрованный текст совпадает с исходным.")
else:
    print("\nРасшифрованный текст не совпадает с исходным.")
