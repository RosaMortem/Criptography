#3
import random
import struct

def rotate_left(value, shift, bit_size=16):
    return ((value << shift) | (value >> (bit_size - shift))) & (2**bit_size - 1)
def rotate_right(value, shift, bit_size=16):
    return ((value >> shift) | (value << (bit_size - shift))) & (2**bit_size - 1)
def F(x0, x1, x2):
    not_x0 = (~x0)
    x0_x1 = not_x0 ^ (rotate_left(x1, 5)) %  (2**16)
    x0_x1_x2 = x0_x1 & rotate_right(x2, 9)
    return x0_x1_x2
def generate_round_key(K_64, i):
    shift_1 = i * 5
    shift_2  = i * 2
    shifted_key1 = K_64 << shift_1
    shifted_key2 = K_64 >> shift_2
    res = (shifted_key1 ^ shifted_key2) & (2**16 - 1)
    return res
def feistel_round(x0, x1, x2, x3, key, round_num):
    k_i = generate_round_key(key, round_num)
    F_result = F(x0, x1, x2)
    new_x0 = x3 ^ F_result
    new_x1 = x0
    new_x2 = x1 ^ k_i
    new_x3 = x2 ^ x3
    return new_x0, new_x1, new_x2, new_x3
def feistel_encrypt_block(block, key, rounds):
    x0, x1, x2, x3 = block
    for i in range(rounds):
        x0, x1, x2, x3 = feistel_round(x0, x1, x2, x3, key, i)
    return x0, x1, x2, x3

def hash_feistel(blocks, key, iv, rounds=4):
    feedback = iv
    for block in blocks:
        encrypted_feedback = feistel_encrypt_block(feedback, key, rounds)
        feedback = tuple(a ^ b for a, b in zip(block, encrypted_feedback))
    return feedback

def finalize_hash(hash_64bit):
    return hash_64bit[0] ^ hash_64bit[1] ^ hash_64bit[2] ^ hash_64bit[3]

def read_text_blocks(filename):
    with open(filename, 'r') as file:
        data = file.read().encode()
    blocks = []
    for i in range(0, len(data), 8):
        block = data[i:i+8]
        if len(block) < 8:
            block += bytes(8 - len(block))
        x0 = int.from_bytes(block[:2], 'big')
        x1 = int.from_bytes(block[2:4], 'big')
        x2 = int.from_bytes(block[4:6], 'big')
        x3 = int.from_bytes(block[6:], 'big')
        blocks.append((x0, x1, x2, x3))
    return blocks
def write_text_blocks(blocks, filename):
    with open(filename, 'wb') as file:
        for block in blocks:
            for part in block:
                file.write(part.to_bytes(2, 'big'))

def find_collision_linear(h0, key, hash_size=64, max_messages=2000000):
    seen_hashes = {}
    mask = (1 << hash_size) - 1

    for i in range(max_messages):
        m = struct.pack(">Q", i)
        hash_64bit = hash_feistel([m], key, h0)
        h = sum(hash_64bit) & mask

        if h in seen_hashes:
            m_prev = seen_hashes[h]
            return m_prev, m, h

        seen_hashes[h] = m

    raise Exception("Коллизия не найдена")


def main():
    key = random.getrandbits(64)
    iv = (random.getrandbits(16), random.getrandbits(16), random.getrandbits(16), random.getrandbits(16))

    print(f"Ключ шифрования: {key:016X}")
    print(f"Инициализационный вектор (IV): {[f'{x:04X}' for x in iv]}")

    plaintext_blocks = read_text_blocks('for_collision.txt')
    print("\nИсходные блоки текста:")
    for i, block in enumerate(plaintext_blocks):
        print(f"  Блок {i}: {[f'{x:04X}' for x in block]}")

    hash_64bit = hash_feistel(plaintext_blocks, key, iv, rounds=4)
    print("\nХеш-код (64 бита):", [f"{x:04X}" for x in hash_64bit])

    hash_32bit = finalize_hash(hash_64bit)
    print("Финализированный хеш-код (32 бита):", f"{hash_32bit:08X}")

    h0 = iv
    collision_64bit_1, collision_64bit_2, collision_hash_64bit = find_collision_linear(h0, key, hash_size=64)
    if collision_64bit_1:
        print("\nНайдена 64-битная коллизия:")
        print("  Блоки 1:", [f"{x:04X}" for x in collision_64bit_1])
        print("  Блоки 2:", [f"{x:04X}" for x in collision_64bit_2])
        print("  Хеш-код:", collision_hash_64bit)
    else:
        print("Коллизия не найдена за указанное количество попыток.")


if __name__ == "__main__":
    main()
