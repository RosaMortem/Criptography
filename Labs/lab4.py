#1
import random
import time

def rotate_left(value, shift, bit_size=16):
    return ((value << shift) | (value >> (bit_size - shift))) & (2**bit_size - 1)

def rotate_right(value, shift, bit_size=16):
    return ((value >> shift) | (value << (bit_size - shift))) & (2**bit_size - 1)

def F1(m2, m3):
    return rotate_left(m2, 5) ^ m3

def F2(m0, m1):
    m0_not = ~m0 & (2**16 - 1)
    m1_rotated = rotate_right(~m1 & (2**16 - 1), 12)
    return m0_not ^ m1_rotated

def generate_round_key(key, round_num):
    return (rotate_left(key, round_num * 3) ^ rotate_right(key, round_num)) & (2**16 - 1)

def feistel_round(m0, m1, m2, m3, key, round_num):
    round_key = generate_round_key(key, round_num)
    m0_new = m0 ^ round_key ^ F1(m2, m3)
    m1_new = m1 ^ round_key ^ F2(m0, m1)
    m2_new = m2 ^ (round_key >> 3)
    m3_new = m3 ^ (round_key >> 3)
    return m0_new, m1_new, m2_new, m3_new

def feistel_encrypt_block(block, key, rounds):
    m0, m1, m2, m3 = block
    for i in range(rounds):
        m0, m1, m2, m3 = feistel_round(m0, m1, m2, m3, key, i)
    return m0, m1, m2, m3

def hash_feistel(blocks, key, iv, rounds=4):
    feedback = tuple(a ^ b for a, b in zip(iv, blocks[0]))
    for block in blocks:
        encrypted_feedback = feistel_encrypt_block(feedback, key, rounds)
        feedback = tuple(a ^ b for a, b in zip(block, encrypted_feedback))
    return feedback

def finalize_hash(hash_64bit):
    return hash_64bit[0] ^ hash_64bit[1] ^ hash_64bit[2] ^ hash_64bit[3]

def pbkdf2(password, salt, iterations, dk_len, rounds=4):

    password_blocks = [
        tuple(int.from_bytes(password[i:i + 2], 'big') for i in range(j, j + 4 * 2, 2))
        for j in range(0, len(password), 4 * 2)
    ]

    iv = tuple(int.from_bytes(salt[i:i + 2], 'big') for i in range(0, len(salt), 2))
    while len(iv) < 4:
        iv += (0,)

    block_count = (dk_len + 7) // 8
    derived_key = b''

    print("=== Отладка PBKDF2 ===")
    for block_num in range(1, block_count + 1):
        print(f"  Блок {block_num}:")

        u = hash_feistel(password_blocks, int.from_bytes(salt, 'big') ^ block_num, iv, rounds)
        t = u
        print(f"    U1: {u}")

        for iteration in range(1, iterations):
            u = hash_feistel(password_blocks, int.from_bytes(salt, 'big'), u, rounds)
            t = tuple(a ^ b for a, b in zip(t, u))
            if iteration < 5:
                print(f"    U{iteration + 1}: {u}")

        derived_key += b''.join(part.to_bytes(2, 'big') for part in t)

    print("\n=== Секретный ключ ===")
    print(f"  {derived_key.hex()}")

    return derived_key[:dk_len]


def generate_salt(length=8):
    return bytes(random.randint(0, 255) for _ in range(length))

def main():
    password = b"Qwerty123"
    salt = generate_salt()
    iterations = 1000
    dk_len = 32
    rounds = 4

    print("=== Параметры ===")
    print(f"Пароль: {password.decode()}")
    print(f"Соль: {salt.hex()}")
    print(f"Итерации: {iterations}")
    print(f"Длина ключа: {dk_len} байт")
    print(f"Раунды хэш-функции: {rounds}\n")

    start_time = time.time()
    derived_key = pbkdf2(password, salt, iterations, dk_len, rounds)
    elapsed_time = time.time() - start_time

    print("=== Результаты ===")
    print(f"Ключ: {derived_key.hex()}")
    print(f"Время выполнения: {elapsed_time:.4f} секунд")

    print("\n=== Тесты с разным числом итераций ===")
    for test_iterations in [100, 500, 1000, 5000]:
        start_time = time.time()
        pbkdf2(password, salt, test_iterations, dk_len, rounds)
        elapsed_time = time.time() - start_time
        print(f"Итерации: {test_iterations}, Время: {elapsed_time:.4f} секунд")

if __name__ == "__main__":
    main()
