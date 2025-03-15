#1
import random
import time

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
    password = b"My 1! password"
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
