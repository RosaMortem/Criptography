import hashlib
import random

class EllipticCurve:
    def __init__(self, a, b, p, g_x, g_y, n):
        self.a = a
        self.b = b
        self.p = p
        self.g = (g_x, g_y)  # Генераторная точка
        self.n = n

    def is_on_curve(self, point):
        if point is None:
            return True
        x, y = point
        return (y ** 2 - (x ** 3 + self.a * x + self.b)) % self.p == 0

    def point_add(self, p1, p2):
        if p1 is None:
            return p2
        if p2 is None:
            return p1

        x1, y1 = p1
        x2, y2 = p2

        if x1 == x2 and y1 != y2:
            return None

        if x1 == x2:
            m = (3 * x1 ** 2 + self.a) * pow(2 * y1, -1, self.p)
        else:
            m = (y2 - y1) * pow(x2 - x1, -1, self.p)

        m %= self.p
        x3 = (m ** 2 - x1 - x2) % self.p
        y3 = (m * (x1 - x3) - y1) % self.p

        return x3, y3

    def scalar_mult(self, k, point):
        result = None
        addend = point

        while k:
            if k & 1:
                result = self.point_add(result, addend)
            addend = self.point_add(addend, addend)
            k >>= 1

        return result

curve = EllipticCurve(
    a=-3,
    b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    g_x=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    g_y=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162CBCE33576B315ECECBB6406837BF51F,
    n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
)

def generate_keys(curve):
    private_key = random.randint(1, curve.n - 1)
    public_key = curve.scalar_mult(private_key, curve.g)
    return private_key, public_key

def derive_shared_secret(private_key, peer_public_key, curve):
    shared_point = curve.scalar_mult(private_key, peer_public_key)
    shared_secret = hashlib.sha256(str(shared_point[0]).encode()).digest()
    return shared_secret

if __name__ == "__main__":
    print("Ключ для первого")
    alice_private_key, alice_public_key = generate_keys(curve)

    print("Ключ для второго")
    bob_private_key, bob_public_key = generate_keys(curve)

    print("Генерация общего секрета...")
    shared_secret_first = derive_shared_secret(alice_private_key, bob_public_key, curve)
    shared_secret_second = derive_shared_secret(bob_private_key, alice_public_key, curve)

    print("Общий секрет (first):", shared_secret_first.hex())
    print("Общий секрет (second):", shared_secret_second.hex())

    if shared_secret_first == shared_secret_second:
        print("Ключи совпали")
    else:
        print("Ключи не совпали")
