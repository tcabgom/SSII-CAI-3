import random
from sympy import symbols, interpolate

THRESHOLD = 5
TOTAL_SHARES = 10

def generate_shares(secret):
    prime = 2**256 - 189
    coefficients = [secret] + [random.randint(0, prime - 1) for _ in range(THRESHOLD - 1)]

    shares = []
    for x in range(1, TOTAL_SHARES + 1):
        share = sum(c * (x**i) % prime for i, c in enumerate(coefficients)) % prime
        shares.append((x, share))

    return shares

def reconstruct_secret(shares, threshold):
    prime = 2**256 - 189

    x, y = symbols('x y')
    polynomial = interpolate(shares, x)

    secret = polynomial.subs(x, 0) % prime
    return secret

def test_shamir():
    secret_key = 1234567890

    shares = generate_shares(secret_key)
    print("Acciones generadas:")
    for share in shares:
        print("Acción {}: {}".format(share[0], share[1]))

    reconstructed_secret = reconstruct_secret(shares[:THRESHOLD], THRESHOLD)
    print("\nSecreto reconstruido:", reconstructed_secret)

if __name__ == '__main__':
    test_shamir()