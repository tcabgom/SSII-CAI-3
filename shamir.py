import random
import os
from sympy import symbols, interpolate

THRESHOLD = 5
TOTAL_SHARES = 10
NUM_TESTS = 50

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

    secret = int(polynomial.subs(x, 0)) % prime
    return secret

def test_shamir():
    successful_reconstructions = 0
    for _ in range(NUM_TESTS):
        secret_key = int.from_bytes(os.urandom(32), 'big')
        shares = generate_shares(secret_key)

        reconstructed_secret  = reconstruct_secret(shares[:THRESHOLD], THRESHOLD)

        if reconstructed_secret == secret_key:
            successful_reconstructions += 1

    success_rate = successful_reconstructions / NUM_TESTS
    print("#####   PRUEBA DE SHAMIR   #####\n- Total de acciones generadas: {}\n- Total de acciones necesarias para reconstruir el secreto: {}".format(TOTAL_SHARES, THRESHOLD))
    print("\nResultados de las pruebas:")
    print("Número de pruebas realizadas: ", NUM_TESTS)
    print("Número de reconstrucciones exitosas: ", successful_reconstructions)
    print("Tasa de éxito: {:.2%}".format(success_rate))


if __name__ == '__main__':
    test_shamir()
