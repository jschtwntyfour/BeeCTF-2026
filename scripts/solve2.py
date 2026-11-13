

from sympy import isprime, integer_nthroot, gcd
from math import isqrt
from itertools import permutations
from functools import reduce

# ---- paste the values from output.txt ----
b = -407946574
c = 11628115226198413
N = 164103673186697727671722517410226002906879141982342298006270740993575128060288062377686357173615144650094900819078657436448212260441188396518435481548008982857808877755043040683468826834204148286862400745792942911835378554490970396965476874729956964887490530190715807606376876934079480979314518005127672139955529452398314934852303956344925712426471106427349767243505754306224918218253432291631725948044232476004787137247267688452041121917757041903922924197626084123090022652514946023212690698102436410479976971803282749892087676271910247477
e = 65537
enc_flag = 102832139856312140336726094268851743508377413685056466478748226207484626066630287716796833661909161899880937337618949062565552264033571851045993011107979073721293682863726166331594753684082828845118786778308204348436965601513817088775583392149401812385050290911191099259842128621204875936065554380892216940641331468951366485513574353970130737811703965209145155308271867280466084409254323109131133830508125204416074712106428838349225044881769804658631340533343501492660056186554271363488166023024317526226248126487617205847186710620133768946
aux_pieces = [{'m': 2561491, 'S': 11056512, 'P': 18053508979136}, {'m': 24608653, 'S': 86014386, 'P': 101242257423968}, {'m': 38948137, 'S': 58029350, 'P': 717480558864069}, {'m': 62359261, 'S': 285676679, 'P': 13019423790321208}, {'m': 54206773, 'S': 205805922, 'P': 2097964148493437}, {'m': 48192329, 'S': 209784813, 'P': 3352924911931992}, {'m': 18283693, 'S': 51673811, 'P': 20839805895774}, {'m': 65441393, 'S': 281422623, 'P': 7277550341099060}, {'m': 25730777, 'S': 41777697, 'P': 357141440780810}, {'m': 28848451, 'S': 61386549, 'P': 880081987210844}, {'m': 23598079, 'S': 94792540, 'P': 1363038669333891}]

# ---- 1. recover r1, r2 from x^2 + b x + c = 0 ----
disc = b * b - 4 * c
sqrt_disc, exact = integer_nthroot(disc, 2)
assert exact, "discriminant is not a perfect square"
r1 = (-b + sqrt_disc) // 2
r2 = (-b - sqrt_disc) // 2
assert r1 + r2 == -b and r1 * r2 == c
print("[+] r1, r2 =", r1, r2)

# ---- 2. recover leak = k mod m for every piece ----
residues = []
moduli = []
for piece in aux_pieces:
    m, S, P = piece["m"], piece["S"], piece["P"]
    disc2 = S * S - 4 * P
    sq, ok = integer_nthroot(disc2, 2)
    assert ok, f"bad piece for m={m}"
    root_hi = (S + sq) // 2
    root_lo = (S - sq) // 2
    leak = min(root_hi, root_lo)   # decoy > m > leak always
    assert 0 <= leak < m
    residues.append(leak)
    moduli.append(m)

# ---- 3. CRT to recover k ----
def crt(residues, moduli):
    M = reduce(lambda a, b_: a * b_, moduli)
    x = 0
    for r_i, m_i in zip(residues, moduli):
        Mi = M // m_i
        x += r_i * Mi * pow(Mi, -1, m_i)
    return x % M, M

k, M = crt(residues, moduli)
print("[+] k =", k)
print("[+] M > k ?", M > k)

# ---- 4. candidate primes ----
q1 = r1 + k
q2 = r2 + k
print("[+] q1 =", q1, "isprime:", isprime(q1))
print("[+] q2 =", q2, "isprime:", isprime(q2))
assert isprime(q1) and isprime(q2)

# ---- 5. figure out exponents + p3 ----
found = None
for a1, a2, a3 in set(permutations([2, 3, 2])):
    denom = (q1 ** a1) * (q2 ** a2)
    if N % denom != 0:
        continue
    rest = N // denom
    p3, exact = integer_nthroot(rest, a3)
    if exact and isprime(p3):
        found = (a1, a2, a3, p3)
        break

assert found, "couldn't find matching exponent/p3 combo"
a1, a2, a3, p3 = found
print(f"[+] exponents (a1,a2,a3) = ({a1},{a2},{a3})")
print("[+] p3 =", p3)

assert (q1 ** a1) * (q2 ** a2) * (p3 ** a3) == N

# ---- 6. RSA decrypt with known factorization (with multiplicities) ----
def phi_prime_power(p, a):
    return (p - 1) * (p ** (a - 1))

phi = phi_prime_power(q1, a1) * phi_prime_power(q2, a2) * phi_prime_power(p3, a3)
d = pow(e, -1, phi)
m_int = pow(enc_flag, d, N)

flag_bytes = m_int.to_bytes((m_int.bit_length() + 7) // 8, "big")
print("[+] FLAG:", flag_bytes.decode())
