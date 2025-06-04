import math
import random
from typing import Tuple

PRIME_MIN_VAL = 50
PRIME_MAX_VAL = 80

def generate_random_prime(min_val=50, max_val=100):
    """Generate a random prime number in given range"""    
    while True:
        candidate = random.randint(min_val, max_val)
        if is_prime(candidate):
            return candidate

def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return False
    return True

class PaillierContext:
    """Paillier cryptosystem context"""   
    def __init__(self):
        """Generate prime numbers"""
        self.p = generate_random_prime(PRIME_MIN_VAL, PRIME_MAX_VAL)
        self.q = generate_random_prime(PRIME_MIN_VAL, PRIME_MAX_VAL)
        
        # Ensure p != q
        while self.p == self.q:
            self.q = generate_random_prime(PRIME_MIN_VAL, PRIME_MAX_VAL)
            
        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)
        
        # Simplified variant parameters
        self.g = self.n + 1
        self.lmbda = self.phi
        self.mu = pow(self.lmbda, -1, self.n)
        
    def get_public_key(self) -> Tuple[int, int]:
        """Return public key (g, n)"""
        return (self.g, self.n)
    
    def decrypt(self, c: int) -> int:
        """Decrypt ciphertext c"""
        cl = pow(c, self.lmbda, self.n * self.n)
        l = int(cl - 1) / int(self.n)
        p = int((l * self.mu) % self.n)
        
        # Handle negative values (convert from modular arithmetic)
        if p > self.n // 2:
            p = p - self.n
            
        return p


def encrypt_vote(vote_value: int, public_key: Tuple[int, int]) -> Tuple[int, int]:
    """Encrypt vote using given public key, return ciphertext and random r"""
    g, n = public_key
    r = random.randint(1, n - 1)
    while math.gcd(r, n) != 1:
        r = random.randint(1, n - 1)
    
    encrypted_vote = (pow(g, vote_value, n * n) * pow(r, n, n * n)) % (n * n)
    return encrypted_vote, r


def calculate_encrypted_sum(encrypted_values: list, public_key: Tuple[int, int]) -> int:
    """Calculate homomorphic sum of all encrypted votes"""
    if not encrypted_values:
        return 0
        
    g, n = public_key
    
    # Homomorphic addition = multiplication of ciphertexts
    encrypted_sum = encrypted_values[0]
    for i in range(1, len(encrypted_values)):
        encrypted_sum = (encrypted_sum * encrypted_values[i]) % (n * n)
    
    return encrypted_sum


def generate_zkp_challange_response(m: int, r: int, public_key: Tuple[int, int], e: int) -> Tuple[int, int, int]:
    """Generate a zero-knowledge proof (u, v, w) for vote m encrypted with Paillier."""
    g, N = public_key
    N2 = N * N
    x = random.randint(1, N - 1)
    s = random.randint(1, N - 1)
    
    u = (pow(g, x, N2) * pow(s, N, N2)) % N2
    v = (x - e * m) % N
    w = (s * pow(r, -e, N)) % N
    
    return u, v, w

def verify_zkp_response(u: int, v: int, w: int, e: int, c, public_key: Tuple[int, int]) -> bool:
    """Verify zero-knowledge proof response (u, v, w) against challenge e."""
    g, N = public_key
    N2 = N * N
    lhs = (pow(g, v, N2) * pow(w, N, N2) * pow(c, e, N2)) % N2
    
    return lhs == u