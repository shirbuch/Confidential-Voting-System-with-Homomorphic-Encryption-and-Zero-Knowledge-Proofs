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
