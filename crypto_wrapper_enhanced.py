import math
import random
from typing import Tuple, Optional
from dataclasses import dataclass

# Constants
PRIME_MIN_VAL = 50
PRIME_MAX_VAL = 80
DEFAULT_GROUP_GENERATOR = 2
SCHNORR_PRIME = 11835969984353354216691437291006245763846242542829548494585386007353171784095072175673343062339173975526279362680161974682108208645413677644629654572794703

def generate_random_prime(min_val: int = 50, max_val: int = 100) -> int:
    """Generate a random prime number in given range"""    
    while True:
        candidate = random.randint(min_val, max_val)
        if is_prime(candidate):
            return candidate

def is_prime(n: int) -> bool:
    """Check if a number is prime"""
    if n < 2:
        return False
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return False
    return True

@dataclass
class PaillierKeyPair:
    """Paillier key pair container"""
    public_key: Tuple[int, int]  # (g, n)
    private_key: Tuple[int, int, int, int]  # (p, q, lambda, mu)

@dataclass
class SigmaCommitment:
    """Sigma protocol commitment"""
    a: int  # g^r mod p
    r: int  # random value used in commitment
    
@dataclass
class SigmaProof:
    """Sigma protocol proof"""
    z: int  # response z = r + c*w
    
@dataclass
class SigmaChallenge:
    """Sigma protocol challenge"""
    c: int  # random challenge

class PaillierContext:
    """Paillier cryptosystem context"""   
    def __init__(self):
        """Generate prime numbers and initialize context"""
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
        
    def get_key_pair(self) -> PaillierKeyPair:
        """Return complete key pair"""
        public_key = (self.g, self.n)
        private_key = (self.p, self.q, self.lmbda, self.mu)
        return PaillierKeyPair(public_key, private_key)
    
    def decrypt(self, c: int) -> int:
        """Decrypt ciphertext c"""
        cl = pow(c, self.lmbda, self.n * self.n)
        l = int(cl - 1) / int(self.n)
        p = int((l * self.mu) % self.n)
        
        # Handle negative values (convert from modular arithmetic)
        if p > self.n // 2:
            p = p - self.n
            
        return p

class SigmaProtocol:
    """Sigma (Schnorr) protocol implementation for ZKP"""
    
    def __init__(self, generator: int = DEFAULT_GROUP_GENERATOR, prime: int = SCHNORR_PRIME):
        self.g = generator
        self.p = prime
        
    def create_commitment(self, secret: int) -> Tuple[SigmaCommitment, int]:
        """Create commitment for a secret, returns commitment and encrypted secret"""
        r = random.randrange(self.p)
        a = pow(self.g, r, self.p)
        k = pow(self.g, secret, self.p)  # encrypted secret
        return SigmaCommitment(a, r), k
    
    def generate_challenge(self) -> SigmaChallenge:
        """Generate random challenge"""
        c = random.randrange(self.p)
        return SigmaChallenge(c)
    
    def create_proof(self, commitment: SigmaCommitment, challenge: SigmaChallenge, secret: int) -> SigmaProof:
        """Create proof response"""
        z = commitment.r + challenge.c * secret
        return SigmaProof(z)
    
    def verify_proof(self, commitment: SigmaCommitment, challenge: SigmaChallenge, 
                    proof: SigmaProof, encrypted_secret: int) -> bool:
        """Verify the proof"""
        left_side = pow(self.g, proof.z, self.p)
        right_side = (commitment.a * pow(encrypted_secret, challenge.c, self.p)) % self.p
        return left_side == right_side

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

def decrypt_with_private_key(ciphertext: int, private_key: Tuple[int, int, int, int], n: int) -> int:
    """Decrypt using private key components"""
    p, q, lmbda, mu = private_key
    cl = pow(ciphertext, lmbda, n * n)
    l = int(cl - 1) / int(n)
    result = int((l * mu) % n)
    
    # Handle negative values
    if result > n // 2:
        result = result - n
        
    return result