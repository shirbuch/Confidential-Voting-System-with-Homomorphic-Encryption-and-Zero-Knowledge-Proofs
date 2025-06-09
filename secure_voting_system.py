from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from enum import Enum
import random

# Import our enhanced crypto wrapper
from crypto_wrapper_enhanced import (
    PaillierContext, SigmaProtocol, PaillierKeyPair,
    SigmaCommitment, SigmaChallenge, SigmaProof,
    encrypt_vote, calculate_encrypted_sum, decrypt_with_private_key
)

class VoteValue(Enum):
    """Vote values enumeration"""
    YES = 1
    NO = -1

@dataclass
class Vote:
    """Vote data structure"""
    voter_id: str
    vote: VoteValue

@dataclass
class EncryptedVote:
    """Encrypted vote with commitment"""
    voter_id: str
    encrypted_vote: int
    commitment: SigmaCommitment

@dataclass
class VoterContext:
    """Voter's cryptographic context for ZKP"""
    voter_id: str
    vote: VoteValue
    commitment: SigmaCommitment
    encrypted_secret: int

class Simulator:
    """Simulator that generates votes and handles ZKP requests"""
    
    def __init__(self, votes: List[Tuple[str, VoteValue]], fraudulent_voters: Optional[List[str]] = None):
        self.votes = [Vote(voter_id, vote) for voter_id, vote in votes]
        self.sigma = SigmaProtocol()
        self.voter_contexts: Dict[str, VoterContext] = {}
        # Store which voters should provide fraudulent proofs
        self.fraudulent_voters = set(fraudulent_voters or [])
        
    def get_votes(self) -> List[Vote]:
        """Return the list of votes"""
        return self.votes.copy()
    
    def store_voter_context(self, voter_id: str, vote: VoteValue, 
                          commitment: SigmaCommitment, encrypted_secret: int):
        """Store voter context for later ZKP"""
        self.voter_contexts[voter_id] = VoterContext(
            voter_id, vote, commitment, encrypted_secret
        )
    
    def provide_proof(self, voter_id: str, challenge: SigmaChallenge) -> Optional[SigmaProof]:
        """Provide ZKP proof for a specific voter - may be fraudulent based on simulator setup"""
        if voter_id not in self.voter_contexts:
            return None
            
        context = self.voter_contexts[voter_id]
        
        # Check if this voter should provide fraudulent proof
        if voter_id in self.fraudulent_voters:
            # Provide fraudulent proof using wrong secret
            wrong_secret = VoteValue.YES.value if context.vote == VoteValue.NO else VoteValue.NO.value
            return self.sigma.create_proof(
                context.commitment,
                challenge,
                wrong_secret
            )
        else:
            # Provide legitimate proof
            return self.sigma.create_proof(
                context.commitment, 
                challenge, 
                context.vote.value
            )

class Client:
    """Client (Kiosk) that handles encryption and decryption"""
    
    def __init__(self):
        self.paillier = PaillierContext()
        self.key_pair = self.paillier.get_key_pair()
        self.sigma = SigmaProtocol()
        
    def get_public_key(self) -> Tuple[int, int]:
        """Return public key for server"""
        return self.key_pair.public_key
    
    def process_votes(self, votes: List[Vote], simulator: Simulator) -> List[EncryptedVote]:
        """Process votes: encrypt and create commitments"""
        encrypted_votes = []
        
        for vote in votes:
            # Encrypt the vote
            encrypted_value, _ = encrypt_vote(vote.vote.value, self.key_pair.public_key)
            
            # Create commitment for ZKP
            commitment, encrypted_secret = self.sigma.create_commitment(vote.vote.value)
            
            # Store context in simulator for later ZKP
            simulator.store_voter_context(
                vote.voter_id, vote.vote, commitment, encrypted_secret
            )
            
            encrypted_votes.append(EncryptedVote(
                voter_id=vote.voter_id,
                encrypted_vote=encrypted_value,
                commitment=commitment
            ))
            
        return encrypted_votes
    
    def decrypt_result(self, encrypted_tally: int) -> int:
        """Decrypt the final tally"""
        return decrypt_with_private_key(
            encrypted_tally,
            self.key_pair.private_key,
            self.key_pair.public_key[1]  # n
        )

class Server:
    """Server that aggregates votes and verifies proofs"""
    
    def __init__(self):
        self.vote_storage: Dict[str, Tuple[int, SigmaCommitment]] = {}
        self.public_key: Optional[Tuple[int, int]] = None
        self.sigma = SigmaProtocol()
        self.encrypted_tally: Optional[int] = None
        self.final_result: Optional[int] = None
        
    def receive_public_key(self, public_key: Tuple[int, int]):
        """Receive public key from client"""
        self.public_key = public_key
        print(f"Server: Received public key from client")
        
    def receive_encrypted_votes(self, encrypted_votes: List[EncryptedVote]):
        """Receive and store encrypted votes"""
        for encrypted_vote in encrypted_votes:
            self.vote_storage[encrypted_vote.voter_id] = (
                encrypted_vote.encrypted_vote,
                encrypted_vote.commitment
            )
        print(f"Server: Received {len(encrypted_votes)} encrypted votes")
        
    def compute_tally(self) -> int:
        """Compute homomorphic tally"""
        if not self.public_key:
            raise RuntimeError("Public key not received")
            
        encrypted_values = [vote_data[0] for vote_data in self.vote_storage.values()]
        self.encrypted_tally = calculate_encrypted_sum(encrypted_values, self.public_key)
        print(f"Server: Computed encrypted tally")
        return self.encrypted_tally
        
    def receive_decrypted_result(self, result: int):
        """Receive final result from client"""
        self.final_result = result
        if result > 0:
            print("Server: Majority voted YES")
        elif result < 0:
            print("Server: Majority voted NO")
        else:
            print("Server: Tie vote")
            
    def verify_all_proofs(self, simulator: Simulator) -> Dict[str, bool]:
        """Verify ZKP proofs for all voters"""
        verification_results = {}
        
        print(f"Server: Starting ZKP verification for {len(self.vote_storage)} voters")
        
        for voter_id, (encrypted_vote, commitment) in self.vote_storage.items():
            # Generate challenge
            challenge = self.sigma.generate_challenge()
            
            # Request proof from simulator
            proof = simulator.provide_proof(voter_id, challenge)
            
            if proof is None:
                verification_results[voter_id] = False
                continue
                
            # Get encrypted secret from simulator's context
            encrypted_secret = simulator.voter_contexts[voter_id].encrypted_secret
            
            # Verify proof
            is_valid = self.sigma.verify_proof(commitment, challenge, proof, encrypted_secret)
            verification_results[voter_id] = is_valid
            
            status = "VALID" if is_valid else "INVALID"
            print(f"Server: Voter {voter_id} proof: {status}")
            
        return verification_results

def run_voting_simulation(votes: List[Tuple[str, VoteValue]], fraudulent_voters: Optional[List[str]] = None):
    """Run complete voting simulation"""
    print("=" * 60)
    print("SECURE VOTING SYSTEM SIMULATION")
    print("=" * 60)
    
    # Initialize components
    simulator = Simulator(votes, fraudulent_voters)
    client = Client()
    server = Server()
    
    print(f"\nPhase 1: Vote Processing")
    print("-" * 30)
    
    # Step 1: Client sends public key to server
    server.receive_public_key(client.get_public_key())
    
    # Step 2: Simulator sends votes to client
    votes_list = simulator.get_votes()
    print(f"Simulator: Generated {len(votes_list)} votes")
    
    # Step 3: Client processes votes (encrypt + commit)
    encrypted_votes = client.process_votes(votes_list, simulator)
    print(f"Client: Processed {len(encrypted_votes)} votes")
    
    # Step 4: Client sends encrypted votes to server
    server.receive_encrypted_votes(encrypted_votes)
    
    # Step 5: Server computes homomorphic tally
    encrypted_tally = server.compute_tally()
    
    # Step 6: Client decrypts result and sends back to server
    decrypted_result = client.decrypt_result(encrypted_tally)
    server.receive_decrypted_result(decrypted_result)
    
    print(f"\nPhase 2: Zero-Knowledge Proof Verification")
    print("-" * 45)
    
    # Step 7: Server verifies all proofs
    verification_results = server.verify_all_proofs(simulator)
    
    # Summary
    print(f"\nVerification Summary:")
    print("-" * 20)
    valid_proofs = sum(1 for valid in verification_results.values() if valid)
    total_proofs = len(verification_results)
    print(f"Valid proofs: {valid_proofs}/{total_proofs}")
    
    if fraudulent_voters:
        fraud_detected = any(not verification_results.get(voter_id, True) for voter_id in fraudulent_voters)
        print(f"Fraud detection: {'SUCCESS' if fraud_detected else 'FAILED'}")
    
    return verification_results

# Test cases
def test_normal_flow():
    """Test normal voting flow without fraud"""
    print("\nTEST CASE 1: Normal Flow")
    votes = [
        ("Alice", VoteValue.YES),
        ("Bob", VoteValue.NO),
        ("Charlie", VoteValue.YES),
        ("Diana", VoteValue.YES),
        ("Eve", VoteValue.NO)
    ]
    
    results = run_voting_simulation(votes)
    assert all(results.values()), "All proofs should be valid in normal flow"
    print("✓ Normal flow test passed")

def test_fraud_detection():
    """Test fraud detection"""
    print("\nTEST CASE 2: Fraud Detection")
    votes = [
        ("Alice", VoteValue.YES),
        ("Bob", VoteValue.NO),
        ("Charlie", VoteValue.YES),
        ("Diana", VoteValue.YES),
        ("Eve", VoteValue.NO)
    ]
    
    results = run_voting_simulation(votes, fraudulent_voters=["Charlie"])
    assert not results["Charlie"], "Fraudulent proof should be detected"
    assert all(valid for voter_id, valid in results.items() if voter_id != "Charlie"), \
           "Other proofs should remain valid"
    print("✓ Fraud detection test passed")

if __name__ == "__main__":
    test_normal_flow()
    test_fraud_detection()