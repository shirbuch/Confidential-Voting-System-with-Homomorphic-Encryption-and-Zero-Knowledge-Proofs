#!/usr/bin/env python3
"""
Comprehensive test suite for the secure voting system.

This module contains unit tests, integration tests, and security tests
to ensure the voting system works correctly and securely.
"""

import unittest
import random
from typing import List, Dict

from secure_voting_system import (
    Simulator, Client, Server, VoteValue, Vote,
    run_voting_simulation
)
from crypto_wrapper_enhanced import (
    PaillierContext, SigmaProtocol, is_prime, generate_random_prime,
    encrypt_vote, calculate_encrypted_sum, decrypt_with_private_key
)
from voting_config import VotingSystemConfig

class TestCryptoPrimitives(unittest.TestCase):
    """Test cryptographic primitives"""
    
    def setUp(self):
        self.paillier = PaillierContext()
        self.sigma = SigmaProtocol()
        
    def test_prime_generation(self):
        """Test prime number generation"""
        prime = generate_random_prime(50, 100)
        self.assertTrue(is_prime(prime))
        self.assertGreaterEqual(prime, 50)
        self.assertLessEqual(prime, 100)
        
    def test_paillier_encryption_decryption(self):
        """Test Paillier encryption and decryption"""
        key_pair = self.paillier.get_key_pair()
        
        test_values = [0, 1, -1, 5, -5, 100, -100]
        
        for value in test_values:
            encrypted, _ = encrypt_vote(value, key_pair.public_key)
            decrypted = decrypt_with_private_key(
                encrypted, key_pair.private_key, key_pair.public_key[1]
            )
            self.assertEqual(value, decrypted, f"Failed for value {value}")
            
    def test_homomorphic_addition(self):
        """Test homomorphic addition property"""
        key_pair = self.paillier.get_key_pair()
        
        values = [1, -1, 1, 1, -1]  # Expected sum: 1
        encrypted_values = []
        
        for value in values:
            encrypted, _ = encrypt_vote(value, key_pair.public_key)
            encrypted_values.append(encrypted)
            
        encrypted_sum = calculate_encrypted_sum(encrypted_values, key_pair.public_key)
        decrypted_sum = decrypt_with_private_key(
            encrypted_sum, key_pair.private_key, key_pair.public_key[1]
        )
        
        expected_sum = sum(values)
        self.assertEqual(expected_sum, decrypted_sum)
        
    def test_sigma_protocol_valid_proof(self):
        """Test valid Sigma protocol proof"""
        secret = 42
        commitment, encrypted_secret = self.sigma.create_commitment(secret)
        challenge = self.sigma.generate_challenge()
        proof = self.sigma.create_proof(commitment, challenge, secret)
        
        is_valid = self.sigma.verify_proof(
            commitment, challenge, proof, encrypted_secret
        )
        self.assertTrue(is_valid)
        
    def test_sigma_protocol_invalid_proof(self):
        """Test invalid Sigma protocol proof"""
        secret = 42
        wrong_secret = 24
        
        commitment, encrypted_secret = self.sigma.create_commitment(secret)
        challenge = self.sigma.generate_challenge()
        proof = self.sigma.create_proof(commitment, challenge, wrong_secret)
        
        is_valid = self.sigma.verify_proof(
            commitment, challenge, proof, encrypted_secret
        )
        self.assertFalse(is_valid)

class TestVotingComponents(unittest.TestCase):
    """Test individual voting system components"""
    
    def setUp(self):
        self.votes = [
            ("Alice", VoteValue.YES),
            ("Bob", VoteValue.NO),
            ("Charlie", VoteValue.YES)
        ]
        self.simulator = Simulator(self.votes)
        self.client = Client()
        self.server = Server()
        
    def test_simulator_initialization(self):
        """Test simulator initialization"""
        votes = self.simulator.get_votes()
        self.assertEqual(len(votes), 3)
        self.assertEqual(votes[0].voter_id, "Alice")
        self.assertEqual(votes[0].vote, VoteValue.YES)
        
    def test_simulator_fraud_initialization(self):
        """Test simulator initialization with fraudulent voters"""
        simulator = Simulator(self.votes, fraudulent_voters=["Bob"])
        self.assertIn("Bob", simulator.fraudulent_voters)
        self.assertNotIn("Alice", simulator.fraudulent_voters)
        
    def test_client_key_generation(self):
        """Test client key pair generation"""
        public_key = self.client.get_public_key()
        self.assertIsInstance(public_key, tuple)
        self.assertEqual(len(public_key), 2)
        self.assertGreater(public_key[0], 0)  # g
        self.assertGreater(public_key[1], 0)  # n
        
    def test_vote_processing(self):
        """Test vote processing by client"""
        votes = self.simulator.get_votes()
        encrypted_votes = self.client.process_votes(votes, self.simulator)
        
        self.assertEqual(len(encrypted_votes), len(votes))
        for encrypted_vote in encrypted_votes:
            self.assertIsInstance(encrypted_vote.encrypted_vote, int)
            self.assertIsNotNone(encrypted_vote.commitment)
            
    def test_server_vote_storage(self):
        """Test server vote storage"""
        votes = self.simulator.get_votes()
        encrypted_votes = self.client.process_votes(votes, self.simulator)
        
        self.server.receive_public_key(self.client.get_public_key())
        self.server.receive_encrypted_votes(encrypted_votes)
        
        self.assertEqual(len(self.server.vote_storage), len(votes))
        
    def test_tally_computation(self):
        """Test encrypted tally computation"""
        votes = self.simulator.get_votes()
        encrypted_votes = self.client.process_votes(votes, self.simulator)
        
        self.server.receive_public_key(self.client.get_public_key())
        self.server.receive_encrypted_votes(encrypted_votes)
        
        encrypted_tally = self.server.compute_tally()
        decrypted_tally = self.client.decrypt_result(encrypted_tally)
        
        expected_tally = sum(vote.vote.value for vote in votes)
        self.assertEqual(decrypted_tally, expected_tally)

class TestIntegrationScenarios(unittest.TestCase):
    """Test complete voting scenarios"""
    
    def test_small_election_all_yes(self):
        """Test small election with all YES votes"""
        votes = [("Voter1", VoteValue.YES), ("Voter2", VoteValue.YES)]
        results = run_voting_simulation(votes)
        self.assertTrue(all(results.values()))
        
    def test_small_election_all_no(self):
        """Test small election with all NO votes"""
        votes = [("Voter1", VoteValue.NO), ("Voter2", VoteValue.NO)]
        results = run_voting_simulation(votes)
        self.assertTrue(all(results.values()))
        
    def test_mixed_election(self):
        """Test election with mixed votes"""
        votes = [
            ("Voter1", VoteValue.YES),
            ("Voter2", VoteValue.NO),
            ("Voter3", VoteValue.YES),
            ("Voter4", VoteValue.NO),
            ("Voter5", VoteValue.YES)
        ]
        results = run_voting_simulation(votes)
        self.assertTrue(all(results.values()))
        
    def test_single_voter_election(self):
        """Test election with single voter"""
        votes = [("OnlyVoter", VoteValue.YES)]
        results = run_voting_simulation(votes)
        self.assertTrue(all(results.values()))
        
    def test_large_random_election(self):
        """Test election with many random votes"""
        votes = []
        for i in range(50):
            voter_id = f"Voter_{i:03d}"
            vote = random.choice([VoteValue.YES, VoteValue.NO])
            votes.append((voter_id, vote))
            
        results = run_voting_simulation(votes)
        self.assertTrue(all(results.values()))

class TestSecurityScenarios(unittest.TestCase):
    """Test security-related scenarios"""
    
    def test_fraud_detection_single_voter(self):
        """Test fraud detection for single fraudulent voter"""
        votes = [
            ("Honest1", VoteValue.YES),
            ("Fraudster", VoteValue.NO),
            ("Honest2", VoteValue.YES)
        ]
        
        results = run_voting_simulation(votes, fraudulent_voters=["Fraudster"])
        
        # Fraudster should be detected
        self.assertFalse(results["Fraudster"])
        # Honest voters should pass
        self.assertTrue(results["Honest1"])
        self.assertTrue(results["Honest2"])
        
    def test_fraud_detection_multiple_voters(self):
        """Test fraud detection for multiple fraudulent voters"""
        votes = [
            ("Honest1", VoteValue.YES),
            ("Fraudster1", VoteValue.NO),
            ("Honest2", VoteValue.YES),
            ("Fraudster2", VoteValue.NO),
            ("Honest3", VoteValue.YES)
        ]
        
        results = run_voting_simulation(votes, fraudulent_voters=["Fraudster1", "Fraudster2"])
        
        # Fraudsters should be detected
        self.assertFalse(results["Fraudster1"])
        self.assertFalse(results["Fraudster2"])
        # Honest voters should pass
        self.assertTrue(results["Honest1"])
        self.assertTrue(results["Honest2"])
        self.assertTrue(results["Honest3"])
        
    def test_fraud_detection_scenarios(self):
        """Test fraud detection across different voter scenarios"""
        votes = [("V1", VoteValue.YES), ("V2", VoteValue.NO), ("V3", VoteValue.YES)]
        
        # Test fraud detection for each voter individually
        for fraud_id in ["V1", "V2", "V3"]:
            results = run_voting_simulation(votes, fraudulent_voters=[fraud_id])
            self.assertFalse(results[fraud_id], f"Failed to detect fraud for {fraud_id}")
            
            # Other voters should still be valid
            for voter_id in results:
                if voter_id != fraud_id:
                    self.assertTrue(results[voter_id], f"False positive for {voter_id}")
                    
    def test_vote_privacy_preservation(self):
        """Test that individual votes remain private"""
        # This test ensures encrypted votes don't reveal plaintext
        simulator = Simulator([("Alice", VoteValue.YES), ("Bob", VoteValue.NO)])
        client = Client()
        server = Server()
        
        votes = simulator.get_votes()
        encrypted_votes = client.process_votes(votes, simulator)
        
        # Encrypted votes should be different from plaintext
        for encrypted_vote in encrypted_votes:
            original_vote = next(v for v in votes if v.voter_id == encrypted_vote.voter_id)
            self.assertNotEqual(encrypted_vote.encrypted_vote, original_vote.vote.value)
            self.assertNotEqual(encrypted_vote.encrypted_vote, abs(original_vote.vote.value))
            
    def test_honest_vs_fraudulent_proof_generation(self):
        """Test that honest and fraudulent proofs are generated differently"""
        votes = [("Honest", VoteValue.YES), ("Fraudster", VoteValue.NO)]
        
        # Create two simulators - one honest, one with fraud
        honest_simulator = Simulator(votes)
        fraud_simulator = Simulator(votes, fraudulent_voters=["Fraudster"])
        
        # Both should have the same voter contexts after processing
        client = Client()
        client.process_votes(honest_simulator.get_votes(), honest_simulator)
        client.process_votes(fraud_simulator.get_votes(), fraud_simulator)
        
        # Generate proofs for the same challenge
        from crypto_wrapper_enhanced import SigmaProtocol
        sigma = SigmaProtocol()
        challenge = sigma.generate_challenge()
        
        honest_proof = honest_simulator.provide_proof("Fraudster", challenge)
        fraud_proof = fraud_simulator.provide_proof("Fraudster", challenge)
        
        # Proofs should be different (fraudulent one should fail verification)
        if not honest_proof or not fraud_proof:
            self.fail("Proof generation failed for one of the simulators")
        self.assertNotEqual(honest_proof.z, fraud_proof.z)

class TestConfiguration(unittest.TestCase):
    """Test configuration management"""
    
    def test_default_config_validation(self):
        """Test default configuration is valid"""
        config = VotingSystemConfig()
        self.assertTrue(config.validate())
        
    def test_config_serialization(self):
        """Test configuration serialization and deserialization"""
        config1 = VotingSystemConfig()
        config1.system.MAX_VOTERS = 500
        config1.crypto.PRIME_MIN_VAL = 75
        
        config_dict = config1.to_dict()
        config2 = VotingSystemConfig.from_dict(config_dict)
        
        self.assertEqual(config1.system.MAX_VOTERS, config2.system.MAX_VOTERS)
        self.assertEqual(config1.crypto.PRIME_MIN_VAL, config2.crypto.PRIME_MIN_VAL)
        
    def test_invalid_config_detection(self):
        """Test detection of invalid configurations"""
        config = VotingSystemConfig()
        
        # Test invalid prime range
        config.crypto.PRIME_MIN_VAL = 100
        config.crypto.PRIME_MAX_VAL = 50  # Max < Min
        self.assertFalse(config.validate())
        
        # Reset and test invalid voter count
        config = VotingSystemConfig()
        config.system.MAX_VOTERS = -1
        self.assertFalse(config.validate())

class TestErrorHandling(unittest.TestCase):
    """Test error handling and edge cases"""
    
    def test_empty_vote_list(self):
        """Test handling of empty vote list"""
        # Empty vote list should be handled gracefully
        votes = []
        # This should not crash the system
        try:
            simulator = Simulator(votes)
            results = simulator.get_votes()
            self.assertEqual(len(results), 0)
        except Exception as e:
            self.fail(f"Empty vote list caused exception: {e}")
            
    def test_duplicate_voter_ids(self):
        """Test handling of duplicate voter IDs"""
        votes = [
            ("Alice", VoteValue.YES),
            ("Alice", VoteValue.NO)  # Duplicate ID
        ]
        
        # System should handle duplicates (last vote wins or error)
        try:
            results = run_voting_simulation(votes)
            # If no exception, the system handled it gracefully
            self.assertIsInstance(results, dict)
        except Exception:
            # If exception occurs, it should be a controlled error
            pass
            
    def test_fraudulent_voter_not_in_votes(self):
        """Test specifying fraudulent voter that doesn't exist"""
        votes = [("Alice", VoteValue.YES), ("Bob", VoteValue.NO)]
        
        # This should not crash, but the fraudulent voter simply won't be tested
        try:
            results = run_voting_simulation(votes, fraudulent_voters=["Charlie"])
            # Should still get results for existing voters
            self.assertIn("Alice", results)
            self.assertIn("Bob", results)
            self.assertNotIn("Charlie", results)
        except Exception as e:
            self.fail(f"Non-existent fraudulent voter caused exception: {e}")

def run_all_tests():
    """Run all test suites"""
    test_suites = [
        TestCryptoPrimitives,
        TestVotingComponents,
        TestIntegrationScenarios,
        TestSecurityScenarios,
        TestConfiguration,
        TestErrorHandling
    ]
    
    all_tests = unittest.TestSuite()
    
    for test_class in test_suites:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        all_tests.addTests(tests)
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(all_tests)
    
    return result.wasSuccessful()

if __name__ == "__main__":
    print("Running Comprehensive Test Suite for Secure Voting System")
    print("=" * 60)
    
    success = run_all_tests()
    
    print("\n" + "=" * 60)
    if success:
        print("✅ ALL TESTS PASSED - System is ready for demonstration")
    else:
        print("❌ SOME TESTS FAILED - Please review the issues above")
    print("=" * 60)
    
    exit(0 if success else 1)