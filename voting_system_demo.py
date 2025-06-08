#!/usr/bin/env python3
"""
Secure Voting System Demo

This module demonstrates a complete secure voting system with:
- Homomorphic encryption for vote privacy
- Zero-knowledge proofs for vote integrity verification
- Proper separation of concerns between simulator, client, and server

Usage:
    python voting_system_demo.py
"""

from secure_voting_system import (
    VoteValue, test_normal_flow, test_fraud_detection,
    run_voting_simulation
)

def demo_custom_election():
    """Demo with custom election scenario"""
    print("\n" + "=" * 60)
    print("CUSTOM ELECTION DEMO")
    print("=" * 60)
    print("Scenario: Company board voting on a proposal")
    print("5 board members voting YES/NO on budget increase")
    
    votes = [
        ("BoardMember_001", VoteValue.YES),
        ("BoardMember_002", VoteValue.YES),
        ("BoardMember_003", VoteValue.NO),
        ("BoardMember_004", VoteValue.YES),
        ("BoardMember_005", VoteValue.NO)
    ]
    
    print(f"\nVotes cast:")
    for voter_id, vote in votes:
        print(f"  {voter_id}: {vote.name}")
    
    results = run_voting_simulation(votes)
    return results

def demo_large_election():
    """Demo with larger number of voters"""
    print("\n" + "=" * 60)
    print("LARGE ELECTION DEMO")
    print("=" * 60)
    print("Scenario: Community referendum with 20 voters")
    
    import random
    
    # Generate 20 random votes
    votes = []
    for i in range(20):
        voter_id = f"Voter_{i+1:03d}"
        vote = random.choice([VoteValue.YES, VoteValue.NO])
        votes.append((voter_id, vote))
    
    yes_count = sum(1 for _, vote in votes if vote == VoteValue.YES)
    no_count = len(votes) - yes_count
    
    print(f"\nExpected tally: {yes_count} YES, {no_count} NO")
    print(f"Expected result: {yes_count - no_count} (positive = YES majority)")
    
    results = run_voting_simulation(votes)
    return results

def main():
    """Main demo runner"""
    print("SECURE VOTING SYSTEM DEMONSTRATION")
    print("=" * 60)
    print("\nThis demo showcases:")
    print("• Homomorphic encryption for vote privacy")
    print("• Zero-knowledge proofs for integrity verification")
    print("• Fraud detection capabilities")
    print("• Clean separation of simulator, client, and server roles")
    
    try:
        # Run standard tests
        test_normal_flow()
        test_fraud_detection()
        
        # Run custom demos
        demo_custom_election()
        demo_large_election()
        
        print("\n" + "=" * 60)
        print("ALL DEMONSTRATIONS COMPLETED SUCCESSFULLY")
        print("=" * 60)
        print("\nKey Security Features Demonstrated:")
        print("✓ Vote privacy through homomorphic encryption")
        print("✓ Vote integrity through zero-knowledge proofs")
        print("✓ Fraud detection and prevention")
        print("✓ Secure aggregation without revealing individual votes")
        print("✓ Cryptographically verifiable results")
        
    except Exception as e:
        print(f"\nERROR: {e}")
        print("Demo failed - check system configuration")
        return False
    
    return True

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)