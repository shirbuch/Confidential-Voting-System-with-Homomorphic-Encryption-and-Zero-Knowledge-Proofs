#!/usr/bin/env python3
"""
Voting Client - Homomorphic Version
Each client generates own keys, votes using shared public key
Usage: python client.py [yes|no]
"""

import socket
import json
import sys
from typing import Tuple

from crypto_wrapper import *

class VotingClient:
    def __init__(self, server_host='localhost', server_port=8888):
        self.server_host = server_host
        self.server_port = server_port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        self.client_id = None
        self.context = PaillierContext()  # Generate own keys
        self.shared_public_key = None
        self.is_first_client = False
        
        print(f"Client: Generated key pair with primes p={self.context.p}, q={self.context.q}")
    
    def connect(self):
        """Connect to server and handle registration"""
        try:
            self.socket.connect((self.server_host, self.server_port))
            
            # Receive client ID
            data = self.socket.recv(4096).decode().strip()
            msg = json.loads(data)
            self.client_id = msg['client_id']
            print(f"Client: Assigned ID {self.client_id}")
            
            # Check if first client
            try:
                # Try to receive another message within short timeout
                self.socket.settimeout(1.0)
                data = self.socket.recv(4096).decode().strip()
                if data:
                    # Received shared public key - not first client
                    msg = json.loads(data)
                    if msg['type'] == 'shared_public_key':
                        self.shared_public_key = msg['public_key']
                        print(f"Client {self.client_id}: Received shared public key")
                else:
                    # No immediate response - might be first client
                    self.is_first_client = True
            except socket.timeout:
                # Timeout - likely first client
                self.is_first_client = True
            
            self.socket.settimeout(None)  # Remove timeout
            
            # If first client, send public key
            if self.is_first_client:
                public_key = self.context.get_public_key()
                msg = {'type': 'public_key', 'public_key': public_key}
                self.socket.send((json.dumps(msg) + '\n').encode())
                print(f"Client {self.client_id}: Sent public key as first client")
                
                # Wait for confirmation
                data = self.socket.recv(4096).decode().strip()
                msg = json.loads(data)
                if msg['type'] == 'first_client_confirmed':
                    print(f"Client {self.client_id}: Confirmed as first client")
                    self.shared_public_key = public_key
            
            return True
            
        except Exception as e:
            print(f"Client: Connection error: {e}")
            return False
    
    def cast_vote(self, vote: str):
        """Cast vote (YES=1, NO=-1)"""
        vote_value = 1 if vote.lower() == 'yes' else -1
        
        if not self.shared_public_key:
            print(f"Client {self.client_id}: No shared public key available")
            return False
        
        # Encrypt vote
        encrypted_vote, r = encrypt_vote(vote_value, self.shared_public_key)
        self.last_vote_info = {
            'm': vote_value,
            'r': r
        }
        print(f"Client {self.client_id}: Vote '{vote}' (value={vote_value}) -> encrypted as {encrypted_vote}")
        
        # Send vote to server
        msg = {'type': 'vote', 'encrypted_vote': encrypted_vote}
        self.socket.send((json.dumps(msg) + '\n').encode())
        
        # Wait for confirmation
        data = self.socket.recv(4096).decode().strip()
        msg = json.loads(data)
        if msg['type'] == 'vote_received':
            print(f"Client {self.client_id}: Vote confirmed by server")
            return True
        
        return False
    
    def get_results(self):
        """Request and decrypt final results (first client only)"""
        if not self.is_first_client:
            print(f"Client {self.client_id}: Only first client can decrypt results")
            return
        
        # Request encrypted sum
        msg = {'type': 'get_results'}
        self.socket.send((json.dumps(msg) + '\n').encode())
        
        # Receive encrypted sum
        data = self.socket.recv(4096).decode().strip()
        msg = json.loads(data)
        encrypted_sum = msg['encrypted_sum']
        
        # Decrypt results
        result_value = self.context.decrypt(encrypted_sum)
        
        if result_value > 0:
            result = "YES"
        elif result_value < 0:
            result = "NO"
        else:
            result = "TIE"
        
        print(f"\nClient {self.client_id}: FINAL RESULTS")
        print(f"Client {self.client_id}: Decrypted sum = {result_value}")
        print(f"Client {self.client_id}: Winner = {result}")
    
    def close(self):
        """Close connection"""
        self.socket.close()

def main():
    if len(sys.argv) != 2 or sys.argv[1].lower() not in ['yes', 'no']:
        print("Usage: python client.py [yes|no]")
        sys.exit(1)
    
    vote = sys.argv[1]
    
    client = VotingClient()
    
    if client.connect():
        print(f"Client: Connected successfully")
        
        # Cast vote
        client.cast_vote(vote)
        
        # If first client, wait for user input to get results
        if client.is_first_client:
            input("Press Enter to get results (after all clients have voted)...")
            client.get_results()
        
        client.close()
    else:
        print("Client: Failed to connect")

if __name__ == "__main__":
    main()