#!/usr/bin/env python3
"""
Voting Server - Homomorphic Version
Handles client registration, public key sharing, and vote aggregation
"""

import socket
import json
import threading
import random
from typing import Dict, List, Optional

class VotingServer:
    def __init__(self, host='localhost', port=8888):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Server state
        self.clients = {}  # client_id -> connection
        self.encrypted_votes = []
        self.shared_public_key = None
        self.first_client_id = None
        self.used_ids = set()
        self.voting_active = True
        
    def generate_client_id(self) -> str:
        """Generate random client ID"""
        """so the number of voters will not be traceable to the client"""
        while True:
            client_id = f"C{random.randint(1000, 9999)}"
            if client_id not in self.used_ids:
                self.used_ids.add(client_id)
                return client_id
    
    def handle_client(self, conn, addr):
        """Handle individual client connection"""
        # Assign client ID
        client_id = self.generate_client_id()
    
        try:            
            # Send client ID
            response = {'type': 'client_id', 'client_id': client_id}
            conn.send((json.dumps(response) + '\n').encode())
            
            # Store client connection
            self.clients[client_id] = conn
            print(f"Server: Connected client {client_id} from {addr}")
            
            # Handle first client registration
            if self.first_client_id is None:
                self.first_client_id = client_id
                print(f"Server: {client_id} is the first client")
                
                # Wait for first client's public key
                data = conn.recv(4096).decode().strip()
                if data:
                    msg = json.loads(data)
                    if msg['type'] == 'public_key':
                        self.shared_public_key = msg['public_key']
                        print(f"Server: Received public key from {client_id}: {self.shared_public_key}")
                        
                        # Send confirmation to first client
                        response = {'type': 'first_client_confirmed'}
                        conn.send((json.dumps(response) + '\n').encode())
            else:
                # Send shared public key to other clients
                if self.shared_public_key:
                    response = {'type': 'shared_public_key', 'public_key': self.shared_public_key}
                    conn.send((json.dumps(response) + '\n').encode())
                    print(f"Server: Sent shared public key to {client_id}")
            
            # Handle voting
            while self.voting_active:
                data = conn.recv(4096).decode().strip()
                if not data:
                    break
                    
                msg = json.loads(data)
                
                if msg['type'] == 'vote':
                    encrypted_vote = msg['encrypted_vote']
                    self.encrypted_votes.append(encrypted_vote)
                    print(f"Server: Received vote from {client_id}: {encrypted_vote}")
                    
                    # Send confirmation
                    response = {'type': 'vote_received'}
                    conn.send((json.dumps(response) + '\n').encode())
                
                elif msg['type'] == 'get_results':
                    # Calculate encrypted sum
                    encrypted_sum = self.calculate_encrypted_sum()
                    response = {'type': 'encrypted_sum', 'encrypted_sum': encrypted_sum}
                    conn.send((json.dumps(response) + '\n').encode())
                    print(f"Server: Sent encrypted sum to {client_id} for decryption")
                    
        except Exception as e:
            print(f"Server: Error handling client {client_id}: {e}")
        finally:
            conn.close()
            if client_id in self.clients:
                del self.clients[client_id]
    
    def calculate_encrypted_sum(self) -> int:
        """Calculate homomorphic sum of all encrypted votes"""
        if not self.encrypted_votes:
            return 0
        
        if not self.shared_public_key:
            return 0
            
        g, n = self.shared_public_key
        
        # Homomorphic addition = multiplication of ciphertexts
        encrypted_sum = self.encrypted_votes[0]
        for i in range(1, len(self.encrypted_votes)):
            encrypted_sum = (encrypted_sum * self.encrypted_votes[i]) % (n * n)
        
        print(f"Server: Calculated encrypted sum from {len(self.encrypted_votes)} votes: {encrypted_sum}")
        return encrypted_sum
    
    def start(self):
        """Start the server"""
        self.socket.bind((self.host, self.port))
        self.socket.listen(10)
        print(f"Server: Listening on {self.host}:{self.port}")
        print("Server: Waiting for clients...")
        
        try:
            while True:
                conn, addr = self.socket.accept()
                client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                client_thread.daemon = True
                client_thread.start()
        except KeyboardInterrupt:
            print("\nServer: Shutting down...")
        finally:
            self.socket.close()

if __name__ == "__main__":
    server = VotingServer()
    server.start()