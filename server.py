#!/usr/bin/env python3
"""
Voting Server - Homomorphic Version
Handles client registration, public key sharing, and vote aggregation
"""

import socket
import json
import threading
import random
import time
from typing import Dict, List, Optional

from crypto_wrapper import calculate_encrypted_sum

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
        self.server_running = True
        self.results_requested = False
        self.finished_zkp_validations = False
        self.active_challenges = {}
        
        # Thread-safe shutdown event
        self.shutdown_event = threading.Event()
        
    def shutdown(self):
        """Gracefully shutdown the server"""
        print("\nServer: Initiating shutdown...")
        self.server_running = False
        self.voting_active = False
        self.shutdown_event.set()
        
        # Close all client connections
        for client_id, conn in list(self.clients.items()):
            try:
                conn.close()
            except:
                pass
        self.clients.clear()
        
        # Close server socket
        try:
            self.socket.close()
        except:
            pass
            
        print("Server: Shutdown complete")
        
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
        client_id = None
        
        try:
            # Assign client ID
            client_id = self.generate_client_id()
            
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
            while not self.shutdown_event.is_set() and self.voting_active or not self.finished_zkp_validations:
                try:
                    conn.settimeout(0.5)  # Short timeout to check shutdown frequently
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
                    
                    if not self.shared_public_key:
                        return 0
                    
                    elif msg['type'] == 'get_results':
                        # Calculate encrypted sum
                        encrypted_sum = calculate_encrypted_sum(self.encrypted_votes, self.shared_public_key)
                        print(f"Server: Calculated encrypted sum from {len(self.encrypted_votes)} votes: {encrypted_sum}")
                        response = {'type': 'encrypted_sum', 'encrypted_sum': encrypted_sum}
                        conn.send((json.dumps(response) + '\n').encode())
                        print(f"Server: Sent encrypted sum to {client_id} for decryption")
                        
                        # Mark that results were requested - voting round complete
                        self.results_requested = True
                        self.voting_active = False
                        print("Server: Results requested - voting round complete")

                        # Challenge the clients for ZKP after vote
                        time.sleep(0.5)  # give client a moment to be ready to receive ZKP
                        self.challenge_clients_for_zkp()

                    elif msg['type'] == 'zkp_response':
                        u = msg['u']
                        v = msg['v']
                        w = msg['w']
                        challenge, c = self.active_challenges.pop(client_id, (None, None))
                        if challenge is None or c is None:
                            print(f"Server: No active ZKP challenge for {client_id}")
                            return

                        g, N = self.shared_public_key
                        N2 = N * N
                        lhs = (pow(g, v, N2) * pow(w, N, N2) * pow(c, challenge, N2)) % N2

                        if lhs == u:
                            print(f"Server: ZKP verification PASSED for client {client_id}")
                        else:
                            print(f"Server: ZKP verification FAILED for client {client_id}")
                            self.finished_zkp_validations = True
                            print("Server: Verifying session FAILED. Press Ctrl+C to exit.")
                            return

                        if not self.active_challenges:
                            print("Server: All ZKP validations complete")
                            self.finished_zkp_validations = True
                            print("Server: Voting and verifying session ended. Press Ctrl+C to exit.")
                            break
                        break
                        
                except socket.timeout:
                    # Check if we should continue
                    continue
                except Exception as e:
                    if not self.shutdown_event.is_set():
                        print(f"Server: Error in client loop for {client_id}: {e}")
                    break
                    
        except Exception as e:
            if not self.shutdown_event.is_set():
                print(f"Server: Error handling client {client_id}: {e}")
        finally:
            try:
                conn.close()
            except:
                pass
            if client_id and client_id in self.clients:
                del self.clients[client_id]
                print(f"Server: Client {client_id} disconnected")

    def challenge_client_for_zkp(self, client_id: str, conn: socket.socket):
        if not self.shared_public_key:
            print("Server: No shared public key available for ZKP challenge")
            return
        
        challenge = random.randint(1, self.shared_public_key[1] - 1)
        zkp_request = {
            'type': 'zkp_challenge',
            'challenge': challenge
        }
        conn.send((json.dumps(zkp_request) + '\n').encode())
        self.active_challenges[client_id] = (challenge, self.encrypted_votes[-1])

    def challenge_clients_for_zkp(self):
        """Challenge all clients for zero-knowledge proofs"""
        if not self.shared_public_key:
            print("Server: No shared public key available for ZKP challenge")
            return
        if not self.encrypted_votes:
            print("Server: No votes available for ZKP challenge")
            return
        print("Server: Challenging clients for zero-knowledge proofs")
        for client_id, conn in self.clients.items():
            self.challenge_client_for_zkp(client_id, conn)
            print(f"Server: Challenged client {client_id} for ZKP")

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
    
    def monitor_input(self):
        """Monitor for user input to shutdown server"""
        print("Server: to stop the server, press Ctrl+C")
        try:
            while not self.shutdown_event.is_set():
                # If voting is complete, auto-shutdown
                if self.finished_zkp_validations:
                    print("Server: Voting and verifying complete. Auto-shutting down.")
                    self.shutdown()
                    break           
        except KeyboardInterrupt:
            print("\nServer: Keyboard interrupt received")
            self.shutdown()
    
    def start(self):
        """Start the server"""
        try:
            self.socket.bind((self.host, self.port))
            self.socket.listen(10)
            print(f"Server: Listening on {self.host}:{self.port}")
            
            # Start input monitoring thread
            input_thread = threading.Thread(target=self.monitor_input)
            input_thread.daemon = True
            input_thread.start()
            
            print("Server: Waiting for clients...")
            
            while not self.shutdown_event.is_set():
                try:
                    # Use select to make accept non-blocking
                    import select
                    ready, _, _ = select.select([self.socket], [], [], 1.0)
                    
                    if ready and not self.shutdown_event.is_set():
                        conn, addr = self.socket.accept()
                        
                        if self.shutdown_event.is_set():
                            conn.close()
                            break
                            
                        # If results were already requested, don't accept new clients
                        if self.results_requested:
                            print("Server: Voting round complete, rejecting new client")
                            try:
                                reject_msg = {'type': 'error', 'message': 'Voting session has ended'}
                                conn.send((json.dumps(reject_msg) + '\n').encode())
                            except:
                                pass
                            conn.close()
                            continue
                            
                        client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                        client_thread.daemon = True
                        client_thread.start()
                        
                except Exception as e:
                    if not self.shutdown_event.is_set():
                        print(f"Server: Error accepting connections: {e}")
                        break
                        
        except Exception as e:
            print(f"Server: Failed to start: {e}")
        finally:
            if self.shutdown_event.is_set():
                print("Server: Shutdown event set, exiting main loop")

def main():
    """Main function with better error handling"""
    print("=" * 50)
    print("  Homomorphic Voting Server")
    print("=" * 50)
    print("Commands:")
    print("  - Type 'quit', 'exit', or 'stop' to shutdown")
    print("  - Press Ctrl+C for immediate shutdown")
    print("  - Server auto-shuts down after voting completes")
    print("=" * 50)
    
    server = VotingServer()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nServer: Keyboard interrupt received")
        server.shutdown()
    except Exception as e:
        print(f"Server: Unexpected error: {e}")
        server.shutdown()

if __name__ == "__main__":
    main()