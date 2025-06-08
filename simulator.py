# simulator.py
from client import Client
import time

class Simulator:
    def __init__(self, host='localhost', port=8888):
        self.client = Client(host=host, port=port)
        self.voters = [
            {'id': 'voter1', 'vote': 'yes'},
            {'id': 'voter2', 'vote': 'no'},
            {'id': 'voter3', 'vote': 'yes'}
        ]

    def start(self):
        self.client.connect()
        for i, voter in enumerate(self.voters):
            self.client.cast_vote(voter['vote'])
            if i == 0:
                self.client.get_results()
            time.sleep(1)
            self.client.handle_zkp_challenge()
