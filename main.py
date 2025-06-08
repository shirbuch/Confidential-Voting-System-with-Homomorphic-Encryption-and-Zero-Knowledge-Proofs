# main.py
import subprocess
import time
import threading
from simulator import Simulator

def run_server():
    subprocess.run(["python", "server.py"])

def run_simulator():
    time.sleep(2)
    sim = Simulator()
    sim.start()

def main():
    print("Launching Secure Voting System...")

    server_thread = threading.Thread(target=run_server)
    simulator_thread = threading.Thread(target=run_simulator)

    server_thread.daemon = True
    simulator_thread.daemon = True

    server_thread.start()
    simulator_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] System interrupted by user. Exiting...")

if __name__ == "__main__":
    main()
