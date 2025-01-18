# Scapy for packet sniffing
#! scapy

# Pandas for data manipulation
#! pandas


# Script to install all dependencies listed in requirements.txt

import subprocess
import sys

requirements_file = "requirements.txt"

with open(requirements_file, "r") as file:
    dependencies = [line.strip() for line in file if line.strip() and not line.startswith("#")]

for dependency in dependencies:
    print(f"Installing {dependency}...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", dependency])

print("All dependencies installed successfully!")