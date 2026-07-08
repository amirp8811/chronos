import math
import sys

def shannon_entropy(data):
    if not data:
        return 0
    entropy = 0
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    for count in counts.values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy

if __name__ == "__main__":
    # Example usage: python3 entropy_check.py <binary_packet_file>
    if len(sys.argv) < 2:
        print("Usage: entropy_check.py <file>")
        sys.exit(1)
    with open(sys.argv[1], "rb") as f:
        data = f.read()
        print(f"Shannon Entropy: {shannon_entropy(data):.4f} bits/byte")
