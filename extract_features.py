import os
import math
import numpy as np
import pandas as pd

def calculate_entropy(data):
    if not data:
        return 0
    byte_counts = [0]*256
    for byte in data:
        byte_counts[byte] += 1
    entropy = 0
    for count in byte_counts:
        if count == 0:
            continue
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy / 8   # normalize between 0 and 1

def byte_histogram(data):
    """Returns normalized 256-length histogram (frequency of each byte value)."""
    hist = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    return (hist / len(data)).tolist()

def extract_features(file_path):
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        features = {
            "filename": os.path.basename(file_path),
            "entropy": calculate_entropy(data),
            "size_bytes": os.path.getsize(file_path)
        }

        histogram = byte_histogram(data)
        for i in range(256):
            features[f"byte_{i}"] = histogram[i]

        return features

    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return None

if __name__ == "__main__":
    root_dir = "."
    output = []

    for fname in os.listdir(root_dir):
        if fname.endswith((".exe", ".elf", ".txt", ".zip", ".dll")):
            fpath = os.path.join(root_dir, fname)
            print(f"Extracting: {fpath}")
            feat = extract_features(fpath)
            if feat:
                output.append(feat)

    df = pd.DataFrame(output)
    df.to_csv("features_dataset3.csv", index=False)
    print("✅ Feature extraction complete! Saved to features_dataset2.csv")
