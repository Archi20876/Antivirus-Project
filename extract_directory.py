import os
import math
import numpy as np
import pandas as pd

def calculate_entropy(data):
    """Calculates the Shannon entropy of a given byte string."""
    if not data:
        return 0
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    entropy = 0
    for count in byte_counts:
        if count == 0:
            continue
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy / 8

def extract_directory_features(dir_path):
    """
    Analyzes a directory and its subdirectories to extract features for
    machine learning.
    """
    total_files = 0
    total_executables = 0
    total_size = 0
    total_entropy = 0
    high_entropy_files = 0
    suspicious_file_names = 0
    file_extensions = {}
    
    suspicious_names = ["autorun.inf", "readme.txt.exe", "svchost.exe", "winlogon.exe"]

    for root, dirs, files in os.walk(dir_path):
        for name in files:
            file_path = os.path.join(root, name)
            total_files += 1

            if name.lower().endswith(('.exe', '.dll', '.bat', '.vbs', '.js')):
                total_executables += 1

            if name.lower() in suspicious_names:
                suspicious_file_names += 1

            ext = os.path.splitext(name)[1].lower()
            file_extensions[ext] = file_extensions.get(ext, 0) + 1

            try:
                size = os.path.getsize(file_path)
                total_size += size
                with open(file_path, "rb") as f:
                    data = f.read()
                    entropy = calculate_entropy(data)
                    total_entropy += entropy
                    if entropy > 0.9:
                        high_entropy_files += 1
            except Exception as e:
                # Skip files that can't be read (e.g., permission errors)
                # print(f"Error processing {file_path}: {e}")
                continue

    avg_size = total_size / total_files if total_files > 0 else 0
    avg_entropy = total_entropy / total_files if total_files > 0 else 0
    
    features = {
        "directory_name": os.path.basename(dir_path),
        "total_files": total_files,
        "total_executables": total_executables,
        "avg_size": avg_size,
        "avg_entropy": avg_entropy,
        "high_entropy_files": high_entropy_files,
        "suspicious_file_names": suspicious_file_names,
    }

    return features

if __name__ == "__main__":
    # Define the directory paths to scan
    # Replace these with the actual paths on your system
    directories_to_scan = [
        "/home/archita/antivirus_project/test_dir/",  # Benign example 1
        "/home/archita/antivirus_project/payloads/",  # Benign example 2
    ]
    
    output_data = []

    print("Starting directory feature extraction...")
    for dir_path in directories_to_scan:
        if not os.path.isdir(dir_path):
            print(f"Warning: Directory not found at {dir_path}. Skipping.")
            continue
        
        print(f"[*] Extracting features from: {dir_path}")
        features = extract_directory_features(dir_path)
        
        # Add a label for training
        # You must manually label your data as benign (0) or malicious (1)
        # For a real dataset, you'd need a mapping or a structured list
        features['label'] = 0 # Example: assuming all are benign for now
        output_data.append(features)

    # Save the extracted features to a CSV file
    if output_data:
        df = pd.DataFrame(output_data)
        df.to_csv("directory_features.csv", index=False)
        print("✅ Feature extraction complete! Saved to 'directory_features.csv'")
    else:
        print("❌ No data was extracted. Check your directory paths.")
