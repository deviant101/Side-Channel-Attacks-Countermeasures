#!/usr/bin/env python3
"""
Timing Attack Implementation.

This script demonstrates a timing attack against the vulnerable AES implementation.
It exploits data-dependent timing variations in the encryption process to extract
information about the secret key.
"""

import time
import numpy as np
import matplotlib.pyplot as plt
from typing import List, Dict, Tuple
import os
import sys

# Import our vulnerable AES implementation
from aes_implementation import VulnerableAES, generate_key

class TimingAttack:
    def __init__(self, target_aes: VulnerableAES):
        """Initialize with a reference to the target AES implementation."""
        self.target = target_aes
        self.collected_timings: Dict[bytes, List[float]] = {}
    
    def collect_timing_data(self, num_samples: int = 1000) -> Dict[bytes, List[float]]:
        """
        Collect timing data by encrypting different plaintexts.
        For each byte value (0-255), encrypt multiple times and record timings.
        """
        print(f"Collecting timing data with {num_samples} samples per byte value...")
        
        for byte_value in range(256):
            # Create a plaintext with just this byte value repeated
            plaintext = bytes([byte_value] * 16)
            timings = []
            
            # Encrypt multiple times and record timing
            for _ in range(num_samples):
                _, _, execution_time = self.target.encrypt_block(plaintext)
                timings.append(execution_time)
            
            self.collected_timings[bytes([byte_value])] = timings
            sys.stdout.write(f"\rCollected data for byte value: {byte_value}/255")
            sys.stdout.flush()
        
        print("\nData collection complete!")
        return self.collected_timings
    
    def analyze_timing_data(self) -> Dict[int, List[float]]:
        """
        Analyze the collected timing data to extract information.
        For a real attack, this would attempt to recover key bits.
        """
        # Calculate average timing for each byte value
        average_timings = {}
        for byte_val, timings in self.collected_timings.items():
            byte_int = byte_val[0]  # Convert from bytes to int
            average_timings[byte_int] = sum(timings) / len(timings)
        
        # Sort byte values by average timing
        sorted_timings = sorted(average_timings.items(), key=lambda x: x[1])
        
        # Extract key information based on timing differences
        # In a real attack, these timing differences would correlate with key bits
        potential_keys = {}
        for i, (byte_val, avg_time) in enumerate(sorted_timings):
            # The byte values with unusual timings are potentially revealing key information
            potential_keys[byte_val] = avg_time
        
        return potential_keys
    
    def visualize_timing_data(self):
        """
        Visualize the timing differences to show the side channel leak.
        """
        if not self.collected_timings:
            print("No timing data available. Run collect_timing_data() first.")
            return
        
        # Extract average timings for visualization
        byte_values = []
        avg_timings = []
        
        for byte_val, timings in self.collected_timings.items():
            byte_values.append(byte_val[0])
            avg_timings.append(sum(timings) / len(timings))
        
        # Ensure we're plotting in byte order
        sorted_indices = sorted(range(len(byte_values)), key=lambda i: byte_values[i])
        sorted_bytes = [byte_values[i] for i in sorted_indices]
        sorted_timings = [avg_timings[i] for i in sorted_indices]
        
        # Create visualization
        plt.figure(figsize=(12, 6))
        plt.bar(sorted_bytes, sorted_timings, width=1.0)
        plt.title('Timing Side-Channel Analysis')
        plt.xlabel('Byte Value')
        plt.ylabel('Average Execution Time (seconds)')
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        
        # Highlight specific patterns that reveal information
        plt.axhline(y=np.mean(sorted_timings), color='r', linestyle='-', label='Average Time')
        
        # Highlight byte value 0 which has additional delay in our implementation
        zero_idx = sorted_bytes.index(0) if 0 in sorted_bytes else -1
        if zero_idx >= 0:
            plt.bar(0, sorted_timings[zero_idx], color='red', width=1.0)
        
        # Highlight even values which have different timing
        even_bytes = [b for b in range(256) if b % 2 == 0]
        even_indices = [sorted_bytes.index(b) for b in even_bytes if b in sorted_bytes]
        for idx in even_indices:
            plt.bar(sorted_bytes[idx], sorted_timings[idx], color='orange', width=1.0)
            
        plt.legend()
        
        # Save the figure
        os.makedirs('./docs/figures', exist_ok=True)
        plt.savefig('./docs/figures/timing_attack_visualization.png')
        print("Visualization saved to './docs/figures/timing_attack_visualization.png'")
        plt.close()
    
    def demonstrate_attack(self):
        """
        Demonstrate the full timing attack.
        """
        print("Starting timing attack demonstration...")
        
        # Step 1: Collect timing data
        self.collect_timing_data(num_samples=50)  # Reduced for demonstration
        
        # Step 2: Analyze the data
        potential_keys = self.analyze_timing_data()
        
        # Step 3: Report findings
        print("\nTiming Analysis Results:")
        print("-----------------------")
        print(f"Identified {len(potential_keys)} byte values with distinctive timing patterns")
        
        # Display the top 10 most distinctive byte values
        sorted_by_timing = sorted(potential_keys.items(), key=lambda x: x[1], reverse=True)
        print("\nTop 10 byte values with distinctive timing patterns:")
        for i, (byte_val, timing) in enumerate(sorted_by_timing[:10]):
            print(f"  {i+1}. Byte value {byte_val}: {timing:.6f} seconds")
        
        # Step 4: Visualize the results
        self.visualize_timing_data()
        
        print("\nDemonstration complete. In a real attack, these timing differences")
        print("would be used to extract information about the secret key.")


if __name__ == "__main__":
    print("Timing Attack Demonstration")
    print("===========================")
    
    # Generate a random key for demonstration
    key = generate_key()
    print(f"Generated random key: {key.hex()}")
    
    # Create the vulnerable AES implementation
    aes = VulnerableAES(key)
    
    # Create and run the timing attack
    attack = TimingAttack(aes)
    attack.demonstrate_attack()