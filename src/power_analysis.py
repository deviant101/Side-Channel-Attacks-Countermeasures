#!/usr/bin/env python3
"""
Power Analysis Attack Implementation.

This script demonstrates a power analysis attack against the vulnerable AES implementation.
It collects and analyzes power traces during encryption to extract information about
the secret key.
"""

import numpy as np
import matplotlib.pyplot as plt
from typing import List, Dict, Tuple, Optional
import os
import sys
from collections import defaultdict

# Import our vulnerable AES implementation
from aes_implementation import VulnerableAES, generate_key

class PowerAnalysisAttack:
    def __init__(self, target_aes: VulnerableAES):
        """Initialize with a reference to the target AES implementation."""
        self.target = target_aes
        self.collected_traces: Dict[bytes, List[List[float]]] = {}
        self.key_candidates = [0] * 16  # For a 16-byte key
    
    def collect_power_traces(self, num_samples: int = 100) -> Dict[bytes, List[List[float]]]:
        """
        Collect power traces by encrypting different plaintexts.
        For a real DPA attack, we would encrypt many different plaintexts.
        """
        print(f"Collecting power traces with {num_samples} different plaintexts...")
        
        for i in range(num_samples):
            # Create various plaintexts for testing
            if i % 3 == 0:
                plaintext = bytes([i % 256] * 16)  # Repeating value
            elif i % 3 == 1:
                plaintext = bytes([(i + j) % 256 for j in range(16)])  # Incrementing values
            else:
                plaintext = os.urandom(16)  # Random plaintext
            
            # Encrypt and collect power trace
            _, power_trace, _ = self.target.encrypt_block(plaintext)
            
            # Store the plaintext and its corresponding power trace
            self.collected_traces[plaintext] = power_trace
            
            sys.stdout.write(f"\rCollected trace for sample: {i+1}/{num_samples}")
            sys.stdout.flush()
        
        print("\nData collection complete!")
        return self.collected_traces
    
    def differential_power_analysis(self, target_byte_index: int = 0) -> Dict[int, float]:
        """
        Performs Differential Power Analysis (DPA) to reveal key information.
        
        This is a simplified DPA that focuses on the relationship between
        plaintext bytes and power consumption patterns. In a real attack,
        we would use statistical methods like correlation analysis.
        
        Args:
            target_byte_index: Index of the key byte to attack (0-15)
            
        Returns:
            Dictionary of possible key byte values and their correlation scores
        """
        print(f"Performing DPA attack on key byte {target_byte_index}...")
        
        if not self.collected_traces:
            print("No power traces available. Run collect_power_traces() first.")
            return {}
        
        # For each possible key byte value (0-255)
        key_correlations = {}
        
        # Group traces by the plaintext byte at the target index
        traces_by_plaintext_byte = defaultdict(list)
        for plaintext, trace in self.collected_traces.items():
            plaintext_byte = plaintext[target_byte_index]
            traces_by_plaintext_byte[plaintext_byte].extend(trace)
        
        # In a real DPA attack, we would perform statistical correlation analysis
        # between the power traces and the Hamming weight of intermediate values
        # For this simplified demonstration, we'll use direct averaging
        
        # For each possible key value (0-255)
        for key_guess in range(256):
            # Calculate correlation metric for this key guess
            # In a real attack, this would involve modeling the power consumption
            correlation_sum = 0
            count = 0
            
            for plaintext_byte, traces in traces_by_plaintext_byte.items():
                # Simulate correlation with the Hamming weight of SubBytes(plaintext_byte ⊕ key_guess)
                # This is a simplified model; a real attack would use actual intermediate values
                intermediate_val = plaintext_byte ^ key_guess  # XOR operation
                hamming_weight = bin(intermediate_val).count('1')  # Count set bits
                
                # Calculate "correlation" with power trace
                # In a real attack, we would use statistical correlation
                trace_avg = sum(traces) / len(traces) if traces else 0
                correlation_sum += trace_avg * hamming_weight
                count += 1
            
            key_correlations[key_guess] = correlation_sum / count if count > 0 else 0
        
        # The key candidate with the highest correlation is likely the correct one
        self.key_candidates[target_byte_index] = max(key_correlations.items(), key=lambda x: x[1])[0]
        
        return key_correlations
    
    def visualize_power_analysis(self, target_byte_index: int = 0, correlations: Optional[Dict[int, float]] = None):
        """
        Visualize the power analysis results.
        
        Args:
            target_byte_index: Index of the key byte being analyzed
            correlations: Optional pre-calculated correlations
        """
        if correlations is None:
            if not hasattr(self, 'key_correlations') or not self.key_correlations:
                correlations = self.differential_power_analysis(target_byte_index)
            else:
                correlations = self.key_correlations
        
        # Prepare data for visualization
        key_guesses = list(correlations.keys())
        correlation_values = list(correlations.values())
        
        # Sort for better visualization
        sorted_indices = np.argsort(key_guesses)
        sorted_keys = [key_guesses[i] for i in sorted_indices]
        sorted_correlations = [correlation_values[i] for i in sorted_indices]
        
        # Highlight the most likely key byte
        best_guess = max(correlations.items(), key=lambda x: x[1])[0]
        best_guess_idx = sorted_keys.index(best_guess)
        
        # Create visualization
        plt.figure(figsize=(12, 6))
        plt.bar(sorted_keys, sorted_correlations, width=1.0)
        plt.title(f'Differential Power Analysis for Key Byte {target_byte_index}')
        plt.xlabel('Key Byte Guess')
        plt.ylabel('Correlation Value')
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        
        # Highlight the most likely key byte
        plt.bar(best_guess, sorted_correlations[best_guess_idx], color='red', width=1.0)
        
        # Add annotation for the best guess
        plt.annotate(f'Best Guess: 0x{best_guess:02X}',
                    xy=(best_guess, sorted_correlations[best_guess_idx]),
                    xytext=(best_guess, sorted_correlations[best_guess_idx] + max(correlation_values) * 0.05),
                    arrowprops=dict(facecolor='black', shrink=0.05),
                    horizontalalignment='center',
                    verticalalignment='bottom')
        
        # Save the figure
        os.makedirs('./docs/figures', exist_ok=True)
        plt.savefig(f'./docs/figures/power_analysis_byte_{target_byte_index}.png')
        print(f"Visualization saved to './docs/figures/power_analysis_byte_{target_byte_index}.png'")
        plt.close()
    
    def visualize_power_traces(self, num_traces: int = 5):
        """
        Visualize collected power traces for comparison.
        
        Args:
            num_traces: Number of traces to visualize
        """
        if not self.collected_traces:
            print("No power traces available. Run collect_power_traces() first.")
            return
        
        plt.figure(figsize=(14, 8))
        
        # Select a few traces to visualize
        traces_to_show = list(self.collected_traces.items())[:num_traces]
        
        for i, (plaintext, trace) in enumerate(traces_to_show):
            # Truncate the trace for better visualization
            max_len = min(500, len(trace))
            plt.plot(trace[:max_len], label=f"Plaintext starting with: {plaintext[:4].hex()}")
        
        plt.title('Power Consumption Traces During Encryption')
        plt.xlabel('Time Sample')
        plt.ylabel('Power Consumption (Simulated)')
        plt.legend()
        plt.grid(True, alpha=0.3)
        
        # Save the figure
        os.makedirs('./docs/figures', exist_ok=True)
        plt.savefig('./docs/figures/power_traces_comparison.png')
        print("Power traces visualization saved to './docs/figures/power_traces_comparison.png'")
        plt.close()
    
    def demonstrate_attack(self, target_byte_indices: List[int] = None):
        """
        Demonstrate the full power analysis attack.
        
        Args:
            target_byte_indices: List of key byte indices to attack (default is first byte)
        """
        if target_byte_indices is None:
            target_byte_indices = [0]  # Default: attack first byte
            
        print("Starting power analysis attack demonstration...")
        
        # Step 1: Collect power traces
        self.collect_power_traces(num_samples=100)  # Reduced for demonstration
        
        # Step 2: Visualize raw power traces for comparison
        self.visualize_power_traces(num_traces=5)
        
        # Step 3: Perform DPA on target bytes and visualize
        for byte_idx in target_byte_indices:
            correlations = self.differential_power_analysis(byte_idx)
            self.visualize_power_analysis(byte_idx, correlations)
            
            # Report the most likely key byte
            best_guess = max(correlations.items(), key=lambda x: x[1])[0]
            print(f"Key byte {byte_idx}: Most likely value is 0x{best_guess:02X}")
        
        # Step 4: Report findings
        print("\nPower Analysis Attack Results:")
        print("-----------------------------")
        print("Recovered key bytes:")
        
        # Display recovered key bytes (only those we attacked)
        recovered_key = ""
        for i in range(16):
            if i in target_byte_indices:
                recovered_key += f"{self.key_candidates[i]:02X} "
            else:
                recovered_key += "?? "
        
        print(f"  {recovered_key}")
        print("\nIn a real attack, all 16 bytes would be recovered, potentially")
        print("requiring more traces and more sophisticated statistical analysis.")


if __name__ == "__main__":
    print("Power Analysis Attack Demonstration")
    print("==================================")
    
    # Generate a random key for demonstration
    key = generate_key()
    print(f"Generated random key: {key.hex()}")
    
    # Create the vulnerable AES implementation
    aes = VulnerableAES(key)
    
    # Create and run the power analysis attack
    attack = PowerAnalysisAttack(aes)
    
    # Attack first 4 bytes of the key for demonstration
    attack.demonstrate_attack(target_byte_indices=[0, 1, 2, 3])