#!/usr/bin/env python3
"""
Countermeasures Against Side-Channel Attacks.

This module implements various defensive techniques to protect cryptographic
implementations against timing and power analysis side-channel attacks.
"""

import time
import random
import os
from typing import List, Tuple
import numpy as np

# Import our vulnerable AES implementation as a base
from aes_implementation import SBOX, generate_key

class ProtectedAES:
    """
    AES implementation with countermeasures against side-channel attacks.
    This class demonstrates various techniques to mitigate timing and power
    analysis attacks.
    """
    
    def __init__(self, key: bytes, enable_countermeasures: bool = True):
        """
        Initialize with a key and countermeasure settings.
        
        Args:
            key: The encryption key
            enable_countermeasures: Whether to enable protection (for comparison)
        """
        self.key = key
        self.enable_countermeasures = enable_countermeasures
        self.power_trace = []  # For comparison with vulnerable implementation
        
    def _constant_time_lookup(self, table: List[int], index: int) -> int:
        """
        Perform a table lookup in constant time to prevent timing attacks.
        
        In a normal table lookup, the CPU might optimize and return early for
        certain indices due to caching or branch prediction. This implementation
        ensures every lookup takes the same time regardless of the index.
        """
        result = 0
        
        # Access every element of the table, but only keep the one we want
        for i in range(len(table)):
            # This is a constant-time select operation
            # It evaluates both options regardless of the condition
            # The condition itself is evaluated in constant time
            dummy = (i == index)  # This will be 1 if true, 0 if false
            result = (result & ~dummy) | (table[i] & dummy)
        
        return result
    
    def _masked_sub_bytes(self, data: List[int]) -> List[int]:
        """
        SubBytes operation with masking to prevent power analysis attacks.
        
        This implementation uses random masking to hide the actual values
        being processed, which helps prevent power analysis.
        """
        result = []
        
        for i in range(len(data)):
            byte = data[i]
            
            if self.enable_countermeasures:
                # Add random noise to power consumption
                self._add_random_power_noise()
                
                # Apply masking: Use random mask to hide the actual value
                # in the power trace
                mask = random.randint(0, 255)
                masked_byte = byte ^ mask  # XOR with random mask
                
                # Lookup in the S-box (constant time if enabled)
                if self.enable_countermeasures:
                    # Constant-time lookup to prevent timing attacks
                    substituted = self._constant_time_lookup(SBOX, masked_byte)
                else:
                    substituted = SBOX[masked_byte]
                
                # Remove the mask (adjusted for the S-box transformation)
                # In a real implementation, we'd use a masked S-box
                # This is simplified for demonstration
                result_byte = substituted ^ SBOX[mask]
                
                # Record simulated power (with masking, it's now unrelated to data)
                power = 0.01 * random.uniform(0.8, 1.2)  # Randomized power trace
                self.power_trace.append(power)
            else:
                # Fallback to normal (vulnerable) implementation
                substituted = SBOX[byte]
                result_byte = substituted
                
                # Record simulated power (data-dependent, vulnerable)
                power = 0.01 * (byte ^ self.key[i % len(self.key)])
                power += random.uniform(0, 0.005)
                self.power_trace.append(power)
            
            result.append(result_byte)
            
        return result
        
    def _add_random_power_noise(self):
        """
        Add random operations to obscure the power trace.
        This is a basic technique to add noise to the power side-channel.
        """
        if not self.enable_countermeasures:
            return
            
        # Perform some random operations to add noise
        dummy = 0
        iterations = random.randint(10, 20)
        for _ in range(iterations):
            dummy = (dummy + random.randint(0, 255)) & 0xFF
        
        # Ensure the result is used somehow to prevent optimization
        if dummy == 0:
            dummy = 1
            
    def encrypt_block(self, plaintext: bytes) -> Tuple[bytes, List[float], float]:
        """
        Encrypt a block of data with side-channel protections.
        Returns the encrypted data, power trace, and timing information.
        """
        # Clear power trace from previous operations
        self.power_trace = []
        
        # Convert to integers
        data = list(plaintext)
        
        # Apply random timing to defeat timing attacks
        if self.enable_countermeasures:
            # Add random delay before processing
            time.sleep(random.uniform(0.001, 0.002))
        
        # Record the start time
        start_time = time.time()
        
        # For this simple demonstration, we'll just apply SubBytes
        # and XOR with the key (not full AES)
        for _ in range(10):  # 10 rounds
            data = self._masked_sub_bytes(data)
            
            # Mix with key (with constant-time operations if enabled)
            if self.enable_countermeasures:
                # Constant-time XOR implementation
                for i in range(len(data)):
                    # Additional noise to hide power consumption during key mixing
                    self._add_random_power_noise()
                    
                    # The XOR itself is generally constant-time
                    data[i] ^= self.key[i % len(self.key)]
            else:
                # Standard implementation (potentially vulnerable)
                for i in range(len(data)):
                    data[i] ^= self.key[i % len(self.key)]
        
        # Record the end time
        end_time = time.time()
        execution_time = end_time - start_time
        
        # Apply random timing to defeat timing attacks
        if self.enable_countermeasures:
            # Add random delay after processing to normalize total execution time
            time.sleep(random.uniform(0.001, 0.002))
        
        return bytes(data), self.power_trace, execution_time

    def encrypt_with_blinding(self, plaintext: bytes) -> bytes:
        """
        Encrypt with an additional countermeasure: blinding.
        
        Blinding adds randomness to the encryption process to prevent
        attackers from controlling inputs precisely.
        """
        if not self.enable_countermeasures:
            result, _, _ = self.encrypt_block(plaintext)
            return result
            
        # Generate a random blinding factor
        blind = os.urandom(len(plaintext))
        blind_data = bytes(a ^ b for a, b in zip(plaintext, blind))
        
        # Encrypt the blinded data
        encrypted_blind, _, _ = self.encrypt_block(blind_data)
        
        # Compensate for the blinding
        # In a real implementation, this would be more complex and specific
        # to the encryption algorithm
        result = bytes(a ^ b for a, b in zip(encrypted_blind, blind))
        
        return result


# Other countermeasure techniques demonstration

def demonstrate_shuffling(data: bytes) -> bytes:
    """
    Demonstrate operation shuffling as a countermeasure.
    
    Shuffling changes the order of operations to make it harder
    for attackers to correlate power traces with specific operations.
    """
    # Create a list of operations to perform
    operations = list(range(len(data)))
    # Shuffle their order
    random.shuffle(operations)
    
    result = bytearray(data)
    
    # Perform operations in random order
    for op_idx in operations:
        # Example operation: rotate bits of the byte
        byte = result[op_idx]
        # Rotate bits right by a random amount
        rotation = random.randint(1, 7)
        rotated = ((byte >> rotation) | (byte << (8 - rotation))) & 0xFF
        result[op_idx] = rotated
    
    return bytes(result)

def demonstrate_random_delays() -> float:
    """
    Demonstrate random delays as a countermeasure against timing attacks.
    
    Returns the total execution time for comparison.
    """
    start_time = time.time()
    
    # Perform some crypto operations
    dummy = 0
    for i in range(1000):
        # Insert random delays
        if random.random() < 0.1:  # 10% chance
            sleep_time = random.uniform(0.0001, 0.0005)
            time.sleep(sleep_time)
        
        # Simulated operation
        dummy = (dummy + i) % 256
    
    end_time = time.time()
    return end_time - start_time

def demonstrate_double_execution(func, *args, **kwargs) -> Tuple:
    """
    Demonstrate double execution technique for validation.
    
    This countermeasure executes the operation twice and compares
    the results to detect glitch attacks or fault injections.
    """
    # First execution
    result1 = func(*args, **kwargs)
    
    # Second execution
    result2 = func(*args, **kwargs)
    
    # Compare results
    if result1 != result2:
        # Results differ - potential attack detected
        raise SecurityError("Potential fault injection detected")
    
    return result1

class SecurityError(Exception):
    """Exception raised for security-related errors."""
    pass


# Example usage and comparison
if __name__ == "__main__":
    print("Countermeasures Demonstration")
    print("============================")
    
    # Generate a random key
    key = generate_key()
    print(f"Generated random key: {key.hex()}")
    
    # Create both the vulnerable and protected implementations
    aes_protected = ProtectedAES(key, enable_countermeasures=True)
    aes_vulnerable = ProtectedAES(key, enable_countermeasures=False)
    
    # Test data
    test_data = bytes([i % 256 for i in range(16)])
    
    print("\nComparing execution with and without countermeasures:")
    
    # Without countermeasures
    print("\nWithout countermeasures:")
    encrypted_vuln, power_vuln, time_vuln = aes_vulnerable.encrypt_block(test_data)
    print(f"  Encrypted: {encrypted_vuln.hex()}")
    print(f"  Execution time: {time_vuln:.6f} seconds")
    print(f"  Power trace length: {len(power_vuln)} samples")
    print(f"  Power trace variance: {np.var(power_vuln):.8f}")
    
    # With countermeasures
    print("\nWith countermeasures:")
    encrypted_prot, power_prot, time_prot = aes_protected.encrypt_block(test_data)
    print(f"  Encrypted: {encrypted_prot.hex()}")
    print(f"  Execution time: {time_prot:.6f} seconds")
    print(f"  Power trace length: {len(power_prot)} samples")
    print(f"  Power trace variance: {np.var(power_prot):.8f}")
    
    # Additional countermeasures demonstration
    print("\nDemonstrating additional countermeasures:")
    
    # Shuffling
    print("\nOperation shuffling example:")
    shuffled = demonstrate_shuffling(test_data)
    print(f"  Original data: {test_data.hex()}")
    print(f"  After shuffling: {shuffled.hex()}")
    
    # Random delays
    print("\nRandom delays example:")
    execution_time = demonstrate_random_delays()
    print(f"  Execution time with random delays: {execution_time:.6f} seconds")
    
    # Double execution (fault detection)
    print("\nDouble execution (fault detection) example:")
    try:
        result = demonstrate_double_execution(lambda x: x + 1, 41)
        print(f"  Result: {result}")
    except SecurityError as e:
        print(f"  Error: {e}")