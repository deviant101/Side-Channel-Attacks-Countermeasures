#!/usr/bin/env python3
"""
Tests for timing attack implementation.

This module tests the timing attack against the vulnerable AES implementation.
"""

import os
import sys
import unittest
import statistics
import numpy as np

# Add the src directory to the path so we can import our modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from aes_implementation import VulnerableAES, generate_key
from timing_attack import TimingAttack

class TestTimingAttack(unittest.TestCase):
    """Test cases for the timing attack implementation."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.key = generate_key()
        self.aes = VulnerableAES(self.key)
        self.attack = TimingAttack(self.aes)
    
    def test_timing_difference(self):
        """Test that there are measurable timing differences for different inputs."""
        # Test data with values that should have different timing characteristics
        zeros = bytes([0] * 16)  # All zeros (should be slower)
        ones = bytes([255] * 16)  # All ones
        mixed = bytes([i % 256 for i in range(16)])  # Mixed values
        
        # Collect timing data
        timings_zeros = []
        timings_ones = []
        timings_mixed = []
        
        # Perform multiple encryptions to get statistically significant results
        for _ in range(10):
            _, _, time_zeros = self.aes.encrypt_block(zeros)
            _, _, time_ones = self.aes.encrypt_block(ones)
            _, _, time_mixed = self.aes.encrypt_block(mixed)
            
            timings_zeros.append(time_zeros)
            timings_ones.append(time_ones)
            timings_mixed.append(time_mixed)
        
        # Calculate average timings
        avg_zeros = statistics.mean(timings_zeros)
        avg_ones = statistics.mean(timings_ones)
        avg_mixed = statistics.mean(timings_mixed)
        
        print(f"\nAverage encryption times:")
        print(f"  All zeros: {avg_zeros:.6f} seconds")
        print(f"  All ones:  {avg_ones:.6f} seconds")
        print(f"  Mixed:     {avg_mixed:.6f} seconds")
        
        # Assert that zeros are slower (our implementation adds delays for zero bytes)
        self.assertGreater(avg_zeros, avg_ones, "Zeros should be slower than ones")
        
        # Test that the timing differences are statistically significant
        # using a simple statistical measure
        std_dev = statistics.stdev(timings_zeros + timings_ones + timings_mixed)
        difference = abs(avg_zeros - avg_ones)
        
        print(f"  Timing difference: {difference:.6f} seconds")
        print(f"  Standard deviation: {std_dev:.6f} seconds")
        
        # The difference should be greater than the standard deviation
        # for statistical significance
        self.assertGreater(difference, std_dev, 
                          "Timing difference should be statistically significant")
    
    def test_collect_timing_data(self):
        """Test the timing data collection functionality."""
        # Collect timing data for a small subset of byte values
        byte_values = [0, 1, 2, 255]
        
        for byte_val in byte_values:
            plaintext = bytes([byte_val] * 16)
            timings = []
            
            # Perform multiple encryptions to get reliable timing data
            for _ in range(5):
                _, _, execution_time = self.aes.encrypt_block(plaintext)
                timings.append(execution_time)
            
            self.attack.collected_timings[bytes([byte_val])] = timings
        
        # Make sure we collected data for each byte value
        self.assertEqual(len(self.attack.collected_timings), len(byte_values))
        
        # Analyze the collected data
        potential_keys = self.attack.analyze_timing_data()
        
        # Ensure the analysis produces results for all byte values
        self.assertEqual(len(potential_keys), len(byte_values))
        
        # Make sure the zero byte has distinctive timing
        # (it should be among the extreme values)
        sorted_timings = sorted(potential_keys.items(), key=lambda x: x[1])
        extremes = [sorted_timings[0][0], sorted_timings[-1][0]]
        
        print("\nByte values with extreme timing:")
        print(f"  Slowest byte: {sorted_timings[-1][0]} ({sorted_timings[-1][1]:.6f} seconds)")
        print(f"  Fastest byte: {sorted_timings[0][0]} ({sorted_timings[0][1]:.6f} seconds)")
        
        self.assertIn(0, extremes, "Zero byte should have distinctive timing")
    
    def test_full_timing_attack(self):
        """Test a complete small-scale timing attack."""
        # Run a reduced version of the timing attack
        print("\nRunning reduced timing attack demonstration...")
        
        # Collect timing data for a reduced set of values
        for byte_value in range(0, 10):  # Just test a few values
            plaintext = bytes([byte_value] * 16)
            timings = []
            
            # Reduce the number of samples for testing
            for _ in range(10):
                _, _, execution_time = self.aes.encrypt_block(plaintext)
                timings.append(execution_time)
            
            self.attack.collected_timings[bytes([byte_value])] = timings
        
        # Analyze the data and print results
        potential_keys = self.attack.analyze_timing_data()
        
        # Ensure we got results
        self.assertGreaterEqual(len(potential_keys), 1)
        
        print("\nReduced timing attack results:")
        for byte_val, timing in sorted(potential_keys.items(), key=lambda x: x[1], reverse=True):
            print(f"  Byte value {byte_val}: {timing:.6f} seconds")
        
        # Check if the zero byte has distinctive timing
        self.assertIn(0, potential_keys)


if __name__ == '__main__':
    unittest.main()