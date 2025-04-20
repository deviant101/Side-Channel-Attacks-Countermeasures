#!/usr/bin/env python3
"""
Tests for side-channel attack countermeasures.

This module tests the effectiveness of various countermeasures
against timing and power analysis attacks.
"""

import os
import sys
import unittest
import statistics
import numpy as np
from scipy import stats

# Add the src directory to the path so we can import our modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from aes_implementation import VulnerableAES, generate_key
from countermeasures import ProtectedAES, demonstrate_shuffling, demonstrate_random_delays
from timing_attack import TimingAttack
from power_analysis import PowerAnalysisAttack

class TestCountermeasures(unittest.TestCase):
    """Test cases for the side-channel attack countermeasures."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.key = generate_key()
        self.vulnerable_aes = VulnerableAES(self.key)
        self.protected_aes = ProtectedAES(self.key, enable_countermeasures=True)
        self.unprotected_aes = ProtectedAES(self.key, enable_countermeasures=False)
    
    def test_constant_time_operations(self):
        """Test if the protected implementation has constant-time behavior."""
        # Test data with values that would show timing differences in the vulnerable implementation
        zeros = bytes([0] * 16)  # All zeros (should be slower in vulnerable)
        ones = bytes([255] * 16)  # All ones
        
        # Collect timing data for both implementations
        vuln_timings_zeros = []
        vuln_timings_ones = []
        prot_timings_zeros = []
        prot_timings_ones = []
        
        # Collect multiple samples for statistical significance
        num_samples = 20
        print("\nCollecting timing data for constant-time analysis...")
        
        for _ in range(num_samples):
            # Vulnerable implementation
            _, _, vuln_time_zeros = self.vulnerable_aes.encrypt_block(zeros)
            _, _, vuln_time_ones = self.vulnerable_aes.encrypt_block(ones)
            
            # Protected implementation
            _, _, prot_time_zeros = self.protected_aes.encrypt_block(zeros)
            _, _, prot_time_ones = self.protected_aes.encrypt_block(ones)
            
            vuln_timings_zeros.append(vuln_time_zeros)
            vuln_timings_ones.append(vuln_time_ones)
            prot_timings_zeros.append(prot_time_zeros)
            prot_timings_ones.append(prot_time_ones)
        
        # Calculate statistics
        vuln_avg_zeros = statistics.mean(vuln_timings_zeros)
        vuln_avg_ones = statistics.mean(vuln_timings_ones)
        vuln_diff = abs(vuln_avg_zeros - vuln_avg_ones)
        vuln_std = statistics.stdev(vuln_timings_zeros + vuln_timings_ones)
        
        prot_avg_zeros = statistics.mean(prot_timings_zeros)
        prot_avg_ones = statistics.mean(prot_timings_ones)
        prot_diff = abs(prot_avg_zeros - prot_avg_ones)
        prot_std = statistics.stdev(prot_timings_zeros + prot_timings_ones)
        
        # Calculate statistical significance using t-test
        # Null hypothesis: The means of the two timing distributions are the same
        vuln_ttest = stats.ttest_ind(vuln_timings_zeros, vuln_timings_ones)
        prot_ttest = stats.ttest_ind(prot_timings_zeros, prot_timings_ones)
        
        print("\nTiming Analysis Results:")
        print("----------------------")
        print("Vulnerable Implementation:")
        print(f"  Average time for zeros: {vuln_avg_zeros:.6f} seconds")
        print(f"  Average time for ones: {vuln_avg_ones:.6f} seconds")
        print(f"  Timing difference: {vuln_diff:.6f} seconds")
        print(f"  Standard deviation: {vuln_std:.6f} seconds")
        print(f"  T-test p-value: {vuln_ttest.pvalue:.6f}")
        
        print("\nProtected Implementation:")
        print(f"  Average time for zeros: {prot_avg_zeros:.6f} seconds")
        print(f"  Average time for ones: {prot_avg_ones:.6f} seconds")
        print(f"  Timing difference: {prot_diff:.6f} seconds")
        print(f"  Standard deviation: {prot_std:.6f} seconds") 
        print(f"  T-test p-value: {prot_ttest.pvalue:.6f}")
        
        # The vulnerable implementation should show statistically significant timing differences
        # (p-value < 0.05), while the protected one should not (p-value >= 0.05)
        self.assertLess(vuln_ttest.pvalue, 0.05, 
                       "Vulnerable implementation should have statistically significant timing differences")
        self.assertGreaterEqual(prot_ttest.pvalue, 0.05,
                              "Protected implementation should not have statistically significant timing differences")
    
    def test_power_trace_masking(self):
        """Test if the protected implementation masks power traces effectively."""
        # Generate test data
        test_data = bytes([i % 256 for i in range(16)])
        
        # Collect power traces for both implementations
        _, vuln_power, _ = self.vulnerable_aes.encrypt_block(test_data)
        _, prot_power, _ = self.protected_aes.encrypt_block(test_data)
        
        # Calculate statistics of the power traces
        vuln_mean = np.mean(vuln_power)
        vuln_std = np.std(vuln_power)
        prot_mean = np.mean(prot_power)
        prot_std = np.std(prot_power)
        
        print("\nPower Analysis Results:")
        print("---------------------")
        print(f"Vulnerable power trace: mean={vuln_mean:.6f}, std={vuln_std:.6f}")
        print(f"Protected power trace: mean={prot_mean:.6f}, std={prot_std:.6f}")
        
        # The protected implementation should have higher variance in power
        # consumption due to added noise and randomization
        self.assertGreater(prot_std, vuln_std,
                          "Protected implementation should have more randomized power consumption")
        
        # Test correlation between power traces and the data/key
        # For vulnerable implementation, there should be correlation
        # For protected implementation, there should be minimal correlation
        vuln_correlations = []
        prot_correlations = []
        
        # Collect multiple power traces for both implementations
        for i in range(10):
            plaintext = bytes([(i + j) % 256 for j in range(16)])
            
            _, vuln_trace, _ = self.vulnerable_aes.encrypt_block(plaintext)
            _, prot_trace, _ = self.protected_aes.encrypt_block(plaintext)
            
            # Calculate correlation with the first byte of plaintext XORed with the first byte of key
            # This is a simplified model for the correlation between power and the operation being performed
            byte_correlation = []
            for j in range(min(len(vuln_trace), len(prot_trace))):
                expected_power = 0.01 * (plaintext[0] ^ self.key[0])
                vuln_correlation = abs(vuln_trace[j] - expected_power) / expected_power
                prot_correlation = abs(prot_trace[j] - expected_power) / expected_power
                byte_correlation.append((vuln_correlation, prot_correlation))
            
            # Average the correlations
            if byte_correlation:
                avg_vuln_corr = sum(c[0] for c in byte_correlation) / len(byte_correlation)
                avg_prot_corr = sum(c[1] for c in byte_correlation) / len(byte_correlation)
                vuln_correlations.append(avg_vuln_corr)
                prot_correlations.append(avg_prot_corr)
        
        # Calculate average correlations
        avg_vuln_correlation = sum(vuln_correlations) / len(vuln_correlations)
        avg_prot_correlation = sum(prot_correlations) / len(prot_correlations)
        
        print(f"\nAvg correlation (vulnerable): {avg_vuln_correlation:.6f}")
        print(f"Avg correlation (protected): {avg_prot_correlation:.6f}")
        
        # The protected implementation should have less correlation with the data
        # A perfect countermeasure would have zero correlation
        self.assertLess(avg_prot_correlation, avg_vuln_correlation,
                       "Protected implementation should have less power correlation with data")
    
    def test_timing_attack_resistance(self):
        """Test resistance against timing attacks."""
        # Create timing attacks against both implementations
        vuln_attack = TimingAttack(self.vulnerable_aes)
        prot_attack = TimingAttack(self.protected_aes)
        
        # Collect timing data for a small subset of byte values
        byte_values = [0, 255]  # Should have very different timings in vulnerable impl
        
        print("\nRunning timing attacks against both implementations...")
        
        # Collect data for both attacks
        for attack in [vuln_attack, prot_attack]:
            for byte_val in byte_values:
                plaintext = bytes([byte_val] * 16)
                timings = []
                
                # Collect multiple samples
                for _ in range(10):
                    _, _, execution_time = attack.target.encrypt_block(plaintext)
                    timings.append(execution_time)
                
                attack.collected_timings[bytes([byte_val])] = timings
        
        # Analyze the data from both attacks
        vuln_keys = vuln_attack.analyze_timing_data()
        prot_keys = prot_attack.analyze_timing_data()
        
        # Calculate the timing differences found in each attack
        vuln_diff = abs(statistics.mean(vuln_attack.collected_timings[bytes([0])]) - 
                       statistics.mean(vuln_attack.collected_timings[bytes([255])]))
                       
        prot_diff = abs(statistics.mean(prot_attack.collected_timings[bytes([0])]) - 
                      statistics.mean(prot_attack.collected_timings[bytes([255])]))
        
        print("\nTiming attack results:")
        print("Vulnerable implementation - timing difference: {:.6f} seconds".format(vuln_diff))
        print("Protected implementation - timing difference: {:.6f} seconds".format(prot_diff))
        
        # The timing difference in the protected implementation should be
        # significantly less than in the vulnerable implementation
        self.assertLess(prot_diff, vuln_diff, 
                       "Protected implementation should have smaller timing differences")
    
    def test_blinding_countermeasure(self):
        """Test the blinding countermeasure."""
        # Create test data
        test_data = bytes([i % 256 for i in range(16)])
        
        # Use the same key but different implementations
        unprotected_result = self.unprotected_aes.encrypt_with_blinding(test_data)
        protected_result = self.protected_aes.encrypt_with_blinding(test_data)
        
        # The functional result should be the same (both should correctly encrypt)
        # but the protected one should be using blinding internally
        print("\nTesting blinding countermeasure:")
        print(f"Unprotected result: {unprotected_result.hex()}")
        print(f"Protected result: {protected_result.hex()}")
        
        # For multiple runs with blinding, the protected implementation
        # should show different intermediate values each time
        intermediate_results = []
        for _ in range(5):
            # Run the blinding multiple times and check intermediate values
            # This is a simplified test - in reality, you'd need to trace the
            # internal execution to see the different intermediate values
            result = self.protected_aes.encrypt_with_blinding(test_data)
            intermediate_results.append(result)
            
        # Even with blinding, the final result should be deterministic for the same input
        for result in intermediate_results[1:]:
            self.assertEqual(result, intermediate_results[0], 
                           "Blinding should not affect the final result")
    
    def test_additional_countermeasures(self):
        """Test additional countermeasure techniques."""
        # Test shuffling
        test_data = bytes([i % 256 for i in range(16)])
        shuffled_results = []
        
        # Run shuffling multiple times and check results
        for _ in range(5):
            result = demonstrate_shuffling(test_data)
            shuffled_results.append(result)
            
        # Each shuffling should produce a different result
        unique_results = set(shuffled_results)
        print(f"\nShuffling produced {len(unique_results)} unique results out of 5 runs")
        self.assertGreater(len(unique_results), 1, 
                          "Shuffling should produce different results each time")
        
        # Test random delays
        delay_times = []
        for _ in range(5):
            execution_time = demonstrate_random_delays()
            delay_times.append(execution_time)
        
        # The execution times should vary
        time_variance = np.var(delay_times)
        print(f"Random delay variance: {time_variance:.6f} seconds²")
        self.assertGreater(time_variance, 0, 
                          "Random delays should produce varying execution times")


if __name__ == '__main__':
    unittest.main()