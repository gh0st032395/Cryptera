import os
import sys

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from crypto_core.constants import K_DATA, R_PARITY, PROFILES_INTEGRITY

def test_gui_defaults_match_core():
    # In main_gui.py, the default is set to "Medium"
    # We want to ensure "Medium" in PROFILES_INTEGRITY matches K_DATA/R_PARITY
    
    medium_profile = PROFILES_INTEGRITY["Medium"]
    
    assert K_DATA == medium_profile["k"], f"K_DATA mismatch: {K_DATA} != {medium_profile['k']}"
    assert R_PARITY == medium_profile["r"], f"R_PARITY mismatch: {R_PARITY} != {medium_profile['r']}"
    
    print("UI and Core defaults are aligned!")

if __name__ == "__main__":
    test_gui_defaults_match_core()
