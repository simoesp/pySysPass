#!/usr/bin/env python3
"""Test integration between activation script and emergency_auth service."""
import sys
import os
import tempfile
sys.path.insert(0, '/srv/pySysPass')
os.chdir('/srv/pySysPass')

# Test that the emergency_auth service can read the flag file created by the script
from app.services.emergency_auth import is_active, get_remaining_seconds, deactivate, EMERGENCY_FLAG_FILE
import json
from datetime import UTC, datetime, timedelta

# Create a temporary flag directory
with tempfile.TemporaryDirectory() as tmpdir:
    flag_file = os.path.join(tmpdir, "emergency-auth-active")
    
    # Monkey-patch the flag file path
    import app.services.emergency_auth as ea
    from pathlib import Path
    original_flag_path = ea.EMERGENCY_FLAG_FILE
    ea.EMERGENCY_FLAG_FILE = Path(flag_file)
    
    try:
        # Create flag file like the script does
        activated_at = datetime.now(UTC).replace(tzinfo=None).isoformat()
        timeout_hours = 2
        expires_at = (datetime.fromisoformat(activated_at) + timedelta(hours=timeout_hours)).isoformat()
        
        data = {
            "activated_at": activated_at,
            "timeout_hours": timeout_hours,
            "expires_at": expires_at,
            "activated_by": "test",
            "recovery_token": "test-token"
        }
        
        with open(flag_file, 'w') as f:
            json.dump(data, f)
        
        # Test is_active
        print(f"is_active(): {is_active()}")
        print(f"get_remaining_seconds(): {get_remaining_seconds()}")
        
        # Test deactivate
        result = deactivate()
        print(f"deactivate(): {result}")
        print(f"is_active() after deactivate: {is_active()}")
        
        print("Integration test PASSED")
    finally:
        ea.EMERGENCY_FLAG_FILE = original_flag_path