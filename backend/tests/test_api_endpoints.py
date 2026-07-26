"""
Test 3-Layer Detection API Endpoints
Tests the new `/ransomware/detect-layers` and `/ransomware/monitor-encryption` endpoints
"""

import requests
import json
import os
from datetime import datetime, timezone

# API Base URL
BASE_URL = os.getenv("ACDS_API_BASE_URL", "http://localhost:8000/api/v1")
RANSOMWARE_API = f"{BASE_URL}/ransomware"


def test_layer_status():
    """Test getting status of all 3 detection layers"""
    print('\n' + '='*70)
    print('TEST: GET Detection Layers Status')
    print('='*70)
    
    try:
        response = requests.get(f"{RANSOMWARE_API}/layers/status")
        print(f'Status Code: {response.status_code}')
        print(json.dumps(response.json(), indent=2))
        return response.json()
    except Exception as e:
        print(f'Error: {e}')
        return None


def test_three_layer_detection_with_command():
    """Test 3-layer detection with command input"""
    print('\n' + '='*70)
    print('TEST: 3-Layer Detection with Command (Ransomware-like)')
    print('='*70)
    
    payload = {
        "command": "cmd.exe /c vssadmin delete shadows /all /quiet",
        "process_name": "cmd.exe",
        "process_pid": 5678,
        "source_host": "WORKSTATION-001",
        "user": "attacker@domain.com",
        "file_activities": None
    }
    
    try:
        response = requests.post(f"{RANSOMWARE_API}/detect-layers", json=payload)
        print(f'Status Code: {response.status_code}')
        result = response.json()
        
        if response.status_code == 200:
            print(json.dumps(result, indent=2))
            return result
        else:
            print(f'Error: {result}')
            return None
    except Exception as e:
        print(f'Error: {e}')
        return None


def test_three_layer_detection_with_encryption():
    """Test 3-layer detection with file encryption activity"""
    print('\n' + '='*70)
    print('TEST: 3-Layer Detection with File Encryption Activity')
    print('='*70)
    
    # Simulate ransomware encrypting files
    file_activities = [
        {
            "path": f"C:/Users/Documents/file_{i:04d}.docx",
            "operation": "modify",
            "extension": ".encrypted",
            "process_pid": 5678,
            "process_name": "ransomware.exe",
            "source_host": "WORKSTATION-001"
        }
        for i in range(50)
    ]
    
    payload = {
        "command": None,
        "process_name": "ransomware.exe",
        "process_pid": 5678,
        "source_host": "WORKSTATION-001",
        "user": "attacker@domain.com",
        "file_activities": file_activities
    }
    
    try:
        response = requests.post(f"{RANSOMWARE_API}/detect-layers", json=payload)
        print(f'Status Code: {response.status_code}')
        result = response.json()
        
        if response.status_code == 200:
            print(json.dumps(result, indent=2))
            return result
        else:
            print(f'Error: {result}')
            return None
    except Exception as e:
        print(f'Error: {e}')
        return None


def test_encryption_monitoring():
    """Test direct encryption monitoring endpoint"""
    print('\n' + '='*70)
    print('TEST: Encryption Monitoring (Layer 3 Only)')
    print('='*70)
    
    file_activities = [
        {
            "path": f"C:/Users/Documents/sensitive_data_{i:04d}.xlsx",
            "operation": "modify",
            "extension": ".locked",
            "process_pid": 9999,
            "process_name": "suspicious.exe",
            "source_host": "WORKSTATION-002"
        }
        for i in range(75)
    ]
    
    try:
        response = requests.post(f"{RANSOMWARE_API}/monitor-encryption", json=file_activities)
        print(f'Status Code: {response.status_code}')
        result = response.json()
        
        if response.status_code == 200:
            print(json.dumps(result, indent=2))
            return result
        else:
            print(f'Error: {result}')
            return None
    except Exception as e:
        print(f'Error: {e}')
        return None


def test_benign_activity():
    """Test with benign backup activity (should be filtered as safe)"""
    print('\n' + '='*70)
    print('TEST: Benign Backup Activity (Backup-Safe Filter)')
    print('='*70)
    
    file_activities = [
        {
            "path": "C:/ProgramData/BackupService/backup.bak",
            "operation": "create",
            "extension": ".bak",
            "process_pid": 1234,
            "process_name": "BackupService.exe",
            "source_host": "WORKSTATION-001"
        }
    ]
    
    payload = {
        "command": None,
        "process_name": "BackupService.exe",
        "process_pid": 1234,
        "source_host": "WORKSTATION-001",
        "user": "system",
        "file_activities": file_activities
    }
    
    try:
        response = requests.post(f"{RANSOMWARE_API}/detect-layers", json=payload)
        print(f'Status Code: {response.status_code}')
        result = response.json()
        
        if response.status_code == 200:
            print(json.dumps(result, indent=2))
            return result
        else:
            print(f'Error: {result}')
            return None
    except Exception as e:
        print(f'Error: {e}')
        return None


def main():
    """Run all API endpoint tests"""
    print('\n' + '#'*70)
    print('# 3-LAYER RANSOMWARE DETECTION API ENDPOINT TESTS')
    print('#'*70)
    print(f'API Base URL: {BASE_URL}')
    print('Note: Make sure FastAPI server is running (python main.py)')
    
    # Test layer status first
    status_result = test_layer_status()
    
    if status_result and status_result.get('success'):
        # Test 3-layer detection with command
        test_three_layer_detection_with_command()
        
        # Test 3-layer detection with encryption
        test_three_layer_detection_with_encryption()
        
        # Test encryption monitoring
        test_encryption_monitoring()
        
        # Test benign backup activity
        test_benign_activity()
        
        print('\n' + '#'*70)
        print('# TEST SUITE COMPLETE')
        print('#'*70)
    else:
        print('\nAPI not responding. Make sure the FastAPI server is running.')
        print('Start the server with: python main.py')


if __name__ == '__main__':
    main()
