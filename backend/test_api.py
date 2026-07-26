"""
API Endpoint Test Script
========================
Tests all API endpoints of the ACDS backend.
Run this after starting the server with: uvicorn main:app --host 0.0.0.0 --port 8000
"""

import requests
import json
import os
import sys

BASE_URL = os.getenv("ACDS_BACKEND_URL", "http://localhost:8000")
API_PREFIX = "/api/v1"

def print_header(title):
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)

def print_result(test_name, passed, details=""):
    status = "PASS" if passed else "FAIL"
    print(f"  {status}: {test_name}")
    if details:
        print(f"         {details}")

def test_health():
    """Test health endpoint"""
    print_header("TEST: Health Endpoint")
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        passed = response.status_code == 200
        print_result("GET /health", passed, f"Status: {response.status_code}")
        if passed:
            data = response.json()
            print(f"         Response: {json.dumps(data, indent=2)[:200]}...")
        return passed
    except requests.exceptions.ConnectionError:
        print_result("Connection", False, f"Server not running at {BASE_URL}")
        return False
    except Exception as e:
        print_result("Health endpoint", False, str(e))
        return False

def test_model_info():
    """Test model info endpoint"""
    print_header("TEST: Model Info Endpoint")
    try:
        response = requests.get(f"{BASE_URL}{API_PREFIX}/threats/model/info", timeout=5)
        passed = response.status_code == 200
        print_result(f"GET {API_PREFIX}/threats/model/info", passed, f"Status: {response.status_code}")
        if passed:
            data = response.json()
            print(f"         Model version: {data.get('model_version', 'N/A')}")
            print(f"         Accuracy: {data.get('metrics', {}).get('accuracy', 0)*100:.2f}%")
        return passed
    except Exception as e:
        print_result("Model info endpoint", False, str(e))
        return False

def test_scan_phishing():
    """Test phishing email scan"""
    print_header("TEST: Scan Phishing Email")
    try:
        payload = {
            "content": "URGENT: Your account has been compromised! Click here to verify: http://malicious-site.com/verify",
            "sender": "security@fake-bank.com"
        }
        response = requests.post(
            f"{BASE_URL}{API_PREFIX}/threats/scan",
            json=payload,
            timeout=10
        )
        passed = response.status_code == 200
        print_result(f"POST {API_PREFIX}/threats/scan (phishing)", passed, f"Status: {response.status_code}")
        if passed:
            data = response.json()
            result = data.get('result', {})
            detection = result.get('pipeline_results', {}).get('detection', {})
            is_phishing = detection.get('is_phishing', False)
            confidence = detection.get('confidence', 0)
            severity = result.get('severity', 'N/A')
            print(f"         Is Phishing: {is_phishing}")
            print(f"         Confidence: {confidence*100:.1f}%")
            print(f"         Severity: {severity}")
            print(f"         Incident ID: {result.get('incident_id', 'N/A')}")
            return is_phishing and confidence > 0.5
        return False
    except Exception as e:
        print_result("Scan phishing", False, str(e))
        return False

def test_scan_safe():
    """Test safe email scan"""
    print_header("TEST: Scan Safe Email")
    try:
        payload = {
            "content": "Hi team, the meeting has been moved to 3pm tomorrow. See you there!",
            "sender": "colleague@company.com"
        }
        response = requests.post(
            f"{BASE_URL}{API_PREFIX}/threats/scan",
            json=payload,
            timeout=10
        )
        passed = response.status_code == 200
        print_result(f"POST {API_PREFIX}/threats/scan (safe)", passed, f"Status: {response.status_code}")
        if passed:
            data = response.json()
            result = data.get('result', {})
            detection = result.get('pipeline_results', {}).get('detection', {})
            is_phishing = detection.get('is_phishing', True)
            confidence = detection.get('confidence', 0)
            print(f"         Is Phishing: {is_phishing}")
            print(f"         Confidence: {confidence*100:.1f}%")
            return not is_phishing
        return False
    except Exception as e:
        print_result("Scan safe", False, str(e))
        return False

def test_scan_with_response():
    """Test full orchestrated scan with response"""
    print_header("TEST: Full Orchestrated Scan")
    try:
        payload = {
            "content": """
            SECURITY ALERT!
            
            Your PayPal account has been suspended due to suspicious activity.
            
            Click here immediately to restore access: http://paypa1-verify.com/login
            
            If you don't act within 24 hours, your account will be permanently closed.
            
            PayPal Security Team
            """,
            "sender": "security@paypa1.com"
        }
        response = requests.post(
            f"{BASE_URL}{API_PREFIX}/threats/scan/respond",
            json=payload,
            timeout=15
        )
        passed = response.status_code == 200
        print_result(f"POST {API_PREFIX}/threats/scan/respond", passed, f"Status: {response.status_code}")
        if passed:
            data = response.json()
            result = data.get('result', {})
            
            # Check for orchestrated response fields
            has_incident = 'incident_id' in result
            has_pipeline = 'pipeline_results' in result
            has_actions = 'actions_taken' in result
            
            print(f"         Incident ID: {result.get('incident_id', 'N/A')}")
            print(f"         Severity: {result.get('severity', 'N/A')}")
            print(f"         Lifecycle State: {result.get('lifecycle_state', 'N/A')}")
            
            if has_pipeline:
                pipeline = result.get('pipeline_results', {})
                detection = pipeline.get('detection', {})
                print(f"         Detection: {detection.get('is_phishing', 'N/A')}")
                print(f"         Confidence: {detection.get('confidence', 0)*100:.1f}%")
                print(f"         Evidence items: {len(pipeline.get('explainability', {}).get('evidence', []))}")
            
            return has_incident and has_pipeline
        return False
    except Exception as e:
        print_result("Full scan", False, str(e))
        return False

def test_explain():
    """Test explainability endpoint"""
    print_header("TEST: Explainability Endpoint")
    try:
        payload = {
            "content": "Click http://evil.com to claim your prize of $1,000,000! Act now before it expires!",
            "sender": "winner@lottery.com"
        }
        response = requests.post(
            f"{BASE_URL}{API_PREFIX}/threats/scan/explain",
            json=payload,
            timeout=10
        )
        passed = response.status_code == 200
        print_result(f"POST {API_PREFIX}/threats/scan/explain", passed, f"Status: {response.status_code}")
        if passed:
            data = response.json()
            explainability = data.get('explainability', {})
            iocs = explainability.get('iocs', {})
            print(f"         URLs found: {iocs.get('urls', [])}")
            print(f"         Keywords: {iocs.get('keywords', [])}")
            print(f"         Evidence count: {len(explainability.get('evidence', []))}")
            # Check if explanation was generated
            has_explanation = len(explainability.get('explanation', '')) > 0
            return has_explanation
        return False
    except Exception as e:
        print_result("Explain", False, str(e))
        return False

def test_stats():
    """Test statistics endpoint"""
    print_header("TEST: Statistics Endpoint")
    try:
        response = requests.get(f"{BASE_URL}{API_PREFIX}/threats/stats", timeout=5)
        passed = response.status_code == 200
        print_result(f"GET {API_PREFIX}/threats/stats", passed, f"Status: {response.status_code}")
        if passed:
            data = response.json()
            print(f"         Total scans: {data.get('total_scans', 0)}")
            print(f"         Phishing detected: {data.get('phishing_detected', 0)}")
        return passed
    except Exception as e:
        print_result("Stats", False, str(e))
        return False

def test_incidents():
    """Test incidents endpoint"""
    print_header("TEST: Incidents Endpoint")
    try:
        response = requests.get(f"{BASE_URL}{API_PREFIX}/threats/incidents", timeout=5)
        passed = response.status_code == 200
        print_result(f"GET {API_PREFIX}/threats/incidents", passed, f"Status: {response.status_code}")
        if passed:
            data = response.json()
            incidents = data.get('incidents', [])
            print(f"         Total incidents: {data.get('total', 0)}")
            if incidents:
                print(f"         Latest incident: {incidents[0].get('incident_id', 'N/A')}")
        return passed
    except Exception as e:
        print_result("Incidents", False, str(e))
        return False

def run_all_tests():
    """Run all API tests"""
    print("\n" + "=" * 60)
    print("  ACDS API ENDPOINT TESTS")
    print("=" * 60)
    print(f"  Testing against: {BASE_URL}")
    
    tests = [
        ("Health Check", test_health),
        ("Model Info", test_model_info),
        ("Scan Phishing Email", test_scan_phishing),
        ("Scan Safe Email", test_scan_safe),
        ("Full Orchestrated Scan", test_scan_with_response),
        ("Explainability", test_explain),
        ("Statistics", test_stats),
        ("Incidents List", test_incidents),
    ]
    
    results = []
    for name, test_func in tests:
        try:
            passed = test_func()
            results.append((name, passed))
        except Exception as e:
            results.append((name, False))
            print(f"  ERROR in {name}: {e}")
    
    # Print summary
    print_header("API TEST SUMMARY")
    
    passed_count = sum(1 for _, p in results if p)
    total_count = len(results)
    
    for name, passed in results:
        status = "PASS" if passed else "FAIL"
        print(f"  {status}: {name}")
    
    print("\n" + "-" * 60)
    print(f"  Total: {passed_count}/{total_count} tests passed")
    
    if passed_count == total_count:
        print("\n  🎉 ALL API TESTS PASSED!")
    else:
        print(f"\n  ⚠️  {total_count - passed_count} test(s) failed.")
    
    print("=" * 60 + "\n")
    
    return passed_count == total_count

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
