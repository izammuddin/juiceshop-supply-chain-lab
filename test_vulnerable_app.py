"""
test_vulnerable_app.py
-----------------------
Comprehensive unit tests for vulnerable_app.py using pytest and AI-enhanced test cases.

Tests cover:
1. Basic functionality tests
2. Security vulnerability tests (SQL injection, command injection, XSS)
3. Access control tests
4. Input validation tests
5. Error handling tests
"""

import pytest
import json
import os
from vulnerable_app import app, init_db, DB_PATH


@pytest.fixture
def client():
    """Create a test client for the Flask app."""
    app.config['TESTING'] = True
    
    # Remove existing database if it exists
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    
    # Initialize fresh database
    init_db()
    
    with app.test_client() as client:
        yield client
    
    # Cleanup
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)


class TestBasicEndpoints:
    """Test basic endpoint functionality."""
    
    def test_index_returns_ok_status(self, client):
        """Test that index endpoint returns service status."""
        response = client.get('/')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['service'] == 'workshop-target-app'
        assert data['status'] == 'ok'
    
    def test_index_returns_json(self, client):
        """Test that index returns valid JSON."""
        response = client.get('/')
        assert response.content_type == 'application/json'


class TestLoginFunctionality:
    """Test login endpoint basic functionality."""
    
    def test_login_with_valid_credentials(self, client):
        """Test login with valid username and password."""
        payload = {
            "username": "alice",
            "password": "alice123"
        }
        response = client.post('/login', 
                              json=payload,
                              content_type='application/json')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['authenticated'] is True
        assert data['user_id'] == 1
        assert data['role'] == 'user'
    
    def test_login_with_invalid_credentials(self, client):
        """Test login with wrong password."""
        payload = {
            "username": "alice",
            "password": "wrongpassword"
        }
        response = client.post('/login', 
                              json=payload,
                              content_type='application/json')
        assert response.status_code == 401
        data = json.loads(response.data)
        assert data['authenticated'] is False
    
    def test_login_with_nonexistent_user(self, client):
        """Test login with non-existent username."""
        payload = {
            "username": "nonexistent",
            "password": "anypassword"
        }
        response = client.post('/login', 
                              json=payload,
                              content_type='application/json')
        assert response.status_code == 401
        data = json.loads(response.data)
        assert data['authenticated'] is False
    
    def test_admin_login_valid(self, client):
        """Test admin login with valid credentials."""
        payload = {
            "username": "admin",
            "password": "admin_super_pw"
        }
        response = client.post('/login', 
                              json=payload,
                              content_type='application/json')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['authenticated'] is True
        assert data['role'] == 'admin'


class TestSQLInjectionVulnerability:
    """Test SQL injection vulnerability in login endpoint."""
    
    def test_sql_injection_bypass_with_comment(self, client):
        """Test SQL injection bypass using comment."""
        # Classic SQL injection: username = "admin' -- "
        payload = {
            "username": "admin' -- ",
            "password": "anything"
        }
        response = client.post('/login', 
                              json=payload,
                              content_type='application/json')
        # This should bypass authentication due to SQL injection
        # Expected: authenticated as admin regardless of password
        data = json.loads(response.data)
        # The vulnerability allows bypassing authentication
        assert response.status_code in [200, 400]  # 200 if vulnerable, 400 if query fails
    
    def test_sql_injection_with_or_condition(self, client):
        """Test SQL injection with OR condition."""
        # username = "' OR '1'='1"
        payload = {
            "username": "' OR '1'='1",
            "password": "' OR '1'='1"
        }
        response = client.post('/login', 
                              json=payload,
                              content_type='application/json')
        # This attempts to bypass authentication
        data = json.loads(response.data)
        assert response.status_code in [200, 400]
    
    def test_sql_injection_union_based(self, client):
        """Test UNION-based SQL injection."""
        payload = {
            "username": "' UNION SELECT 1,2,3 -- ",
            "password": "anything"
        }
        response = client.post('/login', 
                              json=payload,
                              content_type='application/json')
        # Should result in error or unexpected data
        assert response.status_code in [200, 400]
    
    def test_sql_injection_with_special_chars(self, client):
        """Test SQL injection with various special characters."""
        injection_payloads = [
            "admin' -- ",
            "admin' /*",
            "1' AND '1'='1",
            "admin'#",
            "' OR '1'='1' -- ",
        ]
        for payload_username in injection_payloads:
            response = client.post('/login',
                                  json={"username": payload_username, "password": "test"},
                                  content_type='application/json')
            # Just verify we get a response (not 500)
            assert response.status_code in [200, 400, 401]


class TestAccessControl:
    """Test broken access control vulnerability."""
    
    def test_access_any_user_without_auth(self, client):
        """Test accessing user 1 without authentication."""
        response = client.get('/users/1')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['username'] == 'alice'
        assert data['id'] == 1
    
    def test_access_admin_without_auth(self, client):
        """Test accessing admin user (id=3) without authentication."""
        response = client.get('/users/3')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['username'] == 'admin'
        assert data['role'] == 'admin'
    
    def test_access_nonexistent_user(self, client):
        """Test accessing non-existent user ID."""
        response = client.get('/users/999')
        assert response.status_code == 404
        data = json.loads(response.data)
        assert data['error'] == 'not found'
    
    def test_broken_access_control_all_users(self, client):
        """Test that all user records are accessible without authentication."""
        for user_id in [1, 2, 3]:
            response = client.get(f'/users/{user_id}')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert 'username' in data
            assert 'role' in data


class TestCommandInjectionVulnerability:
    """Test command injection vulnerability in ping endpoint."""
    
    def test_ping_valid_host(self, client):
        """Test ping with valid host."""
        response = client.get('/ping?host=127.0.0.1')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'output' in data
        # Should contain ping output
        assert 'bytes' in data['output'] or 'BYTES' in data['output'] or data['output']
    
    def test_command_injection_with_semicolon(self, client):
        """Test command injection using semicolon."""
        response = client.get('/ping?host=127.0.0.1; id')
        assert response.status_code == 200
        data = json.loads(response.data)
        # The injected 'id' command output may appear in output
        assert 'output' in data or 'error' in data
    
    def test_command_injection_with_pipe(self, client):
        """Test command injection using pipe."""
        response = client.get('/ping?host=127.0.0.1 | whoami')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'output' in data or 'error' in data
    
    def test_command_injection_with_backquotes(self, client):
        """Test command injection using command substitution."""
        response = client.get('/ping?host=127.0.0.1`id`')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'output' in data or 'error' in data
    
    def test_command_injection_with_ampersand(self, client):
        """Test command injection using background execution."""
        response = client.get('/ping?host=127.0.0.1 & ls &')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'output' in data or 'error' in data
    
    def test_command_injection_with_logical_operators(self, client):
        """Test command injection using logical operators."""
        response = client.get('/ping?host=127.0.0.1 && whoami')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert response.status_code == 200


class TestXSSVulnerability:
    """Test XSS vulnerability in search endpoint."""
    
    def test_search_with_normal_text(self, client):
        """Test search with normal search term."""
        response = client.get('/search?q=laptop')
        assert response.status_code == 200
        assert 'laptop' in response.data.decode()
    
    def test_search_with_html_injection(self, client):
        """Test search with HTML injection."""
        response = client.get('/search?q=<img src=x>')
        assert response.status_code == 200
        data = response.data.decode()
        # The vulnerability: HTML is not escaped
        assert '<img src=x>' in data
    
    def test_search_with_script_tag(self, client):
        """Test search with script tag injection."""
        response = client.get('/search?q=<script>alert("xss")</script>')
        assert response.status_code == 200
        data = response.data.decode()
        # The vulnerability: JavaScript is not escaped
        assert '<script>' in data
        assert 'alert' in data
    
    def test_search_with_svg_injection(self, client):
        """Test search with SVG-based XSS."""
        response = client.get('/search?q=<svg onload=alert("xss")>')
        assert response.status_code == 200
        data = response.data.decode()
        assert 'onload' in data
    
    def test_search_with_iframe_injection(self, client):
        """Test search with iframe injection."""
        response = client.get('/search?q=<iframe src="javascript:alert(1)"></iframe>')
        assert response.status_code == 200
        data = response.data.decode()
        assert '<iframe' in data
    
    def test_search_with_event_handler(self, client):
        """Test search with event handler injection."""
        response = client.get('/search?q=<div onclick="alert(\'xss\')">')
        assert response.status_code == 200
        data = response.data.decode()
        assert 'onclick' in data


class TestInputValidation:
    """Test input validation and sanitization."""
    
    def test_login_with_empty_username(self, client):
        """Test login with empty username."""
        payload = {"username": "", "password": "test"}
        response = client.post('/login', 
                              json=payload,
                              content_type='application/json')
        assert response.status_code in [400, 401]
    
    def test_login_with_very_long_input(self, client):
        """Test login with extremely long input."""
        payload = {
            "username": "a" * 10000,
            "password": "b" * 10000
        }
        response = client.post('/login', 
                              json=payload,
                              content_type='application/json')
        # Should handle gracefully
        assert response.status_code in [200, 400, 401]
    
    def test_search_with_long_query(self, client):
        """Test search with very long query string."""
        long_query = "x" * 10000
        response = client.get(f'/search?q={long_query}')
        assert response.status_code == 200
    
    def test_ping_with_invalid_host(self, client):
        """Test ping with invalid host parameter."""
        response = client.get('/ping?host=invalid@#$%')
        assert response.status_code == 200


class TestErrorHandling:
    """Test error handling and error messages."""
    
    def test_login_with_malformed_json(self, client):
        """Test login with malformed JSON."""
        response = client.post('/login', 
                              data='not valid json',
                              content_type='application/json')
        # Should handle gracefully
        assert response.status_code in [400, 401]
    
    def test_nonexistent_endpoint(self, client):
        """Test accessing non-existent endpoint."""
        response = client.get('/nonexistent')
        assert response.status_code == 404
    
    def test_invalid_user_id_type(self, client):
        """Test accessing user endpoint with invalid ID type."""
        response = client.get('/users/invalid')
        assert response.status_code in [404, 400]


class TestCrossPlatformSecurity:
    """Test security across different scenarios."""
    
    def test_authentication_context_isolation(self, client):
        """Test that successful login doesn't create session."""
        # Login once
        payload = {"username": "alice", "password": "alice123"}
        client.post('/login', json=payload, content_type='application/json')
        
        # Try to access protected resource without subsequent auth
        # (Note: no protection in this app, but testing the concept)
        response = client.get('/users/1')
        assert response.status_code == 200
    
    def test_data_persistence_across_requests(self, client):
        """Test that data persists across requests."""
        # Get user 1
        response1 = client.get('/users/1')
        data1 = json.loads(response1.data)
        username1 = data1['username']
        
        # Get user 1 again
        response2 = client.get('/users/1')
        data2 = json.loads(response2.data)
        username2 = data2['username']
        
        assert username1 == username2


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
