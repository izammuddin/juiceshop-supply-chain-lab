# AI-Enhanced Software Testing Workshop

> **An Educational Framework for Security-Focused AI-Driven Testing**

This workshop demonstrates comprehensive AI-enhanced software testing practices applied to a deliberately vulnerable Flask application. Participants learn security testing, exploit development, and test automation through hands-on exercises.

## 📚 Workshop Contents

### 🎯 Learning Objectives

1. **Write Unit Tests** - Develop comprehensive functional tests for all endpoints
2. **Create Security Tests** - Demonstrate and test security vulnerabilities
3. **Apply AI to Testing** - Generate creative, systematic test cases using AI-enhanced patterns
4. **Document Vulnerabilities** - Understand and explain security flaws in detail
5. **Generate Reports** - Create professional test coverage and vulnerability reports
6. **Automate Testing** - Integrate testing into CI/CD pipelines with GitHub Actions

### 📁 Files Included

```
├── vulnerable_app.py              # Deliberately vulnerable Flask app
├── test_vulnerable_app.py         # Comprehensive test suite (500+ lines)
├── requirements-testing.txt       # Python dependencies
├── .github/workflows/
│   └── test-ai-enhanced.yml      # GitHub Actions automation
└── README.md                      # This file
```

---

## 🚀 Quick Start

### 1. Environment Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements-testing.txt
```

### 2. Run Vulnerable Application

```bash
# Terminal 1
python vulnerable_app.py
# App runs on http://127.0.0.1:5000
```

### 3. Run Test Suite

```bash
# Terminal 2
pytest test_vulnerable_app.py -v
```

### 4. Generate Coverage Report

```bash
pytest test_vulnerable_app.py --cov=vulnerable_app --cov-report=html
# Open htmlcov/index.html in browser
```

---

## 🛡️ Vulnerabilities Demonstrated

### 1. SQL Injection (CWE-89)

**What it is:** User input directly concatenated into SQL queries without parameterization.

**Location:** `/login` endpoint (POST)

**Test Coverage:** 5 test cases

**Example Exploit:**
```bash
curl -X POST http://127.0.0.1:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\'--","password":"anything"}'
```

**Why It's Critical:**
- Allows attackers to bypass authentication
- Can lead to data theft or deletion
- One of OWASP Top 10 vulnerabilities

**Fix (Not Deployed):**
```python
# Use parameterized queries
cur.execute("SELECT ... WHERE username=? AND password=?", (username, password))
```

### 2. Command Injection (CWE-78)

**What it is:** User input directly passed to shell commands without validation.

**Location:** `/ping` endpoint (GET)

**Test Coverage:** 5 test cases

**Example Exploit:**
```bash
curl "http://127.0.0.1:5000/ping?host=127.0.0.1;id"
```

**Why It's Critical:**
- Allows arbitrary command execution
- Attacker can read files, modify system, steal data
- Complete system compromise possible

**Fix (Not Deployed):**
```python
# Use command list instead of shell
subprocess.run(["ping", "-c", "1", host], capture_output=True)
```

### 3. Broken Access Control (CWE-639)

**What it is:** No authentication or authorization checks on user data endpoints.

**Location:** `/users/<int:user_id>` endpoint (GET)

**Test Coverage:** 4 test cases

**Example Exploit:**
```bash
# Access admin user data without login
curl http://127.0.0.1:5000/users/3
```

**Why It's Critical:**
- Users can access other users' private data
- Admin information exposed
- Violates confidentiality principle

**Fix (Not Deployed):**
```python
@require_auth
def get_user(user_id):
    if not is_authorized(current_user, user_id):
        return {"error": "forbidden"}, 403
```

### 4. Cross-Site Scripting (CWE-79)

**What it is:** User input echoed in HTML response without encoding.

**Location:** `/search` endpoint (GET)

**Test Coverage:** 6 test cases

**Example Exploit:**
```bash
curl "http://127.0.0.1:5000/search?q=<script>alert('XSS')</script>"
```

**Why It's Critical:**
- JavaScript executed in victim's browser
- Session hijacking possible
- Phishing attacks easy
- User data theft

**Fix (Not Deployed):**
```python
from markupsafe import escape
safe_term = escape(request.args.get('q', ''))
```

### 5. Hardcoded Secrets (CWE-798)

**What it is:** Secret keys hardcoded in source code.

**Location:** `vulnerable_app.py`, line 25

**Impact:** Session forgery, authentication bypass

**Fix (Not Deployed):**
```python
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
```

### 6. Plaintext Passwords (CWE-256)

**What it is:** Passwords stored without hashing in database.

**Location:** User table initialization

**Impact:** Complete credential compromise on database breach

**Fix (Not Deployed):**
```python
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
```

---

## 🧪 Test Suite Details

### Test Organization (10 Classes, 35+ Tests)

| Class | Purpose | Tests |
|-------|---------|-------|
| `TestBasicEndpoints` | Index endpoint | 2 |
| `TestLoginFunctionality` | Login mechanism | 4 |
| `TestSQLInjectionVulnerability` | SQL injection exploits | 5 |
| `TestAccessControl` | Broken access control | 4 |
| `TestCommandInjectionVulnerability` | Command injection | 5 |
| `TestXSSVulnerability` | XSS attacks | 6 |
| `TestInputValidation` | Input handling | 4 |
| `TestErrorHandling` | Error responses | 3 |
| `TestCrossPlatformSecurity` | Data isolation | 2 |

### Running Specific Tests

```bash
# Run all SQL injection tests
pytest test_vulnerable_app.py::TestSQLInjectionVulnerability -v

# Run specific test
pytest test_vulnerable_app.py::TestSQLInjectionVulnerability::test_sql_injection_bypass_with_comment -v

# Run tests with coverage
pytest test_vulnerable_app.py --cov=vulnerable_app --cov-report=term-missing

# Run tests matching pattern
pytest test_vulnerable_app.py -k "injection" -v
```

---

## 🤖 AI-Enhanced Testing Features

### 1. Systematic Vulnerability Coverage

Tests are organized by vulnerability type, ensuring complete coverage:
- SQL Injection: 5 different payload variations
- Command Injection: 5 different metacharacter techniques
- XSS: 6 different HTML/JavaScript injection vectors

### 2. Edge Case Testing

AI-generated tests cover edge cases:
- Empty inputs
- Extremely long inputs (10,000+ characters)
- Special characters and combinations
- Malformed JSON

### 3. Test Fixture Management

Automatic database setup and teardown:
```python
@pytest.fixture
def client():
    # Fresh database for each test
    # Automatic cleanup after test
```

### 4. Comprehensive Assertions

Tests validate:
- HTTP status codes (200, 400, 401, 404)
- Response JSON structure
- Vulnerability manifestation
- Error messages

---

## 📊 Code Coverage

### Coverage Report

```bash
pytest test_vulnerable_app.py --cov=vulnerable_app --cov-report=html

# View in browser
open htmlcov/index.html
```

### Expected Coverage

- **Endpoints:** 100% (all endpoints tested)
- **Functions:** 95%+ (most code paths covered)
- **Vulnerabilities:** 100% (all intentional flaws demonstrated)

---

## 🚀 Continuous Integration

### GitHub Actions Workflow

**File:** `.github/workflows/test-ai-enhanced.yml`

**Features:**
- Runs on Python 3.9, 3.10, 3.11
- Generates coverage reports
- Performs security scanning with Bandit
- Analyzes each vulnerability type
- Creates artifact artifacts

**Triggers:**
- Push to master/main
- Pull requests
- Manual trigger (`workflow_dispatch`)

### View Workflow Results

1. Go to GitHub repository
2. Click "Actions" tab
3. Select "AI-Enhanced Software Testing" workflow
4. View test results and coverage reports

---

## 📈 Workshop Progression

### Level 1: Understanding Basics
- Run the vulnerable app
- Explore endpoints with curl/Postman
- Read the code and understand flaws

### Level 2: Writing Tests
- Run existing test suite
- Understand test structure
- Write new test cases

### Level 3: Security Testing
- Craft SQL injection payloads
- Test command injection vectors
- Exploit broken access control

### Level 4: Advanced Testing
- Combine multiple vulnerabilities
- Create race condition tests
- Test error handling

### Level 5: Automation
- Set up GitHub Actions
- Integrate with CI/CD
- Create custom workflows

---

## 🎓 Key Learning Points

### 1. Security Vulnerability Patterns
- **SQL Injection:** String concatenation in queries
- **Command Injection:** Unvalidated shell command input
- **XSS:** Unencoded output in HTML
- **Access Control:** Missing authorization checks

### 2. Testing Best Practices
- Test organization by feature and type
- Comprehensive assertion patterns
- Fixture management for setup/teardown
- Parametrized tests for variations

### 3. AI-Enhanced Approach
- Systematic test case generation
- Edge case discovery
- Vulnerability-driven testing
- Coverage-focused approach

### 4. Security Principles
- Defense in depth
- Input validation
- Output encoding
- Principle of least privilege
- Fail securely

---

## 🛠️ Troubleshooting

### Issue: Port 5000 already in use

```bash
# Find process using port
lsof -i :5000

# Kill process
kill -9 <PID>

# Or use different port
python vulnerable_app.py --port 5001
```

### Issue: Database locked

```bash
# Remove existing database
rm workshop.db

# Tests will recreate it
pytest test_vulnerable_app.py
```

### Issue: Tests fail with import errors

```bash
# Ensure you're in virtual environment
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements-testing.txt
```

---

## 📚 Additional Resources

### OWASP References
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

### Testing Frameworks
- [pytest Documentation](https://docs.pytest.org/)
- [pytest-cov Coverage](https://pytest-cov.readthedocs.io/)
- [Flask Testing](https://flask.palletsprojects.com/testing/)

### Security Tools
- [Bandit](https://bandit.readthedocs.io/) - Security linter
- [OWASP ZAP](https://www.zaproxy.org/) - Web security scanner
- [Burp Suite](https://portswigger.net/burp) - Web penetration testing

---

## ✅ Workshop Completion Checklist

- [ ] Set up Python virtual environment
- [ ] Install dependencies from requirements-testing.txt
- [ ] Run vulnerable_app.py successfully
- [ ] Run test_vulnerable_app.py and see all tests pass
- [ ] Generate and review coverage report
- [ ] Manually test SQL injection exploit
- [ ] Manually test command injection exploit
- [ ] Manually test XSS payload
- [ ] Manually verify broken access control
- [ ] Review GitHub Actions workflow
- [ ] Understand all 6 vulnerability types

---

## 🎯 Workshop Outcomes

Upon completion, participants will:

✅ Understand common security vulnerabilities  
✅ Write professional security-focused tests  
✅ Generate test cases using AI-enhanced methods  
✅ Use pytest for comprehensive testing  
✅ Automate testing with GitHub Actions  
✅ Document and communicate vulnerabilities  
✅ Appreciate secure coding practices  

---

## 📝 Notes

### Important Warnings

⚠️ **This is an intentionally vulnerable application for educational purposes ONLY.**

- Do NOT deploy to production
- Do NOT expose to public network
- Do NOT use patterns from this code in real applications
- This is for training and learning only

### Responsible Disclosure

If you find real vulnerabilities:
1. Do NOT publicly disclose
2. Report to vendor privately
3. Allow time for patch
4. Follow responsible disclosure guidelines

---

## 📄 License

This workshop material is provided for educational purposes. The vulnerable application is intentionally flawed for training.

---

## 🤝 Contributing

Suggestions for improvements:
- Additional vulnerability types
- More test cases
- Enhanced documentation
- Automated exploit demonstrations

---

**Created:** September 14, 2026  
**Framework:** pytest + Flask  
**Purpose:** Security Awareness Training  
**Status:** Ready for Deployment ✅  

---

**Happy Testing! 🧪🔒**
