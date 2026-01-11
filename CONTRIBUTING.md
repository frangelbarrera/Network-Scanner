# Contributing to Network Scanner

Thank you for your interest in contributing to Network Scanner! This document provides guidelines and information for contributors.

## 🤝 How to Contribute

### Reporting Bugs

1. Check existing issues to avoid duplicates
2. Use the bug report template
3. Include detailed reproduction steps
4. Provide system information and logs

### Suggesting Features

1. Check if the feature already exists or is planned
2. Use the feature request template
3. Explain the use case and benefits
4. Consider implementation complexity

### Code Contributions

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes following our coding standards
4. Add tests for new functionality
5. Update documentation as needed
6. Commit with clear messages: `git commit -m 'Add amazing feature'`
7. Push to your branch: `git push origin feature/amazing-feature`
8. Open a Pull Request

## 🏗️ Development Setup

### Prerequisites

- Python 3.8+
- Node.js 16+
- Git
- Docker (optional)

### Local Development

```bash
# Clone your fork
git clone https://github.com/frangelbarrera/Network-Scanner.git
cd Network-Scanner

# Set up backend
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt  # Development dependencies

# Set up frontend
cd ../frontend
npm install

# Set up CLI
cd ../cli
pip3 install -r requirements.txt
```

### Running Tests

```bash
# Backend tests
cd backend
pytest tests/ -v

# Frontend tests  
cd frontend
npm test

# Linting
flake8 backend/
eslint frontend/src/
```

## 📋 Coding Standards

### Python (Backend)

- Follow PEP 8 style guide
- Use type hints where appropriate
- Write docstrings for all functions and classes
- Keep functions focused and small
- Use meaningful variable names

```python
def analyze_vulnerabilities(scan_results: List[Dict]) -> Dict[str, Any]:
    """
    Analyze vulnerability scan results and provide recommendations.
    
    Args:
        scan_results: List of vulnerability findings
        
    Returns:
        Dict containing analysis and recommendations
    """
    pass
```

### JavaScript/React (Frontend)

- Use functional components with hooks
- Follow ESLint configuration
- Use meaningful component and variable names
- Add PropTypes or TypeScript types
- Keep components focused and reusable

```javascript
const VulnerabilityCard = ({ vulnerability, onSelect }) => {
  const severityColor = getSeverityColor(vulnerability.severity);
  
  return (
    <Card className={`vulnerability-card ${vulnerability.severity.toLowerCase()}`}>
      {/* Component content */}
    </Card>
  );
};
```

### General Guidelines

- Write clear, self-documenting code
- Add comments for complex logic
- Use consistent naming conventions
- Follow the existing project structure
- Keep commits atomic and well-described

## 🧪 Testing

### Backend Testing

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_scanner.py

# Run with coverage
pytest --cov=modules tests/
```

### Frontend Testing

```bash
# Run all tests
npm test

# Run specific test
npm test Scanner.test.js

# Run with coverage
npm test -- --coverage
```

### Test Guidelines

- Write tests for new features
- Include edge cases and error conditions
- Use descriptive test names
- Mock external dependencies
- Aim for good test coverage

## 📚 Documentation

- Update README.md for significant changes
- Add inline code documentation
- Update API documentation
- Include examples for new features
- Keep documentation current

## 🔒 Security

SecScanX is a security tool, so security considerations are paramount:

### Security Guidelines

1. **Input Validation**: Validate all user inputs
2. **Output Encoding**: Properly encode outputs to prevent XSS
3. **Authentication**: Secure authentication mechanisms
4. **Authorization**: Proper access controls
5. **Sensitive Data**: Handle API keys and credentials securely
6. **Dependencies**: Keep dependencies updated
7. **Logging**: Log security events appropriately

### Reporting Security Issues

If you find a security vulnerability:

1. **DO NOT** open a public issue
2. Email with details
3. Include steps to reproduce
4. Allow time for fixes before disclosure

## 🎯 Priority Areas

We especially welcome contributions in:

- New scanning modules and techniques
- AI/ML improvements for analysis
- Performance optimizations
- Mobile/responsive UI improvements
- Documentation and tutorials
- Testing and quality assurance
- Internationalization

## 📝 Pull Request Process

1. **Pre-PR Checklist**:
   - [ ] Code follows style guidelines
   - [ ] Tests pass locally
   - [ ] Documentation updated
   - [ ] No merge conflicts

2. **PR Description**:
   - Clear title and description
   - Link related issues
   - Describe changes made
   - Include screenshots for UI changes

3. **Review Process**:
   - Automated checks must pass
   - At least one maintainer review
   - Address feedback promptly
   - Squash commits if requested

## 🏷️ Issue Labels

- `bug`: Something isn't working
- `enhancement`: New feature or request
- `documentation`: Documentation improvements
- `good first issue`: Good for newcomers
- `help wanted`: Extra attention needed
- `priority-high`: High priority issues
- `security`: Security-related issues

## 📞 Getting Help

- Join our Discord server
- Check the Wiki for documentation
- Open a discussion for questions
- Tag maintainers in issues when needed

## 📜 Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md). We are committed to providing a welcoming and inclusive environment for all contributors.

## 🎉 Recognition

Contributors will be:
- Added to the CONTRIBUTORS.md file
- Mentioned in release notes
- Given credit in documentation
- Invited to the contributors team (for significant contributions)

## 📄 License

By contributing to Network Scanner, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to Network Scanner! Your efforts help make cybersecurity tools more accessible and effective for everyone.
