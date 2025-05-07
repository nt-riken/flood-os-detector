# Development Guidelines

## Code Organization

### Directory Structure
```
flood-os-detector/
├── docs/                  # Documentation
├── results/              # Analysis output
├── main.py              # Main packet capture module
├── analyze.py           # Analysis engine
├── p0f_signatures.py    # P0F signature matching
├── check_lmdb.py        # Database inspection tool
├── pyproject.toml       # Project configuration
└── requirements.txt     # Python dependencies
```

## Critical Rules

### 1. Core Functionality Protection
- DO NOT modify core packet capture logic without approval
- DO NOT change the data storage format (LMDB + MessagePack)
- DO NOT alter the OS detection methods sequence
- DO NOT bypass the standard data flow (Network → Capture → Storage → Analysis)

### 2. Output Format Stability
- DO NOT modify the CSV output format without version update
- DO NOT change field order in reports
- DO NOT remove mandatory fields
- DO NOT add fields without documentation update

### 3. Logging Consistency
- DO NOT change log file names
- DO NOT modify log format structure
- DO NOT remove required log events
- DO NOT create new log files without approval

### 4. Data Flow Protection
- Maintain separation between capture and analysis
- Preserve fingerprint data integrity
- Keep 24-hour expiration for inactive devices
- Maintain 3-10 minute cleanup check interval

## Coding Standards

### Python Style
- Follow PEP 8 guidelines
- Use type hints for all function parameters and return values
- Document all public functions and classes with docstrings
- Use meaningful variable and function names

### Package Management
- ALWAYS use `uv` for Python package management
- DO NOT use pip or other package managers
- Keep dependencies in `pyproject.toml`
- Use `uv pip install` for installing packages
- Use `uv pip freeze` for generating requirements.txt

### Error Handling
- Use try-except blocks for all external operations
- Log errors with appropriate context
- Implement graceful degradation where possible
- Use custom exceptions for specific error cases
- DO NOT use nested try-except blocks as they hide true error sources
- Keep error handling at the appropriate level of abstraction
- Let errors propagate to the appropriate handler rather than catching them too early

### Logging
- Use Python's logging module
- Configure logging with appropriate levels
- Include timestamps in log messages
- Log to both console and file
- Use structured logging for machine-readable output

### Testing
- Write unit tests for all new features
- Include integration tests for critical paths
- Test error conditions and edge cases
- Document test coverage requirements

## Development Process

### Version Control
- Use Git for version control
- Follow feature branch workflow
- Write meaningful commit messages
- Keep commits focused and atomic

### Code Review
- Review all code changes before merging
- Check for:
  - Code style compliance
  - Error handling
  - Performance implications
  - Security considerations
  - Documentation completeness
  - Core functionality protection
  - Output format stability
  - Logging consistency

### Documentation
- Keep documentation up to date
- Document all public APIs
- Include examples in documentation
- Maintain changelog

## Performance Guidelines

### Database Operations
- Use transactions for multiple operations
- Implement proper error handling for database operations
- Monitor database size and performance
- Implement cleanup procedures

### Memory Management
- Use efficient data structures
- Implement proper cleanup of resources
- Monitor memory usage
- Handle large datasets appropriately

### Network Operations
- Implement timeouts for network operations
- Handle network errors gracefully
- Monitor network performance
- Implement retry mechanisms where appropriate

## Security Guidelines

### Data Handling
- Validate all input data
- Sanitize output data
- Implement proper access controls
- Protect sensitive information

### Network Security
- Use secure protocols where possible
- Implement proper authentication
- Monitor for suspicious activity
- Follow security best practices

## Deployment

### Environment Setup
- Use virtual environments
- Document all dependencies
- Specify Python version requirements
- Document system requirements

### Configuration
- Use configuration files
- Document all configuration options
- Implement proper error handling for configuration
- Use environment variables for sensitive data

### Monitoring
- Implement logging
- Monitor system performance
- Track error rates
- Monitor resource usage 