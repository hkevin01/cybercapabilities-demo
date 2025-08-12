# Reverse Engineering Challenge

This repository includes a practical reverse engineering challenge designed to demonstrate static and dynamic analysis capabilities on a benign C binary.

## 🎯 Challenge Overview

### Objective
Reverse engineer a license validation binary to understand the key generation algorithm and create a working keygen for any username.

### Binary Details
- **Language**: C
- **Compilation**: GCC with analysis-friendly flags
- **Location**: `apps/reverse-engineering/challenge-src/`
- **Artifacts**: `bin/challenge` (with symbols), `bin/challenge-stripped` (stripped)

### Build Configuration
```makefile
# Optimized for reverse engineering training
CFLAGS=-O0 -g -fno-stack-protector -no-pie
```

## 🔍 Analysis Approaches

### Static Analysis

#### Recommended Tools
- **Ghidra**: Free NSA reverse engineering suite
- **Cutter/radare2**: Open source disassembler
- **IDA Free**: Industry standard disassembler
- **objdump/readelf**: Command-line analysis tools

#### Key Functions to Identify
1. **main()**: Entry point and argument parsing
2. **derive_key()**: Core key generation algorithm
3. **checksum()**: Hash function implementation
4. **xor_bytes()**: Simple encryption routine

#### Static Analysis Workflow
```bash
# Build the challenge
make re-build

# Basic binary analysis
file bin/challenge
strings bin/challenge
objdump -d bin/challenge | head -50

# Ghidra analysis
# 1. Create new project
# 2. Import bin/challenge
# 3. Analyze with default settings
# 4. Navigate to main function
```

### Dynamic Analysis

#### Debugging Tools
- **GDB**: GNU debugger with source support
- **ltrace**: Library call tracer
- **strace**: System call tracer
- **Valgrind**: Memory analysis framework

#### Dynamic Analysis Workflow
```bash
# Run with sample inputs
./bin/challenge testuser wrongkey

# Debug with GDB
gdb ./bin/challenge
(gdb) set args testuser wrongkey
(gdb) break main
(gdb) run
(gdb) disas derive_key

# Trace library calls
ltrace ./bin/challenge testuser wrongkey

# Monitor system calls
strace ./bin/challenge testuser wrongkey
```

## 🧩 Algorithm Analysis

### Key Generation Process
1. **Username Checksum**: Calculate hash of input username
2. **Character Selection**: Use modulo operation on alphabet
3. **State Mutation**: XOR and bit rotation for complexity
4. **Final Encoding**: XOR with static key (0x5A)

### Reverse Engineering Steps
1. **Function Identification**: Locate key generation routine
2. **Algorithm Reconstruction**: Understand mathematical operations
3. **Constant Extraction**: Find alphabet string and XOR key
4. **Keygen Implementation**: Recreate algorithm in Python/C

### Expected Findings
```c
// Simplified algorithm structure
uint32_t checksum(const char *username);
void derive_key(const char *user, char *output, size_t len);
void xor_bytes(char *buffer, size_t len, uint8_t key);

// Key constants
const char alphabet[] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const uint8_t XOR_KEY = 0x5A;
```

## 🛠️ Solution Development

### Keygen Implementation
```python
#!/usr/bin/env python3
"""
License keygen for reverse engineering challenge
"""

def checksum(username):
    """Reconstruct the checksum algorithm"""
    h = 5381
    for c in username:
        h = ((h << 5) + h) ^ ord(c)
    return h & 0xFFFFFFFF

def derive_key(username, length=19):
    """Recreate the key derivation process"""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    cs = checksum(username)
    key = []
    
    for i in range(length):
        char = alphabet[(cs + i * 7) % len(alphabet)]
        key.append(char)
        cs ^= (ord(char) + i)
        cs = ((cs << 3) | (cs >> 29)) & 0xFFFFFFFF
    
    return ''.join(key)

def generate_license(username):
    """Generate valid license for username"""
    derived = derive_key(username)
    # Apply XOR encoding (0x5A)
    license_bytes = [ord(c) ^ 0x5A for c in derived]
    return ''.join(chr(b) for b in license_bytes)

# Example usage
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: keygen.py <username>")
        sys.exit(1)
    
    username = sys.argv[1]
    license_key = generate_license(username)
    print(f"License for {username}: {license_key}")
```

### Verification
```bash
# Test the keygen
python3 keygen.py admin
./bin/challenge admin <generated_license>
# Expected: "Welcome, admin! License valid."
```

## 📊 Analysis Documentation

### Deliverables
Create analysis documentation in `apps/reverse-engineering/analysis/`:

1. **Analysis Report**: Methodology, findings, and solution
2. **Function Documentation**: Detailed algorithm description
3. **Tool Screenshots**: Ghidra/IDA analysis views (if permitted)
4. **Keygen Source**: Working implementation with comments

### Sample Report Structure
```markdown
# Reverse Engineering Analysis Report

## Executive Summary
- Challenge completed successfully
- Key generation algorithm reconstructed
- Working keygen implementation created

## Static Analysis Findings
- Binary compiled with debugging symbols
- Three main functions identified: main, derive_key, checksum
- Algorithm uses DJB2 hash with custom mutations

## Dynamic Analysis Results
- GDB debugging revealed algorithm flow
- ltrace showed no external library dependencies
- Memory layout analysis confirmed local variables

## Algorithm Reconstruction
[Detailed technical description]

## Solution Implementation
[Keygen code and validation]
```

## 🎓 Learning Objectives

### Skills Demonstrated
- **Static Analysis**: Disassembly reading and function identification
- **Dynamic Analysis**: Debugging and runtime behavior observation
- **Algorithm Reconstruction**: Mathematical process understanding
- **Tool Proficiency**: Professional RE tool usage

### Security Applications
- **Malware Analysis**: Similar techniques for threat investigation
- **Vulnerability Research**: Understanding binary exploitation
- **License Validation**: Software protection mechanism analysis
- **Protocol Reverse Engineering**: Communication format analysis

## 🔗 Related Documentation

- [Static Analysis (SAST)](SAST-ANALYSIS.md)
- [Secure Development Guide](SECURE-DEVELOPMENT.md)
- [Security Assessment Reports](reports/)
