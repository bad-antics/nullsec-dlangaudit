# nullsec-dlangaudit 🔍

> **Security Audit Engine** - D language security scanner with compile-time function execution, Design by Contract, and template metaprogramming.

[![D](https://img.shields.io/badge/D-B03931?style=for-the-badge&logo=d&logoColor=white)](https://dlang.org/)
[![Security](https://img.shields.io/badge/Security-Audit-red?style=for-the-badge)](https://github.com/bad-antics)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

## 🎯 Features

| Feature | Description |
|---------|-------------|
| **CTFE Patterns** | Security patterns compiled at compile-time |
| **Design by Contract** | `in`/`out`/`invariant` validation |
| **Template Engine** | Generic reporter with format templates |
| **Ranges & UFCS** | Lazy evaluation and fluent API |
| **Parallel Scanning** | `std.parallelism` for multi-core |
| **@safe/@trusted** | Memory safety attributes |
| **Mixin Templates** | Extensible rule system |
| **Plugin Architecture** | Custom audit modules |

## �� Quick Start

```bash
# Build
dub build

# Scan directory
./dlangaudit /path/to/scan

# With options
./dlangaudit . --format=json --min-severity=High
```

## 🔬 D Language Features

### Compile-Time Function Execution (CTFE)
```d
// Patterns compiled at compile-time
enum CTPattern[] securityPatterns = [
    CTPattern("hardcoded_password", `(?i)password\s*=\s*["'][^"']+["']`, Severity.Critical, "secrets"),
    CTPattern("aws_access_key", `AKIA[0-9A-Z]{16}`, Severity.Critical, "cloud"),
];

// Compile-time regex
template PatternMatcher(CTPattern pattern) {
    enum PatternMatcher = ctRegex!(pattern.pattern);
}
```

### Design by Contract
```d
struct Finding {
    this(string file, size_t line, ...)
    in {
        assert(file.length > 0, "File path cannot be empty");
        assert(line > 0, "Line number must be positive");
    }
    out {
        assert(this.timestamp != SysTime.init, "Timestamp must be set");
    }
    do {
        // Constructor body
    }
}
```

### Class Invariants
```d
class AuditEngine {
    invariant {
        assert(findings !is null || findings.length == 0);
    }
}
```

### @safe/@trusted Attributes
```d
@safe auto getFindings() {
    return findings.sort!((a, b) => a.severity > b.severity);
}

@trusted void scanFile(string filePath) {
    // File I/O requires @trusted
}
```

### Ranges and UFCS
```d
auto criticalFindings = findings
    .filter!(f => f.severity == Severity.Critical)
    .map!(f => f.format())
    .array;
```

### Template-Based Reporter
```d
struct Reporter(OutputFormat) {
    static string generate(Finding[] findings) {
        return OutputFormat.format(findings);
    }
}

// Usage
writeln(Reporter!ConsoleFormat.generate(findings));
writeln(Reporter!SarifFormat.generate(findings));
```

## 📊 Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| Console | `--format=console` | Colored terminal output |
| JSON | `--format=json` | Machine-readable JSON |
| SARIF | `--format=sarif` | CI/CD integration |

## 🔐 Security Patterns

- **Secrets**: Hardcoded passwords, API keys, AWS credentials
- **Injection**: SQL injection, command injection, eval usage
- **Crypto**: Weak hashing (MD5/SHA1), insecure random
- **Traversal**: Path traversal patterns
- **Config**: Debug flags, insecure settings

## 🛠️ Build

```bash
# Debug build
dub build

# Release with optimizations
dub build --build=release

# Run tests
dub test
```

## 📜 License

MIT License - [@bad-antics](https://github.com/bad-antics)

---

[![GitHub](https://img.shields.io/badge/GitHub-bad--antics-181717?style=flat&logo=github&logoColor=white)](https://github.com/bad-antics)
[![X/Twitter](https://img.shields.io/badge/Twitter-AnonAntics-1DA1F2?style=flat&logo=x&logoColor=white)](https://x.com/AnonAntics)
