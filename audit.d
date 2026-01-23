/**
 * nullsec-dlangaudit - Security Audit Engine
 * 
 * D language security audit framework leveraging:
 * - Compile-time function execution (CTFE)
 * - Ranges and lazy evaluation
 * - @safe/@trusted/@system attributes
 * - Templates and mixins
 * - Unified function call syntax (UFCS)
 * - Contract programming (in/out/invariant)
 */
module nullsec.audit;

import std.stdio;
import std.string;
import std.array;
import std.algorithm;
import std.range;
import std.conv;
import std.datetime;
import std.digest.sha;
import std.format;
import std.regex;
import std.json;
import std.file;
import std.path;
import std.parallelism;

// ═══════════════════════════════════════════════════════════════════════════
// COMPILE-TIME SECURITY PATTERNS (CTFE)
// ═══════════════════════════════════════════════════════════════════════════

/// Security pattern compiled at compile-time
struct CTPattern {
    string name;
    string pattern;
    Severity severity;
    string category;
}

/// Severity levels
enum Severity : ubyte {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

/// CTFE: Generate patterns at compile time
enum CTPattern[] securityPatterns = [
    CTPattern("hardcoded_password", `(?i)password\s*=\s*["'][^"']+["']`, Severity.Critical, "secrets"),
    CTPattern("hardcoded_api_key", `(?i)(api[_-]?key|apikey)\s*=\s*["'][^"']+["']`, Severity.Critical, "secrets"),
    CTPattern("aws_access_key", `AKIA[0-9A-Z]{16}`, Severity.Critical, "cloud"),
    CTPattern("private_key", `-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----`, Severity.Critical, "crypto"),
    CTPattern("sql_injection", `(?i)(execute|exec)\s*\(\s*["'].*\$`, Severity.High, "injection"),
    CTPattern("command_injection", `(?i)(system|popen|exec)\s*\(.*\$`, Severity.High, "injection"),
    CTPattern("path_traversal", `\.\./|\.\.\x5c`, Severity.High, "traversal"),
    CTPattern("weak_hash", `(?i)(md5|sha1)\s*\(`, Severity.Medium, "crypto"),
    CTPattern("insecure_random", `(?i)rand\s*\(|random\s*\(`, Severity.Medium, "crypto"),
    CTPattern("debug_enabled", `(?i)debug\s*=\s*(true|1|on)`, Severity.Low, "config"),
    CTPattern("todo_security", `(?i)(TODO|FIXME|XXX).*security`, Severity.Info, "code_quality"),
    CTPattern("eval_usage", `(?i)\beval\s*\(`, Severity.High, "injection"),
];

/// CTFE: Build regex cache at compile time
template PatternMatcher(CTPattern pattern) {
    enum PatternMatcher = ctRegex!(pattern.pattern);
}

// ═══════════════════════════════════════════════════════════════════════════
// AUDIT FINDING WITH CONTRACTS
// ═══════════════════════════════════════════════════════════════════════════

/// Audit finding with Design by Contract
struct Finding {
    string file;
    size_t line;
    size_t column;
    string patternName;
    Severity severity;
    string category;
    string matchedText;
    string context;
    SysTime timestamp;

    /// Contract: Validate finding on construction
    this(string file, size_t line, size_t column, string patternName,
         Severity severity, string category, string matchedText, string context)
    in {
        assert(file.length > 0, "File path cannot be empty");
        assert(line > 0, "Line number must be positive");
        assert(patternName.length > 0, "Pattern name required");
    }
    out {
        assert(this.timestamp != SysTime.init, "Timestamp must be set");
    }
    do {
        this.file = file;
        this.line = line;
        this.column = column;
        this.patternName = patternName;
        this.severity = severity;
        this.category = category;
        this.matchedText = matchedText;
        this.context = context;
        this.timestamp = Clock.currTime();
    }

    /// UFCS-friendly severity color
    @safe pure string severityColor() const {
        final switch (severity) {
            case Severity.Info:     return "\033[36m";  // Cyan
            case Severity.Low:      return "\033[32m";  // Green
            case Severity.Medium:   return "\033[33m";  // Yellow
            case Severity.High:     return "\033[91m";  // Light Red
            case Severity.Critical: return "\033[31m";  // Red
        }
    }

    /// UFCS: Format for display
    string format() const {
        return "%s[%s]\033[0m %s:%d:%d - %s (%s)".format(
            severityColor(), severity, file, line, column, patternName, category
        );
    }

    /// Convert to JSON
    JSONValue toJson() const {
        JSONValue j;
        j["file"] = file;
        j["line"] = line;
        j["column"] = column;
        j["pattern"] = patternName;
        j["severity"] = severity.to!string;
        j["category"] = category;
        j["matched"] = matchedText;
        j["context"] = context;
        j["timestamp"] = timestamp.toISOExtString();
        return j;
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// AUDIT ENGINE WITH TEMPLATES
// ═══════════════════════════════════════════════════════════════════════════

/// Template-based audit engine
class AuditEngine(PatternSet...) {
    private {
        Finding[] findings;
        string[] excludePaths;
        bool parallelMode;
    }

    /// Invariant: Engine state consistency
    invariant {
        assert(findings !is null || findings.length == 0);
    }

    this(bool parallel = true) @safe {
        this.parallelMode = parallel;
        this.findings = [];
        this.excludePaths = [".git", "node_modules", "__pycache__", ".venv"];
    }

    /// Add exclusion pattern
    void exclude(string path) @safe {
        excludePaths ~= path;
    }

    /// Scan a single file - @trusted due to file I/O
    @trusted void scanFile(string filePath) {
        if (excludePaths.any!(ex => filePath.canFind(ex))) {
            return;
        }

        try {
            string content = readText(filePath);
            auto lines = content.splitLines();

            foreach (lineNum, line; lines.enumerate(1)) {
                scanLineWithPatterns(filePath, lineNum, line, lines);
            }
        } catch (Exception e) {
            // Skip unreadable files
        }
    }

    /// Scan line against all patterns using static foreach
    private void scanLineWithPatterns(string filePath, size_t lineNum, 
                                       string line, string[] allLines) {
        static foreach (pattern; securityPatterns) {
            {
                auto matcher = ctRegex!(pattern.pattern);
                auto matches = line.matchAll(matcher);
                
                foreach (m; matches) {
                    auto col = m.pre.length + 1;
                    auto context = getContext(allLines, lineNum);
                    
                    findings ~= Finding(
                        filePath, lineNum, col,
                        pattern.name, pattern.severity,
                        pattern.category, m.hit, context
                    );
                }
            }
        }
    }

    /// Get surrounding context lines
    @safe pure string getContext(const string[] lines, size_t lineNum) {
        auto start = lineNum > 2 ? lineNum - 2 : 1;
        auto end = min(lineNum + 2, lines.length);
        return lines[start - 1 .. end].join("\n");
    }

    /// Scan directory recursively
    @trusted void scanDirectory(string dirPath) {
        auto files = dirEntries(dirPath, SpanMode.depth)
            .filter!(e => e.isFile)
            .filter!(e => !excludePaths.any!(ex => e.name.canFind(ex)))
            .map!(e => e.name)
            .array;

        if (parallelMode) {
            foreach (file; parallel(files)) {
                scanFile(file);
            }
        } else {
            files.each!(f => scanFile(f));
        }
    }

    /// Get findings using ranges and UFCS
    @safe auto getFindings() {
        return findings
            .sort!((a, b) => a.severity > b.severity)
            .release();
    }

    /// Filter by severity using ranges
    @safe auto bySeverity(Severity minSeverity) {
        return findings
            .filter!(f => f.severity >= minSeverity)
            .array;
    }

    /// Filter by category
    @safe auto byCategory(string category) {
        return findings
            .filter!(f => f.category == category)
            .array;
    }

    /// Group by category using ranges
    @safe auto groupByCategory() {
        return findings.chunkBy!(f => f.category);
    }

    /// Statistics using fold
    @safe auto statistics() {
        struct Stats {
            size_t total;
            size_t[Severity] bySeverity;
            size_t[string] byCategory;
        }

        return findings.fold!(
            (Stats acc, Finding f) {
                acc.total++;
                acc.bySeverity[f.severity]++;
                acc.byCategory[f.category]++;
                return acc;
            }
        )(Stats.init);
    }

    /// Export to JSON
    @trusted string toJson() {
        JSONValue root;
        root["timestamp"] = Clock.currTime().toISOExtString();
        root["total_findings"] = findings.length;
        
        JSONValue[] items;
        foreach (f; findings) {
            items ~= f.toJson();
        }
        root["findings"] = items;
        
        return root.toPrettyString();
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// MIXIN TEMPLATES FOR EXTENSIBILITY
// ═══════════════════════════════════════════════════════════════════════════

/// Mixin template for custom rule sets
mixin template CustomRules(string ruleName, string pattern, Severity sev) {
    auto scan(string content) {
        auto regex = ctRegex!pattern;
        return content.matchAll(regex);
    }
}

/// Plugin interface for audit modules
interface IAuditPlugin {
    string name() @safe;
    Finding[] audit(string content, string filePath) @safe;
}

/// SQL injection deep scanner plugin
class SqlInjectionPlugin : IAuditPlugin {
    override string name() @safe { return "SQL Injection Scanner"; }

    override Finding[] audit(string content, string filePath) @safe {
        Finding[] results;
        auto lines = content.splitLines();
        
        // Dangerous SQL patterns
        auto patterns = [
            ctRegex!(`(?i)execute\s+immediate`),
            ctRegex!(`(?i)sp_executesql`),
            ctRegex!(`(?i)concat.*select.*from`),
            ctRegex!(`\$\{.*\}.*(?i)(select|insert|update|delete)`),
        ];

        foreach (lineNum, line; lines.enumerate(1)) {
            foreach (pat; patterns) {
                if (auto m = line.matchFirst(pat)) {
                    results ~= Finding(
                        filePath, lineNum, m.pre.length + 1,
                        "sql_injection_deep", Severity.Critical,
                        "injection", m.hit, line
                    );
                }
            }
        }
        return results;
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// REPORTER WITH TEMPLATES
// ═══════════════════════════════════════════════════════════════════════════

/// Generic reporter using templates
struct Reporter(OutputFormat) {
    static string generate(Finding[] findings) {
        return OutputFormat.format(findings);
    }
}

/// Console output format
struct ConsoleFormat {
    static string format(Finding[] findings) {
        auto output = appender!string;
        
        output ~= "\n\033[1;35m╔══════════════════════════════════════════════════════════════╗\033[0m\n";
        output ~= "\033[1;35m║           NULLSEC-DLANGAUDIT SECURITY REPORT                ║\033[0m\n";
        output ~= "\033[1;35m╚══════════════════════════════════════════════════════════════╝\033[0m\n\n";

        foreach (sev; [Severity.Critical, Severity.High, Severity.Medium, Severity.Low, Severity.Info]) {
            auto filtered = findings.filter!(f => f.severity == sev).array;
            if (filtered.length > 0) {
                output ~= "\033[1m[%s] - %d findings\033[0m\n".format(sev, filtered.length);
                foreach (f; filtered) {
                    output ~= "  %s\n".format(f.format());
                }
                output ~= "\n";
            }
        }

        return output.data;
    }
}

/// SARIF output format for CI/CD
struct SarifFormat {
    static string format(Finding[] findings) {
        JSONValue sarif;
        sarif["version"] = "2.1.0";
        sarif["$schema"] = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";
        
        JSONValue run;
        run["tool"]["driver"]["name"] = "nullsec-dlangaudit";
        run["tool"]["driver"]["version"] = "1.0.0";
        
        JSONValue[] results;
        foreach (f; findings) {
            JSONValue result;
            result["ruleId"] = f.patternName;
            result["level"] = f.severity >= Severity.High ? "error" : 
                             f.severity >= Severity.Medium ? "warning" : "note";
            result["message"]["text"] = "Security issue: " ~ f.patternName;
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = f.file;
            result["locations"][0]["physicalLocation"]["region"]["startLine"] = f.line;
            results ~= result;
        }
        run["results"] = results;
        sarif["runs"] = [run];
        
        return sarif.toPrettyString();
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN ENTRY POINT
// ═══════════════════════════════════════════════════════════════════════════

void main(string[] args) {
    writeln("\033[1;35m");
    writeln("    ╔═══════════════════════════════════════════════════════════╗");
    writeln("    ║   ██████╗ ██╗      █████╗ ███╗   ██╗ ██████╗              ║");
    writeln("    ║   ██╔══██╗██║     ██╔══██╗████╗  ██║██╔════╝              ║");
    writeln("    ║   ██║  ██║██║     ███████║██╔██╗ ██║██║  ███╗             ║");
    writeln("    ║   ██║  ██║██║     ██╔══██║██║╚██╗██║██║   ██║             ║");
    writeln("    ║   ██████╔╝███████╗██║  ██║██║ ╚████║╚██████╔╝             ║");
    writeln("    ║   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝              ║");
    writeln("    ║                                                           ║");
    writeln("    ║   NULLSEC-DLANGAUDIT v1.0.0                              ║");
    writeln("    ║   Security Audit Engine with CTFE & Contracts            ║");
    writeln("    ╚═══════════════════════════════════════════════════════════╝");
    writeln("\033[0m");

    string targetPath = args.length > 1 ? args[1] : ".";
    string outputFormat = "console";
    Severity minSeverity = Severity.Info;

    // Parse arguments
    foreach (arg; args[2 .. $]) {
        if (arg.startsWith("--format=")) {
            outputFormat = arg["--format=".length .. $];
        } else if (arg.startsWith("--min-severity=")) {
            minSeverity = arg["--min-severity=".length .. $].to!Severity;
        }
    }

    writefln("\033[36m[*] Scanning: %s\033[0m", targetPath);
    writefln("\033[36m[*] Min Severity: %s\033[0m", minSeverity);
    writefln("\033[36m[*] Output Format: %s\033[0m\n", outputFormat);

    // Create engine and scan
    auto engine = new AuditEngine!()();
    
    if (targetPath.isDir) {
        engine.scanDirectory(targetPath);
    } else {
        engine.scanFile(targetPath);
    }

    // Get filtered findings
    auto findings = engine.bySeverity(minSeverity);

    // Output based on format
    switch (outputFormat) {
        case "console":
            writeln(Reporter!ConsoleFormat.generate(findings));
            break;
        case "json":
            writeln(engine.toJson());
            break;
        case "sarif":
            writeln(Reporter!SarifFormat.generate(findings));
            break;
        default:
            writeln(Reporter!ConsoleFormat.generate(findings));
    }

    // Summary statistics
    auto stats = engine.statistics();
    writeln("\033[1;33m═══════════════════════════════════════════════════════════════\033[0m");
    writefln("\033[1;33m SUMMARY: %d total findings\033[0m", stats.total);
    writefln("   Critical: %d | High: %d | Medium: %d | Low: %d | Info: %d",
        stats.bySeverity.get(Severity.Critical, 0),
        stats.bySeverity.get(Severity.High, 0),
        stats.bySeverity.get(Severity.Medium, 0),
        stats.bySeverity.get(Severity.Low, 0),
        stats.bySeverity.get(Severity.Info, 0)
    );
    writeln("\033[1;33m═══════════════════════════════════════════════════════════════\033[0m");
}
