use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
struct DockerFinding {
    file: String,
    line: Option<usize>,
    severity: &'static str,
    category: &'static str,
    issue: String,
    remediation: &'static str,
}

pub async fn run(args: Value) -> Result<String, String> {
    let path_str = args
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required parameter 'path'".to_string())?
        .trim();

    let target_path = Path::new(path_str);
    if !target_path.exists() {
        return Err(format!(
            "Target path '{}' does not exist or is inaccessible",
            path_str
        ));
    }

    let files_to_audit = discover_docker_files(target_path)?;
    if files_to_audit.is_empty() {
        return Err(format!(
            "No Dockerfile or docker-compose files detected in path '{}'",
            path_str
        ));
    }

    let mut findings = Vec::new();
    for file in &files_to_audit {
        audit_file(file, &mut findings)?;
    }

    Ok(format_report(path_str, &files_to_audit, &findings))
}

fn discover_docker_files(path: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    if path.is_file() {
        files.push(path.to_path_buf());
        return Ok(files);
    }

    if path.is_dir() {
        let entries = fs::read_dir(path)
            .map_err(|e| format!("Failed to read directory '{}': {}", path.display(), e))?;

        for entry in entries.flatten() {
            let entry_path = entry.path();
            if entry_path.is_file() {
                let file_name = entry_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("");
                let lower = file_name.to_lowercase();

                if lower == "dockerfile"
                    || lower.starts_with("dockerfile.")
                    || lower.ends_with(".dockerfile")
                    || lower == "docker-compose.yml"
                    || lower == "docker-compose.yaml"
                    || lower == "compose.yml"
                    || lower == "compose.yaml"
                {
                    files.push(entry_path);
                }
            }
        }
    }

    Ok(files)
}

fn audit_file(path: &Path, findings: &mut Vec<DockerFinding>) -> Result<(), String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read file '{}': {}", path.display(), e))?;

    let file_str = path.display().to_string();
    let lower_file = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();

    let is_compose = lower_file.contains("compose")
        || lower_file.ends_with(".yml")
        || lower_file.ends_with(".yaml")
        || content.contains("services:");

    if is_compose {
        audit_compose_content(&file_str, &content, findings);
    } else {
        audit_dockerfile_content(&file_str, &content, findings);
    }

    Ok(())
}

fn audit_dockerfile_content(file: &str, content: &str, findings: &mut Vec<DockerFinding>) {
    let mut last_user: Option<(usize, String)> = None;
    let mut has_healthcheck = false;
    let lines: Vec<&str> = content.lines().collect();

    for (idx, line) in lines.iter().enumerate() {
        let line_num = idx + 1;
        let trimmed = line.trim();

        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }

        let upper = trimmed.to_uppercase();

        // 1. Base Image Tagging (CIS 4.2 / Best Practice)
        if upper.starts_with("FROM ") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                let image = parts[1];
                if image.to_lowercase() != "scratch" {
                    if image.ends_with(":latest") {
                        findings.push(DockerFinding {
                            file: file.to_string(),
                            line: Some(line_num),
                            severity: "MEDIUM",
                            category: "Image Pinning",
                            issue: format!(
                                "Base image '{}' uses mutable ':latest' tag (CIS 4.2)",
                                image
                            ),
                            remediation: "Pin base image to specific semantic version or immutable SHA256 digest (e.g., node:20-alpine@sha256:...).",
                        });
                    } else if !image.contains(':') && !image.contains('@') {
                        findings.push(DockerFinding {
                            file: file.to_string(),
                            line: Some(line_num),
                            severity: "MEDIUM",
                            category: "Image Pinning",
                            issue: format!(
                                "Base image '{}' lacks version tag, implicitly resolving to ':latest'",
                                image
                            ),
                            remediation: "Pin base image version explicitly to ensure reproducible and secure builds.",
                        });
                    }
                }
            }
        }

        // 2. USER directive tracking
        if upper.starts_with("USER ") {
            let user_val = trimmed[5..].trim().to_string();
            last_user = Some((line_num, user_val));
        }

        // 3. Sudo usage in RUN directives
        if upper.starts_with("RUN ") {
            if trimmed.contains("sudo ") || trimmed.contains("sudo\t") {
                findings.push(DockerFinding {
                    file: file.to_string(),
                    line: Some(line_num),
                    severity: "HIGH",
                    category: "Privilege Escalation",
                    issue: "Insecure 'sudo' execution inside container layer".to_string(),
                    remediation: "Avoid installing sudo in containers. Perform installation steps as root, then switch to a non-privileged USER.",
                });
            }

            // Remote script pipe to shell
            let lower_line = trimmed.to_lowercase();
            if (lower_line.contains("curl") || lower_line.contains("wget"))
                && (lower_line.contains("| sh")
                    || lower_line.contains("| bash")
                    || lower_line.contains("|sh")
                    || lower_line.contains("|bash"))
            {
                findings.push(DockerFinding {
                    file: file.to_string(),
                    line: Some(line_num),
                    severity: "HIGH",
                    category: "Supply Chain",
                    issue: "Remote install script downloaded and piped directly into shell (curl | bash)".to_string(),
                    remediation: "Download script, verify SHA256 checksum against trusted manifest, then execute locally.",
                });
            }
        }

        // 4. ADD vs COPY (CIS 4.9)
        if upper.starts_with("ADD ") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            let src = parts.get(1).unwrap_or(&"");
            let is_tar = src.ends_with(".tar")
                || src.ends_with(".tar.gz")
                || src.ends_with(".tgz")
                || src.ends_with(".tar.bz2")
                || src.ends_with(".tar.xz");

            if !is_tar {
                findings.push(DockerFinding {
                    file: file.to_string(),
                    line: Some(line_num),
                    severity: "MEDIUM",
                    category: "Attack Surface",
                    issue: "Use of 'ADD' directive instead of 'COPY' (CIS 4.9)".to_string(),
                    remediation: "Use 'COPY' directive unless automated tarball extraction from host is explicitly required.",
                });
            }
        }

        // 5. Secrets in ENV/ARG instructions
        if upper.starts_with("ENV ") || upper.starts_with("ARG ") {
            let lower_line = trimmed.to_lowercase();
            if lower_line.contains("password=")
                || lower_line.contains("secret=")
                || lower_line.contains("api_key=")
                || lower_line.contains("token=")
                || lower_line.contains("private_key=")
            {
                findings.push(DockerFinding {
                    file: file.to_string(),
                    line: Some(line_num),
                    severity: "CRITICAL",
                    category: "Credential Leak",
                    issue: "Hardcoded secret or credential token detected in ENV/ARG directive".to_string(),
                    remediation: "Never bake secrets into container images. Use BuildKit secrets mount ('--mount=type=secret') or runtime env.",
                });
            }
        }

        // 6. HEALTHCHECK detection (CIS 4.6)
        if upper.starts_with("HEALTHCHECK ") {
            has_healthcheck = true;
        }
    }

    // Evaluate root user status (CIS 4.1)
    match last_user {
        None => {
            findings.push(DockerFinding {
                file: file.to_string(),
                line: None,
                severity: "HIGH",
                category: "Privilege Management",
                issue: "Missing 'USER' directive. Container defaults to executing as root (UID 0) (CIS 4.1)".to_string(),
                remediation: "Create a dedicated unprivileged user (e.g. 'RUN useradd -r -s /bin/false appuser') and add 'USER appuser'.",
            });
        }
        Some((line_num, user)) => {
            let lower_user = user.to_lowercase();
            if lower_user == "root" || lower_user == "0" || lower_user.starts_with("0:") {
                findings.push(DockerFinding {
                    file: file.to_string(),
                    line: Some(line_num),
                    severity: "HIGH",
                    category: "Privilege Management",
                    issue: format!("Container explicitly configured to run as root ('USER {}') (CIS 4.1)", user),
                    remediation: "Change to a dedicated non-root service account to mitigate container breakout impact.",
                });
            }
        }
    }

    // Evaluate HEALTHCHECK
    if !has_healthcheck {
        findings.push(DockerFinding {
            file: file.to_string(),
            line: None,
            severity: "LOW",
            category: "Health Monitoring",
            issue: "No 'HEALTHCHECK' instruction defined in Dockerfile (CIS 4.6)".to_string(),
            remediation: "Add 'HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:8080/health || exit 1'.",
        });
    }
}

fn audit_compose_content(file: &str, content: &str, findings: &mut Vec<DockerFinding>) {
    let mut has_resource_limits = false;

    for (idx, line) in content.lines().enumerate() {
        let line_num = idx + 1;
        let trimmed = line.trim();

        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }

        // 1. Docker Socket Mount (Critical Container Escape)
        if trimmed.contains("/var/run/docker.sock") {
            findings.push(DockerFinding {
                file: file.to_string(),
                line: Some(line_num),
                severity: "CRITICAL",
                category: "Container Escape",
                issue: "Host Docker daemon socket mounted inside container ('/var/run/docker.sock')".to_string(),
                remediation: "Mounting the Docker socket grants full root host compromise. Remove socket mount or use a secure read-only API proxy.",
            });
        }

        // 2. Privileged Container (CIS 5.4)
        if trimmed.contains("privileged: true") || trimmed.contains("privileged: yes") {
            findings.push(DockerFinding {
                file: file.to_string(),
                line: Some(line_num),
                severity: "CRITICAL",
                category: "Kernel Security",
                issue: "Container running in privileged mode ('privileged: true') (CIS 5.4)".to_string(),
                remediation: "Disable privileged mode. Grant only granular required Linux capabilities via 'cap_add'.",
            });
        }

        // 3. Host Network Mode (CIS 5.9)
        if trimmed.contains("network_mode: \"host\"")
            || trimmed.contains("network_mode: 'host'")
            || trimmed.contains("network_mode: host")
        {
            findings.push(DockerFinding {
                file: file.to_string(),
                line: Some(line_num),
                severity: "HIGH",
                category: "Network Isolation",
                issue: "Container shares host network namespace ('network_mode: host') (CIS 5.9)".to_string(),
                remediation: "Use dedicated user-defined Docker bridge networks to isolate container network interfaces.",
            });
        }

        // 4. Host PID Namespace (CIS 5.12)
        if trimmed.contains("pid: \"host\"")
            || trimmed.contains("pid: 'host'")
            || trimmed.contains("pid: host")
        {
            findings.push(DockerFinding {
                file: file.to_string(),
                line: Some(line_num),
                severity: "HIGH",
                category: "Process Isolation",
                issue: "Container shares host PID namespace ('pid: host') (CIS 5.12)".to_string(),
                remediation: "Remove 'pid: host' to maintain process hierarchy isolation from host processes.",
            });
        }

        // 5. Host IPC Namespace (CIS 5.13)
        if trimmed.contains("ipc: \"host\"")
            || trimmed.contains("ipc: 'host'")
            || trimmed.contains("ipc: host")
        {
            findings.push(DockerFinding {
                file: file.to_string(),
                line: Some(line_num),
                severity: "MEDIUM",
                category: "IPC Isolation",
                issue: "Container shares host IPC namespace ('ipc: host') (CIS 5.13)".to_string(),
                remediation: "Isolate IPC namespace to prevent unauthorized access to host shared memory segments.",
            });
        }

        // 6. Dangerous Capabilities (CIS 5.22)
        if trimmed.contains("cap_add:") {
            let dangerous_caps = [
                "SYS_ADMIN",
                "ALL",
                "NET_ADMIN",
                "SYS_PTRACE",
                "DAC_OVERRIDE",
                "SYS_RAWIO",
            ];
            for cap in dangerous_caps {
                if trimmed.contains(cap) {
                    findings.push(DockerFinding {
                        file: file.to_string(),
                        line: Some(line_num),
                        severity: "HIGH",
                        category: "Linux Capabilities",
                        issue: format!("Dangerous Linux capability granted ('{}') (CIS 5.22)", cap),
                        remediation: "Adopt principle of least privilege: drop all capabilities ('cap_drop: [ALL]') and add only minimal safe capabilities.",
                    });
                }
            }
        } else {
            // Also check items under cap_add (indented list)
            let dangerous_caps = [
                "SYS_ADMIN",
                "ALL",
                "NET_ADMIN",
                "SYS_PTRACE",
                "DAC_OVERRIDE",
                "SYS_RAWIO",
            ];
            for cap in dangerous_caps {
                if (trimmed.starts_with("- ") || trimmed.starts_with("-")) && trimmed.contains(cap)
                {
                    findings.push(DockerFinding {
                        file: file.to_string(),
                        line: Some(line_num),
                        severity: "HIGH",
                        category: "Linux Capabilities",
                        issue: format!("Dangerous Linux capability granted ('{}') (CIS 5.22)", cap),
                        remediation: "Adopt principle of least privilege: drop all capabilities ('cap_drop: [ALL]') and add only minimal safe capabilities.",
                    });
                }
            }
        }

        // 7. Wildcard Port Exposure on Database/Management Ports
        if trimmed.starts_with("- ") || trimmed.starts_with("-") {
            let sensitive_ports = ["5432:", "3306:", "27017:", "6379:", "9200:", "2375:"];
            for port in sensitive_ports {
                if (trimmed.contains("0.0.0.0:")
                    || (!trimmed.contains("127.0.0.1")
                        && trimmed.contains('"')
                        && trimmed.contains(port)))
                    && trimmed.contains(port)
                {
                    findings.push(DockerFinding {
                        file: file.to_string(),
                        line: Some(line_num),
                        severity: "HIGH",
                        category: "Port Exposure",
                        issue: format!("Sensitive database/internal port exposed publicly to 0.0.0.0 ('{}')", port.trim_end_matches(':')),
                        remediation: "Bind sensitive internal services to localhost ('127.0.0.1:port:port') or rely solely on internal Docker network.",
                    });
                }
            }
        }

        // 8. Resource limits tracking
        if trimmed.contains("mem_limit:")
            || trimmed.contains("cpus:")
            || trimmed.contains("limits:")
        {
            has_resource_limits = true;
        }
    }

    if !has_resource_limits {
        findings.push(DockerFinding {
            file: file.to_string(),
            line: None,
            severity: "LOW",
            category: "Resource DoS",
            issue: "No CPU or memory limits configured for container services".to_string(),
            remediation: "Define 'deploy.resources.limits.memory' or 'mem_limit' to prevent resource exhaustion attacks.",
        });
    }
}

fn format_report(target: &str, files: &[PathBuf], findings: &[DockerFinding]) -> String {
    let mut report = String::new();
    report.push_str("# SecLens Infrastructure Security: Docker & Container Audit\n\n");
    report.push_str(&format!("- **Target Path:** `{}`\n", target));
    report.push_str(&format!("- **Audited Files Count:** {}\n", files.len()));
    for f in files {
        report.push_str(&format!("  * `{}`\n", f.display()));
    }
    report.push('\n');

    let crit_count = findings.iter().filter(|f| f.severity == "CRITICAL").count();
    let high_count = findings.iter().filter(|f| f.severity == "HIGH").count();
    let med_count = findings.iter().filter(|f| f.severity == "MEDIUM").count();
    let low_count = findings.iter().filter(|f| f.severity == "LOW").count();
    let total = findings.len();

    let (score, grade) = calculate_docker_score(crit_count, high_count, med_count, low_count);

    report.push_str(&format!(
        "### Security Posture Score: **{} / 100** (Grade: **{}**)\n\n",
        score, grade
    ));

    report.push_str("| Metric | Value |\n");
    report.push_str("| :--- | :---: |\n");
    report.push_str(&format!(
        "| **Critical Vulnerabilities** | `{}` |\n",
        crit_count
    ));
    report.push_str(&format!(
        "| **High Severity Issues** | `{}` |\n",
        high_count
    ));
    report.push_str(&format!(
        "| **Medium Severity Issues** | `{}` |\n",
        med_count
    ));
    report.push_str(&format!(
        "| **Low / Best Practice Findings** | `{}` |\n",
        low_count
    ));
    report.push_str(&format!(
        "| **Total Identified Findings** | `{}` |\n\n",
        total
    ));

    if findings.is_empty() {
        report.push_str("> **PASS: All audited container definitions comply with CIS Docker Benchmark standards.** No root execution, socket mounts, privileged modes, or unpinned images were detected.\n");
        return report;
    }

    report.push_str("### Detailed Security Findings Matrix\n\n");
    report.push_str(
        "| File | Line | Severity | Category | Identified Vulnerability | Remediation Guidance |\n",
    );
    report.push_str("| :--- | :---: | :---: | :--- | :--- | :--- |\n");

    for f in findings {
        let line_str = match f.line {
            Some(l) => l.to_string(),
            None => "-".to_string(),
        };

        let sev_badge = match f.severity {
            "CRITICAL" => "**CRITICAL**",
            "HIGH" => "**HIGH**",
            "MEDIUM" => "MEDIUM",
            _ => "LOW",
        };

        report.push_str(&format!(
            "| `{}` | {} | {} | {} | {} | {} |\n",
            f.file, line_str, sev_badge, f.category, f.issue, f.remediation
        ));
    }

    report.push_str("\n### Executive Hardening Recommendations\n");
    if crit_count > 0 {
        report.push_str("- [P0] **CRITICAL CONTAINER ESCAPE VULNERABILITIES DETECTED:** Immediately remove direct `/var/run/docker.sock` mounts and disable `privileged: true` to prevent full host compromise.\n");
    }
    if high_count > 0 {
        report.push_str("- [P1] **HIGH-RISK CONFIGURATIONS:** Enforce unprivileged user execution (`USER nonroot`), avoid host namespaces (`network_mode: host`, `pid: host`), and restrict public port bindings.\n");
    }
    if med_count > 0 {
        report.push_str("- [P2] **HYGIENE & SUPPLY CHAIN:** Pin all base images to immutable SHA256 digests or exact patch versions, and replace `ADD` with `COPY`.\n");
    }

    report
}

fn calculate_docker_score(crit: usize, high: usize, med: usize, low: usize) -> (u32, &'static str) {
    let mut deduction = 0;
    deduction += crit * 35;
    deduction += high * 20;
    deduction += med * 10;
    deduction += low * 4;

    let score = if deduction >= 100 {
        0
    } else {
        100 - deduction as u32
    };
    let grade = match score {
        95..=100 => "A+",
        85..=94 => "A",
        70..=84 => "B",
        55..=69 => "C",
        40..=54 => "D",
        _ => "F",
    };

    (score, grade)
}
