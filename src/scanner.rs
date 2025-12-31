use crate::attacks::{SecurityReport, TestResult, Status};
use crate::error::CddError;
use crate::ScanScope;
use reqwest::Client;
use std::time::Duration;

/// Executes a targeted audit suite based on direct parameters from the DSL parser
pub async fn run_targeted_audit(target_url: &str, scope: ScanScope) -> Result<SecurityReport, CddError> {
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    let mut report = SecurityReport {
        target: target_url.to_string(),
        tests: Vec::new(),
    };

    if target_url.is_empty() {
        return Err(CddError::InternalError("Target is empty".to_string()));
    }

    // Perform an initial query to fetch headers for analysis
    let response = client.get(target_url).send().await?;
    let headers = response.headers();

    // Group 1: KERNEL scope logic
    if scope == ScanScope::Kernel {
        
        // HSTS Check
        let mut hsts = TestResult {
            name: "HSTS: Strict Transport Security".to_string(),
            status: Status::Secure,
            description: "HSTS header is properly configured.".to_string(),
        };
        if !headers.contains_key("strict-transport-security") {
            hsts.status = Status::Vulnerable;
            hsts.description = "HSTS header is missing (MITM risk).".to_string();
        }
        report.tests.push(hsts);

        // Permissive CORS Policy Check
        let cors_attack = client.get(target_url)
            .header("Origin", "https://evil.com")
            .send().await?;

        let mut cors_test = TestResult {
            name: "Gateway: Permissive CORS Policy".to_string(),
            status: Status::Secure,
            description: "CORS policy rejects unknown origins.".to_string(),
        };
        if let Some(allow_origin) = cors_attack.headers().get("access-control-allow-origin") {
            if allow_origin == "*" || allow_origin == "https://evil.com" {
                cors_test.status = Status::Vulnerable;
                cors_test.description = "CORS policy is permissive.".to_string();
            }
        }
        report.tests.push(cors_test);
    }

    // Group 2: TERRITORY scope logic
    if scope == ScanScope::Territory {
        let env_url = format!("{}/.env", target_url.trim_end_matches('/'));
        let env_check = client.get(&env_url).send().await?;

        let mut env_test = TestResult {
            name: "Business: Sensitive File Exposure (.env)".to_string(),
            status: Status::Secure,
            description: "No .env file detected.".to_string(),
        };
        if env_check.status().is_success() {
            env_test.status = Status::Vulnerable;
            env_test.description = "CRITICAL: .env file is accessible.".to_string();
        }
        report.tests.push(env_test);
    }

    Ok(report)
}