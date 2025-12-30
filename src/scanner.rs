use crate::attacks::{SecurityReport, TestResult, Status};
use crate::error::CddError;
use crate::{RatelConfig, ScanScope};
use reqwest::Client;
use std::time::Duration;

// Executes the audit suite according to the provided Ratel configuration.
pub async fn run_suite(config: RatelConfig) -> Result<SecurityReport, CddError> {
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    let mut report = SecurityReport {
        target: config.target_url.clone(),
        tests: Vec::new(),
    };

    if config.target_url.is_empty() {
        return Err(CddError::InternalError("Target is empty".to_string()));
    }

    // Perform an initial query to parse the headers (Useful for KERNEL)
    let response = client.get(&config.target_url).send().await?;
    let headers = response.headers();

    // --- RATEL FILTERING LOGIC ---
    // 1. Instruction group: KERNEL
    if config.scopes.contains(&ScanScope::Kernel) {
        
        // TEST 1: X-Powered-By (ID: SRV_LEAK)
        if !config.ignored_rules.contains(&"SRV_LEAK".to_string()) {
            let mut x_powered = TestResult {
                name: "Information Leak: X-Powered-By".to_string(),
                status: Status::Secure,
                description: "No X-Powered-By header detected.".to_string(),
            };
            if headers.contains_key("x-powered-by") {
                x_powered.status = Status::Warning;
                x_powered.description = "X-Powered-By header is present, leaking server info.".to_string();
            }
            report.tests.push(x_powered);
        }

        // TEST 2: HSTS (ID: HSTS_MISSING)
        if !config.ignored_rules.contains(&"HSTS_MISSING".to_string()) {
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
        }

        // TEST 3: Permissive CORS (ID: CORS_WILD)
        if !config.ignored_rules.contains(&"CORS_WILD".to_string()) {
            let cors_attack = client.get(&config.target_url)
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
    }

    // 2. Instruction group: TERRITORY
    if config.scopes.contains(&ScanScope::Territory) {
        
        // TEST 4: Sensitive File Exposure (ID: MANIFEST_EXPOSURE)
        if !config.ignored_rules.contains(&"MANIFEST_EXPOSURE".to_string()) {
            let env_url = format!("{}/.env", config.target_url.trim_end_matches('/'));
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
    }

    Ok(report)
}