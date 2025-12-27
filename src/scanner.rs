use crate::attacks::{SecurityReport, TestResult, Status};
use reqwest::Client;
use std::time::Duration;

pub async fn run_suite(target: &str) -> Result<SecurityReport, reqwest::Error> {
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    let mut report = SecurityReport {
        target: target.to_string(),
        tests: Vec::new(),
    };

    let responses = client.get(target).send().await?;
    let headers = responses.headers();

    // --- TEST 1: X-Powered-By (Information Leak) ---
    let mut x_powered = TestResult {
        name: "Information Leak: X-Powered-By".to_string(),
        status: Status::Secure,
        description: "No X-Powered-By header detected.".to_string(),
    };

    if headers.contains_key("x-powered-by") {
        x_powered.status = Status::Warning;
        x_powered.description = "X-Powered-By header is present, which may leak server information.".to_string();
    }

    report.tests.push(x_powered);

    // --- TEST 2: HSTS (Strict Transport Security) ---
    let mut hsts = TestResult {
        name: "HSTS: Strict Transport Security".to_string(),
        status: Status::Secure,
        description: "HSTS header is properly configured.".to_string(),
    };

    if !headers.contains_key("strict-transport-security") {
        hsts.status = Status::Vulnerable;
        hsts.description = "HSTS header is missing, vulnerable to downgrade attacks (MITM).".to_string();
    }

    report.tests.push(hsts);

    Ok(report)

}