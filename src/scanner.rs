use crate::attacks::{SecurityReport, TestResult, Status};
use crate::error::CddError;
use crate::ScanScope;
use reqwest::Client;
use std::time::Duration;

pub async fn run_targeted_audit(target_url: &str, scope: ScanScope) -> Result<SecurityReport, CddError> {
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true) // to scan dev environments
        .user_agent("Ratel-Security-Scanner/1.0 (Cloud Detection & Defense)")
        .build()?;

    let mut report = SecurityReport {
        target: target_url.to_string(),
        tests: Vec::new(),
    };

    if target_url.is_empty() {
        return Err(CddError::InternalError("Target URL is empty".to_string()));
    }

    // Requête initiale pour récupérer les headers
    let response = client.get(target_url).send().await?;
    let headers = response.headers();

    // --- LOGIC SCOPE KERNEL (Header Security) ---
    if scope == ScanScope::Kernel {
        
        // 1. HSTS Check
        let mut hsts = TestResult {
            name: "HSTS: Strict Transport Security".into(),
            status: Status::Secure,
            description: "HSTS header is properly configured.".into(),
        };
        if !headers.contains_key("strict-transport-security") {
            hsts.status = Status::Vulnerable;
            hsts.description = "HSTS header is missing (MITM risk).".into();
        }
        report.tests.push(hsts);

        // 2. Clickjacking Protection
        let mut xfo = TestResult {
            name: "Clickjacking: X-Frame-Options".into(),
            status: Status::Secure,
            description: "Anti-clickjacking protection is active.".into(),
        };
        if !headers.contains_key("x-frame-options") && !headers.contains_key("content-security-policy") {
            xfo.status = Status::Vulnerable;
            xfo.description = "Missing X-Frame-Options or CSP frame-ancestors.".into();
        }
        report.tests.push(xfo);

        // 3. MIME Sniffing
        let mut sniffing = TestResult {
            name: "Hygiene: X-Content-Type-Options".into(),
            status: Status::Secure,
            description: "nosniff directive is present.".into(),
        };
        if let Some(val) = headers.get("x-content-type-options") {
            if val != "nosniff" {
                sniffing.status = Status::Warning;
                sniffing.description = "X-Content-Type-Options is set but not to 'nosniff'.".into();
            }
        } else {
            sniffing.status = Status::Vulnerable;
            sniffing.description = "X-Content-Type-Options is missing.".into();
        }
        report.tests.push(sniffing);

        // 4. Server Version Disclosure (ex: FastAPI/Uvicorn leaks)
        let mut server_info = TestResult {
            name: "Exposure: Server Information Leak".into(),
            status: Status::Secure,
            description: "No sensitive server version details leaked.".into(),
        };
        if let Some(s) = headers.get("server") {
            let s_str = s.to_str().unwrap_or("");
            if s_str.contains('/') || s_str.len() > 10 {
                server_info.status = Status::Warning;
                server_info.description = format!("Server header is too verbose: {}", s_str);
            }
        }
        report.tests.push(server_info);

        // 5. Permissive CORS (Attack simulation)
        let cors_attack = client.get(target_url)
            .header("Origin", "https://attacker-domain.com")
            .send().await?;

        let mut cors_test = TestResult {
            name: "Gateway: Permissive CORS Policy".into(),
            status: Status::Secure,
            description: "CORS policy correctly rejects unknown origins.".into(),
        };
        if let Some(ao) = cors_attack.headers().get("access-control-allow-origin") {
            if ao == "*" || ao == "https://attacker-domain.com" {
                cors_test.status = Status::Vulnerable;
                cors_test.description = "VULNERABLE: CORS policy allows arbitrary origins.".into();
            }
        }
        report.tests.push(cors_test);
    }

    // --- LOGIC SCOPE TERRITORY (Infrastructure Exposure) ---
    if scope == ScanScope::Territory {
        
        let paths_to_check = vec![
            (".env", "Sensitive Environment File"),
            (".git/config", "Git Configuration/Source Leak"),
            ("wp-config.php.bak", "WordPress Backup File"),
            (".aws/credentials", "Cloud Credentials Leak")
        ];

        for (path, label) in paths_to_check {
            let full_url = format!("{}/{}", target_url.trim_end_matches('/'), path);
            let check = client.get(&full_url).send().await?;

            let mut test = TestResult {
                name: format!("Infrastructure: {}", label),
                status: Status::Secure,
                description: format!("No {} detected.", path),
            };

            if check.status().is_success() {
                test.status = Status::Vulnerable;
                test.description = format!("CRITICAL: {} is publicly accessible at {}!", label, full_url);
            }
            report.tests.push(test);
        }
    }

    Ok(report)
}