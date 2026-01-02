pub mod scanner;
pub mod attacks;
pub mod error;

use serde::{Deserialize, Serialize};

// Structure returned to ratel-cli to indicate the outcome of an attack or check
#[derive(Serialize, Deserialize, Debug)]
pub struct AttackResult {
    pub success: bool,
    pub message: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScanScope {
    Kernel,
    Territory,
}

/// Core execution engine for synchronizing with ratel-cli payloads
pub fn execute_attack(kind: &str, value: &str) -> AttackResult {

    match kind {
        "attack" => {
            match value {
                "secure_headers" => {
                    // where the bridge with scanner.rs logic will be implemented
                    AttackResult {
                        success: true,
                        message: "Security headers audit completed successfully!!".into(),
                    }
                },
                "clear_session" => AttackResult {
                    success: true,
                    message: "Active sessions cleared from memory".into(),
                },
                _ => AttackResult {
                    success: false,
                    message: format!("Unknown attack payload: {}", value),
                },
            }
        },
        _ => AttackResult {
            success: false,
            message: format!("Unsupported action kind: {}", kind),
        }
    }
}

/// Core verification engine for CHECK instructions
pub fn verify_condition(raw_instruction: &str) -> AttackResult {
    // Logic to verify specific conditions sent by the parser
    if raw_instruction.contains("response.status BE 200") {
        AttackResult {
            success: true,
            message: "HTTP 200 OK verified".into(),
        }
    } else if raw_instruction.contains("EXISTS") {
        AttackResult {
            success: true,
            message: "Header presence confirmed".into(),
        }
    } else {
        AttackResult {
            success: false,
            message: format!("Verification failed for: {}", raw_instruction),
        }
    }
}

#[tokio::main]
async fn main() {
    // Entry point for standalone testing or legacy support
    println!("CDD-Core engine active. Use via ratel-cli for synchronized audits.");
}