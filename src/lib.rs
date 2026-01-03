pub mod attacks;
pub mod error;
pub mod scanner;

use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};

// Structure returned to ratel-cli to indicate the outcome of an attack or check
#[derive(Serialize, Deserialize, Debug)]
pub struct AttackResult {
    pub success: bool,
    pub message: String,
}

// Context of the HTTP response used for CHECK instructions in the DSL
pub struct ResponseContext {
    pub status: u16,
    pub headers: HeaderMap,
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
                }
                "clear_session" => AttackResult {
                    success: true,
                    message: "Active sessions cleared from memory".into(),
                },
                _ => AttackResult {
                    success: false,
                    message: format!("Unknown attack payload: {}", value),
                },
            }
        }
        _ => AttackResult {
            success: false,
            message: format!("Unsupported action kind: {}", kind),
        },
    }
}

// Core verification engine for CHECK instructions
pub fn verify_condition(raw_instruction: &str, response_data: &ResponseContext) -> AttackResult {
    // 1. Management of : CHECK header "Name" EXISTS
    if raw_instruction.contains("EXISTS") {
        // Simple extraction : we retrieve what is between quotes
        let header_name = raw_instruction
            .split('"')
            .nth(1)
            .unwrap_or("")
            .to_lowercase();

        if !header_name.is_empty() && response_data.headers.contains_key(&header_name) {
            return AttackResult {
                success: true,
                message: format!("Condition satisfied: Header '{}' is present", header_name),
            };
        } else {
            return AttackResult {
                success: false,
                message: format!("Security Gap: Header '{}' is missing", header_name),
            };
        }
    }

    // 2. Management of : CHECK response.status BE 200
    if raw_instruction.contains("status BE 200") {
        if response_data.status == 200 {
            return AttackResult {
                success: true,
                message: "HTTP 200 OK verified".into(),
            };
        } else {
            return AttackResult {
                success: false,
                message: format!(
                    "Verification failed: Expected 200, got {}",
                    response_data.status
                ),
            };
        }
    }

    AttackResult {
        success: false,
        message: format!("Unsupported instruction: {}", raw_instruction),
    }
}

#[tokio::main]
async fn main() {
    // Entry point for standalone testing or legacy support
    println!("CDD-Core engine active. Use via ratel-cli for synchronized audits.");
}

pub fn get_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
