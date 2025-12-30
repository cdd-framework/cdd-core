mod scanner;
mod attacks;
mod error;

use std::{env, iter::Scan};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScanScope {
    Kernel,
    Territory,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RatelConfig {
    pub target_url: String,
    pub scopes: Vec<ScanScope>,
    pub ignored_rules: Vec<String>,
    pub failure_policy: String,
}


#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: cdd-core <json_config>");
        eprintln!("Example: cdd-core '{{\"target_url\": \"http://example.com\", \"scopes\": [\"KERNEL\"], \"ignored_rules\": [], \"failure_policy\": \"FAIL_BUILD\"}}'");
        std::process::exit(1);
    }

    let config: RatelConfig = match serde_json::from_str(&args[1]) {
        Ok(cfg) => cfg,
        Err(e) => {
            let error_json = json!({
                "error": true,
                "message": format!("Invalid Ratel configuration: {}", e),
                "type": "ConfigError"
            });
            println!("{}", serde_json::to_string(&error_json).unwrap());
            std::process::exit(1);
        }
    };

    match scanner::run_suite(config).await {
        Ok(report) => {
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
        },
        Err(e) => {
            let error_json = json!({
                "error": true,
                "message": format!("{}", e),
                "type": format!("{:?}", e)
            });
            println!("{}", serde_json::to_string_pretty(&error_json).unwrap());
            std::process::exit(0);
        }
    }
}