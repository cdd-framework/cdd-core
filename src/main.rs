mod scanner;
mod attacks;
mod error;

use std::env;
use serde_json::json;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: cdd-core <url>");
        std::process::exit(1);
    }

    let target = &args[1];

    match scanner::run_suite(target).await {
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