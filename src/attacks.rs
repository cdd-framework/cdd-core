use serde::Serialize;

#[derive(Serialize)]
pub struct SecurityReport {
    pub target: String,
    pub tests: Vec<TestResult>,
}

#[derive(Serialize)]
pub struct TestResult {
    pub name: String,
    pub status: Status,
    pub description: String,
}

#[derive(Serialize)]
pub enum Status {
    Secure,
    Vulnerable,
    Warning,
}