use serde::Serialize;
use std::fmt;

#[derive(Debug, Serialize)]
#[serde(tag = "code", content = "details")]
pub enum CddError {
    InvalidUrl(String),
    NetworkError(String),
    InternalError(String),
}

// So that CddError can be used as a standard error type
impl fmt::Display for CddError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CddError::InvalidUrl(url) => write!(f, "Invalid URL format: {}", url),
            CddError::NetworkError(msg) => write!(f, "Network error occurred: {}", msg),
            CddError::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl From<reqwest::Error> for CddError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_builder() || err.to_string().contains("invalid URL") {
            CddError::InvalidUrl(err.to_string())
        } else {
            CddError::NetworkError(err.to_string())
        }
    }
}