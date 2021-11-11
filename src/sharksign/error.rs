use std::fmt;
use std::error::Error;
use openssl::error::ErrorStack;

#[derive(Debug)]
pub enum SharkSignError {
    StringError(String),
    OpensslError(ErrorStack),
}

impl fmt::Display for SharkSignError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SharkSignError::StringError(e) => write!(f, "Internal Error: {}", e),
            SharkSignError::OpensslError(e) => write!(f, "SSL Error: {}", e),
        }
    }
}

impl From<String> for SharkSignError {
    fn from(result: String) -> SharkSignError {
        SharkSignError::StringError(result)
    }
}

impl From<ErrorStack> for SharkSignError {
    fn from(result: ErrorStack) -> SharkSignError {
        SharkSignError::OpensslError(result)
    }
}

impl Error for SharkSignError {}
