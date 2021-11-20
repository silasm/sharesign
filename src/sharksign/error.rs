use std::fmt;
use std::error::Error;
use openssl::error::ErrorStack;
use actix_web::{http, HttpResponse, dev::HttpResponseBuilder, ResponseError};
use serde_json::json;

#[derive(Debug)]
pub enum SharkSignErrorType {
    StringError(String),
    OpensslError(ErrorStack),
}

#[derive(Debug)]
pub struct SharkSignError {
    err: SharkSignErrorType,
    status: http::StatusCode,
}

impl SharkSignError {
    fn with_status(mut self, status: http::StatusCode) -> Self {
        self.status = status;
        self
    }
}

impl fmt::Display for SharkSignError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.err {
            SharkSignErrorType::StringError(e) => write!(f, "Internal Error {}: {}", self.status, e),
            SharkSignErrorType::OpensslError(e) => write!(f, "SSL Error {} : {}", self.status, e),
        }
    }
}

impl From<String> for SharkSignError {
    fn from(result: String) -> SharkSignError {
        SharkSignError {
            err: SharkSignErrorType::StringError(result),
            status: http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl From<&str> for SharkSignError {
    fn from(result: &str) -> SharkSignError {
        SharkSignError {
            err: SharkSignErrorType::StringError(result.to_owned()),
            status: http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl From<ErrorStack> for SharkSignError {
    fn from(result: ErrorStack) -> SharkSignError {
        SharkSignError {
            err: SharkSignErrorType::OpensslError(result),
            status: http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl<T: Into<SharkSignError>> From<(T, http::StatusCode)> for SharkSignError {
    fn from(result: (T, http::StatusCode)) -> SharkSignError {
        match result {
            (err, status) => err.into().with_status(status)
        }
    }
}


impl Error for SharkSignError {}

impl ResponseError for SharkSignError {
    fn status_code(&self) -> http::StatusCode {
        self.status
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponseBuilder::new(self.status_code())
            .json(json!({"error": format!("{}", self)}))
    }
}
