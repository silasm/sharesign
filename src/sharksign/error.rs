use std::fmt;
use anyhow;
use std::error::Error;
use actix_web::{http, HttpResponse, dev::HttpResponseBuilder, ResponseError};
use serde_json::json;

#[derive(Debug)]
pub enum SharkSignErrorType {
    String(String),
    Pgp(anyhow::Error),
    IO(std::io::Error),
}

#[derive(Debug)]
pub struct SharkSignError {
    err: SharkSignErrorType,
    status: http::StatusCode,
}

impl SharkSignError {
    pub fn with_status(mut self, status: http::StatusCode) -> Self {
        self.status = status;
        self
    }
}

impl fmt::Display for SharkSignError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.err {
            SharkSignErrorType::String(e) => write!(f, "Internal Error {}: {}", self.status, e),
            SharkSignErrorType::Pgp(e) => write!(f, "PGP Error {} : {}", self.status, e),
            SharkSignErrorType::IO(e) => write!(f, "I/O Error {} : {}", self.status, e),
        }
    }
}

impl From<String> for SharkSignError {
    fn from(result: String) -> SharkSignError {
        SharkSignError {
            err: SharkSignErrorType::String(result),
            status: http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl From<&str> for SharkSignError {
    fn from(result: &str) -> SharkSignError {
        SharkSignError {
            err: SharkSignErrorType::String(result.to_owned()),
            status: http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl From<anyhow::Error> for SharkSignError {
    fn from(result: anyhow::Error) -> SharkSignError {
        SharkSignError {
            err: SharkSignErrorType::Pgp(result),
            status: http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl From<std::io::Error> for SharkSignError {
    fn from(result: std::io::Error) -> SharkSignError {
        SharkSignError {
            err: SharkSignErrorType::IO(result),
            status: http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl<T: Into<SharkSignError>> From<(T, http::StatusCode)> for SharkSignError {
    fn from(result: (T, http::StatusCode)) -> SharkSignError {
        let (err, status) = result;
        err.into().with_status(status)
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
