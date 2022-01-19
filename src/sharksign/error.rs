use anyhow;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SharkSignError {
    #[error("No SignRequest with ID: {0:?}")]
    SignRequestNotFound(super::state::ID),
    #[error("Key recovery error: {0:?}")]
    KeyRecovery(String),
    #[error("Invalid configuration: {0:?}")]
    Config(String),
    #[error("PGP error: {source:?}")]
    Pgp {
        #[from]
        source: anyhow::Error,
    },
    #[error("I/O error: {source:?}")]
    IO {
        #[from]
        source: std::io::Error,
    },
    #[error("Revoking key not listed in cert's revocation_keys")]
    NotRevoker,
    #[error("No revocation containing revoking key's fingerprint")]
    NoRevocation,
    #[error("All revocations by revoker failed signature validation")]
    BadSignatureInRevocation,
    #[error("Unexpected error: {0:?}")]
    Unexpected(String),
}

#[cfg(feature = "http")]
mod impl_responserror {
    use actix_web::{HttpResponse, dev::HttpResponseBuilder, ResponseError};
    use serde_json::json;
    use super::SharkSignError as SSE;
    use actix_web::http::StatusCode as HSC;
    
    impl ResponseError for SSE {
        fn status_code(&self) -> HSC {
            match self {
                SSE::SignRequestNotFound(_) => HSC::NOT_FOUND,
                SSE::Config(_)              => HSC::BAD_REQUEST,
                _                           => HSC::INTERNAL_SERVER_ERROR,
            }
        }
    
        fn error_response(&self) -> HttpResponse {
            HttpResponseBuilder::new(self.status_code())
                .json(json!({"error": format!("{}", self)}))
        }
    }
}
