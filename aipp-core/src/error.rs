//! Errors with a kind, so the broker can map each one to the right IRC
//! numeric without guessing from a string.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// bad syntax
    Syntax,
    /// the command needs an identity first
    NotAuthenticated,
    /// the identity is present but lacks the right
    Forbidden,
    Auth,
    RateLimited,
    NoSuchTarget,
    /// the peer is not draining its output
    Backpressure,
    /// frame/payload problem
    Frame,
    UnknownCommand,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AippError {
    pub kind: ErrorKind,
    pub message: String,
}

impl AippError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// The IRC-style numeric the broker answers with.
    pub fn numeric(&self) -> u16 {
        match self.kind {
            ErrorKind::Syntax => 461,
            ErrorKind::NotAuthenticated => 464,
            ErrorKind::Forbidden => 482,
            ErrorKind::Auth => 464,
            ErrorKind::RateLimited => 439,
            ErrorKind::NoSuchTarget => 401,
            ErrorKind::Backpressure => 509,
            ErrorKind::Frame => 409,
            ErrorKind::UnknownCommand => 421,
        }
    }
}

impl fmt::Display for AippError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for AippError {}
