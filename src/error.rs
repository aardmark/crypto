use std::fmt;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Crypto(String),
}

impl std::error::Error for Error {}

impl From<String> for Error {
    fn from(err: String) -> Self {
        Error::Crypto(err)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{}", e),
            Error::Crypto(e) => write!(f, "{}", e),
        }
    }
}
