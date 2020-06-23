use pyo3::{create_exception, create_exception_type_object, PyErr};

pub struct TLSError(rustls::TLSError);

impl TLSError {
    pub fn new(err: rustls::TLSError) -> Self {
        TLSError(err)
    }
}

impl From<TLSError> for PyErr {
    fn from(err: TLSError) -> Self {
        TLSException::py_err(format!("{}", err.0))
    }
}

create_exception!(jimmies, TLSException, pyo3::exceptions::Exception);
