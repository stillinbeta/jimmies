mod context;
mod errors;
mod socket;
mod stream;

use crate::context::Context;

use pyo3::{prelude::*, wrap_pyfunction};
// Just for docs
pub use errors::TLSError;
pub use socket::SSLSocket;

#[pyfunction(cafile = "None", capath = "None", cadata = "None")]
fn create_default_context(
    py: Python,
    cafile: Option<String>,
    capath: Option<String>,
    cadata: Option<PyObject>,
) -> PyResult<Context> {
    Context::new(py, cafile, capath, cadata)
}

#[pymodule]
fn jimmies(py: Python, m: &PyModule) -> PyResult<()> {
    // TODO(EKF)
    // stderrlog::new().verbosity(6).init().unwrap();

    m.add_wrapped(wrap_pyfunction!(create_default_context))?;
    m.add_class::<context::Context>()?;
    m.add_class::<socket::SSLSocket>()?;
    m.add("TLSException", py.get_type::<errors::TLSException>())?;
    Ok(())
}
