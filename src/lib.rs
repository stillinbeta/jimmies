use cpython::{py_fn, py_module_initializer, PyInt, PyObject, PyResult, Python};
use std::net::TcpStream;
use std::os::{
    raw::c_int,
    unix::io::{FromRawFd, RawFd},
};

struct Context {
    cfg: rustls::ClientConfig,
}

impl Context {
    fn new() -> Self {
        Self {
            cfg: rustls::ClientConfig::new(),
        }
    }
}

py_module_initializer!(_jimmies, init_jimmies, PyInit__jimmies, |py, m| {
    m.add(py, "__doc__", "Module documentation string")?;
    m.add(py, "run", py_fn!(py, hello(fd: c_int)))?;
    m.add(
        py,
        "create_default_context",
        py_fn!(py, create_default_context()),
    )?;
    Ok(())
});

fn create_default_context(py: Python) -> PyResult<PyObject> {
    let ctx = Context::new();
    Ok(py.None())
}

fn hello(py: Python, fd: c_int) -> PyResult<PyObject> {
    let _fd = unsafe { TcpStream::from_raw_fd(fd as RawFd) };

    Ok(py.None())
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
