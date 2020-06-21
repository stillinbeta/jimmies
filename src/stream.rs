use crate::socket::TCP_PROTO;
use pyo3::{conversion::FromPyObject, exceptions::TypeError, PyAny, PyResult};
use std::io::{Read, Write};
use std::mem::ManuallyDrop;
use std::net::TcpStream;

use std::os::unix::io::{FromRawFd, RawFd};

pub struct BorrowedTcpStream(ManuallyDrop<TcpStream>);

impl Read for BorrowedTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for BorrowedTcpStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl FromPyObject<'_> for BorrowedTcpStream {
    fn extract(socket: &PyAny) -> PyResult<Self> {
        let proto: i32 = socket.getattr("proto")?.extract()?;
        if proto != TCP_PROTO {
            return Err(TypeError::py_err("Expected a TCP Socket".to_owned()));
        }
        let fd: i32 = socket.call_method0("fileno")?.extract()?;

        // Safety: If we're being passed a valid socket, `fd` will be a valid socket.
        // TODO(EKF): Assert it's not actually a TcpListener
        let sock = unsafe { TcpStream::from_raw_fd(fd as RawFd) };
        Ok(Self(ManuallyDrop::new(sock)))
    }
}
