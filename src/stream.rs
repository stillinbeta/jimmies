use crate::socket::TCP_PROTO;
use pyo3::{conversion::FromPyObject, exceptions::TypeError, PyAny, PyErr, PyResult};
use std::io::{Read, Write};
use std::mem::ManuallyDrop;
use std::net::TcpListener;
use std::net::TcpStream;
use std::os::raw::c_int;

use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd};

fn get_fd(socket: &PyAny) -> PyResult<c_int> {
    let proto: i32 = socket.getattr("proto")?.extract()?;
    if proto != TCP_PROTO {
        return Err(TypeError::py_err("Expected a TCP Socket".to_owned()));
    }
    Ok(socket.call_method0("fileno")?.extract()?)
}

pub struct BorrowedTcpStream(ManuallyDrop<TcpStream>, c_int);

impl BorrowedTcpStream {
    pub fn fd(&self) -> c_int {
        self.1
    }
}

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

impl Drop for BorrowedTcpStream {
    fn drop(&mut self) {
        // SAFETY: this is the only place we remove the stream and its during drop
        unsafe { ManuallyDrop::take(&mut self.0) }.into_raw_fd();
    }
}

impl FromPyObject<'_> for BorrowedTcpStream {
    fn extract(socket: &PyAny) -> PyResult<Self> {
        let fd = get_fd(socket)?;

        // SAFETY: If we're being passed a valid socket, `fd` will be a valid socket.
        // TODO(EKF): Assert it's not actually a TcpListener
        let sock = unsafe { TcpStream::from_raw_fd(fd as RawFd) };
        Ok(Self(ManuallyDrop::new(sock), fd as c_int))
    }
}

pub struct BorrowedTcpListener(ManuallyDrop<TcpListener>, c_int);

impl BorrowedTcpListener {
    pub fn fd(&self) -> c_int {
        self.1
    }

    pub fn accept(&self) -> PyResult<(BorrowedTcpStream, std::net::SocketAddr)> {
        self.0
            .accept()
            .map(|(sock, addr)| (BorrowedTcpStream(ManuallyDrop::new(sock), self.1), addr))
            .map_err(PyErr::from)
    }
}

impl Drop for BorrowedTcpListener {
    fn drop(&mut self) {
        // SAFETY: this is the only place we remove the stream and its during drop
        unsafe { ManuallyDrop::take(&mut self.0) }.into_raw_fd();
    }
}

impl FromPyObject<'_> for BorrowedTcpListener {
    fn extract(socket: &PyAny) -> PyResult<Self> {
        let fd = get_fd(socket)?;
        // SAFETY: If we're being passed a valid socket, `fd` will be a valid file descriptor.
        // TODO(EKF): Assert it's not actually a TcpStream
        let sock = unsafe { TcpListener::from_raw_fd(fd as RawFd) };
        Ok(Self(ManuallyDrop::new(sock), fd as c_int))
    }
}
