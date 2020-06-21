use crate::{errors::TLSError, stream::BorrowedTcpStream};
use pyo3::types::PyBytes;
use pyo3::{buffer::PyBuffer, exceptions::TypeError, prelude::*};
use rustls::StreamOwned;
use std::mem::ManuallyDrop;
use std::net::TcpStream;

pub const TCP_PROTO: i32 = 6;

#[pyclass()]
pub struct SSLSocket {
    pub stream: Box<dyn Stream>,
}

pub struct ClientStream {
    stream: StreamOwned<rustls::ClientSession, BorrowedTcpStream>,
}

impl ClientStream {
    pub fn new(sess: rustls::ClientSession, socket: BorrowedTcpStream) -> Self {
        Self {
            stream: StreamOwned::new(sess, socket),
        }
    }
}

pub trait Stream {
    fn rs(&mut self) -> (&mut dyn std::io::Read, &mut dyn rustls::Session);
    fn ws(&mut self) -> (&mut dyn std::io::Write, &mut dyn rustls::Session);

    fn session(&mut self) -> &mut dyn rustls::Session {
        self.rs().1
    }
    fn read(&mut self) -> &mut dyn std::io::Read {
        self.rs().0
    }
    fn write(&mut self) -> &mut dyn std::io::Write {
        self.ws().0
    }
}

impl Stream for ClientStream {
    fn rs(&mut self) -> (&mut dyn std::io::Read, &mut dyn rustls::Session) {
        (&mut self.stream.sock, &mut self.stream.sess)
    }
    fn ws(&mut self) -> (&mut dyn std::io::Write, &mut dyn rustls::Session) {
        (&mut self.stream.sock, &mut self.stream.sess)
    }

    fn read(&mut self) -> &mut dyn std::io::Read {
        &mut self.stream
    }

    fn write(&mut self) -> &mut dyn std::io::Write {
        &mut self.stream
    }
}

#[pymethods]
impl SSLSocket {
    pub fn do_handshake(&mut self) -> PyResult<()> {
        while self.stream.session().is_handshaking() {
            let (w, s) = self.stream.ws();
            if s.wants_write() {
                s.write_tls(w)?;
                continue;
            }
            let (r, s) = self.stream.rs();
            if s.wants_read() {
                s.read_tls(r)?;
                s.process_new_packets().map_err(TLSError::new)?;
            }
        }
        Ok(())
    }

    fn version(&mut self) -> Option<String> {
        use rustls::ProtocolVersion::*;

        self.stream
            .session()
            .get_protocol_version()
            .map(|proto| match proto {
                // Match these to the format Python Expects
                TLSv1_0 => "TLSv1".to_owned(),
                TLSv1_1 => "TLSv1.1".to_owned(),
                TLSv1_2 => "TLSv1.2".to_owned(),
                _ => format!("{:?}", proto),
            })
    }

    fn recv(&mut self, py: Python, bufsize: usize) -> PyResult<PyObject> {
        let mut buf = Vec::with_capacity(bufsize);
        self.stream.read().read_exact(&mut buf)?;
        Ok(PyBytes::new(py, &buf).to_object(py))
    }

    fn recv_into(&mut self, py: Python, buf: &PyAny) -> PyResult<usize> {
        let buf = PyBuffer::get(py, buf)?;

        if buf.readonly() {
            return Err(TypeError::py_err("Can't recveive into readonly buffer"));
        }
        if buf.dimensions() != 1 {
            return Err(TypeError::py_err("Only one-dimensional buffers supported"));
        }

        // SAFETY: Python guarantees this slice exists with the given size.
        // Will not be mutated as long as we don't call Python before we release the GIL
        let mut slice: &mut [u8] =
            unsafe { std::slice::from_raw_parts_mut(buf.buf_ptr() as *mut u8, buf.item_size()) };

        self.stream.read().read(&mut slice).map_err(|e| e.into())
    }

    fn sendall(&mut self, bytes: &[u8]) -> PyResult<()> {
        self.stream.write().write_all(&bytes).map_err(|e| e.into())
    }

    fn send(&mut self, bytes: &[u8]) -> PyResult<usize> {
        self.stream.write().write(&bytes).map_err(|e| e.into())
    }

    #[args(len = "1024", buffer = "None")]
    fn read(&mut self, py: Python, len: usize, buffer: Option<&PyAny>) -> PyResult<PyObject> {
        if let Some(buf) = buffer {
            let size = self.recv_into(py, buf)?;
            Ok(size.to_object(py))
        } else {
            self.recv(py, len)
        }
    }

    fn write(&mut self, bytes: &[u8]) -> PyResult<usize> {
        self.send(bytes)
    }

    #[args(binary_form = "false")]
    fn get_peer_cert(&mut self, py: Python, binary_form: bool) -> PyResult<PyObject> {
        let sess = self.stream.session();
        if sess.is_handshaking() {
            return Err(pyo3::exceptions::ValueError::py_err(
                "Handshake not complete",
            ));
        }
        match sess.get_peer_certificates() {
            Some(vec) if !vec.is_empty() => {
                if binary_form {
                    let cert = vec.first().unwrap().clone();
                    Ok(cert.as_ref().to_object(py))
                } else {
                    unimplemented!()
                }
            }
            _ => Ok(py.None()),
        }
    }
}
