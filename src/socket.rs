use crate::{
    context::Context,
    errors::TLSError,
    stream::{BorrowedTcpListener, BorrowedTcpStream},
};
use pyo3::{
    buffer::PyBuffer,
    exceptions::{NotImplementedError, RuntimeError, TypeError},
    prelude::*,
    types::PyBytes,
};
use rustls::StreamOwned;
use std::os::raw::c_int;

pub const TCP_PROTO: i32 = 6;

enum StreamKind {
    ClientStream(StreamOwned<rustls::ClientSession, BorrowedTcpStream>),
    ServerStream(StreamOwned<rustls::ServerSession, BorrowedTcpStream>),
    ServerListener(rustls::ServerSession, BorrowedTcpListener),
}

#[pyclass()]
pub struct SSLSocket {
    // We can't easily extract this, so just save it for later
    context: Py<Context>,
    fileno: c_int,
    stream: StreamKind,
    server_name: Option<String>,
}

impl SSLSocket {
    pub fn new_client(
        context: Py<Context>,
        fileno: c_int,
        server_name: String,
        session: rustls::ClientSession,
        stream: BorrowedTcpStream,
    ) -> Self {
        Self {
            context,
            fileno,
            server_name: Some(server_name),
            stream: StreamKind::ClientStream(StreamOwned::new(session, stream)),
        }
    }

    pub fn new_server(
        context: Py<Context>,
        fileno: c_int,
        session: rustls::ServerSession,
        listener: BorrowedTcpListener,
    ) -> Self {
        Self {
            context,
            fileno,
            server_name: None,
            stream: StreamKind::ServerListener(session, listener),
        }
    }

    fn new_server_stream(
        context: Py<Context>,
        fileno: c_int,
        session: rustls::ServerSession,
        listener: BorrowedTcpStream,
    ) -> Self {
        Self {
            context,
            fileno,
            server_name: None,
            stream: StreamKind::ServerStream(StreamOwned::new(session, listener)),
        }
    }

    fn rs(&mut self) -> PyResult<(&mut dyn std::io::Read, &mut dyn rustls::Session)> {
        use StreamKind::*;
        match &mut self.stream {
            ClientStream(so) => Ok((&mut so.sock, &mut so.sess)),
            ServerStream(so) => Ok((&mut so.sock, &mut so.sess)),
            ServerListener(_, _) => Err(RuntimeError::py_err("Can't read on listening socket")),
        }
    }

    fn ws(&mut self) -> PyResult<(&mut dyn std::io::Write, &mut dyn rustls::Session)> {
        use StreamKind::*;
        match &mut self.stream {
            ClientStream(so) => Ok((&mut so.sock, &mut so.sess)),
            ServerStream(so) => Ok((&mut so.sock, &mut so.sess)),
            ServerListener(_, _) => Err(RuntimeError::py_err("Can't write on listening socket")),
        }
    }

    fn session(&self) -> &dyn rustls::Session {
        use StreamKind::*;
        match &self.stream {
            ClientStream(so) => &so.sess,
            ServerStream(so) => &so.sess,
            ServerListener(sess, _) => sess,
        }
    }

    fn reader(&mut self) -> PyResult<&mut dyn std::io::Read> {
        use StreamKind::*;
        match &mut self.stream {
            ClientStream(so) => Ok(so),
            ServerStream(so) => Ok(so),
            ServerListener(_, _) => Err(RuntimeError::py_err("Can't read on listening socket")),
        }
    }

    fn writer(&mut self) -> PyResult<&mut dyn std::io::Write> {
        use StreamKind::*;
        match &mut self.stream {
            ClientStream(so) => Ok(so),
            ServerStream(so) => Ok(so),
            ServerListener(_, _) => Err(RuntimeError::py_err("Can't write on listening socket")),
        }
    }
}

#[pymethods]
impl SSLSocket {
    pub fn do_handshake(&mut self) -> PyResult<()> {
        while self.session().is_handshaking() {
            let (w, s) = self.ws()?;
            if s.wants_write() {
                s.write_tls(w)?;
                continue;
            }
            let (r, s) = self.rs()?;
            if s.wants_read() {
                s.read_tls(r)?;
                s.process_new_packets().map_err(TLSError::new)?;
            }
        }
        Ok(())
    }

    fn version(&self) -> Option<String> {
        use rustls::ProtocolVersion::*;

        self.session()
            .get_protocol_version()
            .map(|proto| match proto {
                // Match these to the format Python Expects
                TLSv1_0 => "TLSv1".to_owned(),
                TLSv1_1 => "TLSv1.1".to_owned(),
                TLSv1_2 => "TLSv1.2".to_owned(),
                TLSv1_3 => "TLSv1.3".to_owned(),
                // The default formats for everything else is fine
                _ => format!("{:?}", proto),
            })
    }

    fn recv(&mut self, py: Python, bufsize: usize) -> PyResult<PyObject> {
        let mut buf = vec![0; bufsize];
        let size = self.reader()?.read(&mut buf)?;
        Ok(PyBytes::new(py, &buf[0..size]).to_object(py))
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
            unsafe { std::slice::from_raw_parts_mut(buf.buf_ptr() as *mut u8, buf.len_bytes()) };

        self.reader()?.read(&mut slice).map_err(|e| e.into())
    }

    fn sendall(&mut self, bytes: &[u8]) -> PyResult<()> {
        self.writer()?.write_all(&bytes).map_err(|e| e.into())
    }

    fn send(&mut self, bytes: &[u8]) -> PyResult<usize> {
        self.writer()?.write(&bytes).map_err(|e| e.into())
    }

    fn fileno(&self) -> c_int {
        self.fileno
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
        let sess = self.session();
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

    fn cipher(&self) -> Option<(String, String, usize)> {
        match (self.version(), self.session().get_negotiated_ciphersuite()) {
            (Some(version), Some(cs)) => {
                Some((format!("{:?}", cs.suite), version, cs.enc_key_len * 8))
            }
            _ => None,
        }
    }

    fn compression(&self) -> PyResult<()> {
        Err(NotImplementedError::py_err(
            "rustls does not expose compression information",
        ))
    }

    fn selected_alpn_protocol(&self) -> Option<String> {
        self.session()
            .get_alpn_protocol()
            .map(|v| String::from_utf8_lossy(v).into_owned())
    }

    fn selected_npn_protocol(&mut self) -> Option<String> {
        // rustls doesn't support NPN
        None
    }

    fn accept(&mut self, py: Python) -> PyResult<Self> {
        let listener = if let StreamKind::ServerListener(_, listener) = &self.stream {
            listener
        } else {
            return Err(RuntimeError::py_err("Can't accept on non-listening socket"));
        };

        let (stream, _) = listener.accept()?;
        let mut ctx = self.context.as_ref(py).try_borrow_mut()?;
        let context_py = self.context.clone_ref(py);

        let cfg = ctx.get_server_config();
        let sess = rustls::ServerSession::new(cfg);
        Ok(Self::new_server_stream(
            context_py,
            self.fileno,
            sess,
            stream,
        ))
    }

    #[getter]
    fn server_hostname(&self) -> Option<&String> {
        self.server_name.as_ref()
    }

    #[getter]
    fn context(&self) -> &Py<Context> {
        &self.context
    }
}
