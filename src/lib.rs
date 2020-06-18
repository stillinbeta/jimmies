use pyo3::{create_exception, exceptions::TypeError, prelude::*, wrap_pyfunction};
use std::clone::Clone;
use std::net::TcpStream;
use std::os::unix::io::{FromRawFd, RawFd};
use std::sync::Arc;

const TCP_PROTO: i32 = 6;

#[pyclass]
#[derive(Clone, Default)]
struct Context {
    client_cfg: Option<Arc<rustls::ClientConfig>>,
    server_cfg: Option<Arc<rustls::ServerConfig>>,

    cafile: Option<String>,
}

struct TLSError(rustls::TLSError);

impl TLSError {
    fn new(err: rustls::TLSError) -> Self {
        TLSError(err)
    }
}

impl From<TLSError> for PyErr {
    fn from(err: TLSError) -> Self {
        TLSException::py_err(format!("{}", err.0))
    }
}

create_exception!(jimmies, TLSException, pyo3::exceptions::Exception);

impl Context {
    fn make_client_config(&self) -> PyResult<rustls::ClientConfig> {
        let mut cfg = rustls::ClientConfig::new();
        cfg.root_store = rustls_native_certs::load_native_certs().map_err(|(_partial, err)| err)?;
        Ok(cfg)
    }

    // TODO(EKF): handle make_server_config as well

    fn get_client_config(&mut self) -> PyResult<&Arc<rustls::ClientConfig>> {
        if self.client_cfg.is_none() {
            let cfg = self.make_client_config()?;
            self.client_cfg = Some(Arc::new(cfg))
        }
        Ok(self.client_cfg.as_ref().unwrap())
    }

    fn get_server_config(&mut self) -> &Arc<rustls::ServerConfig> {
        self.server_cfg
            .get_or_insert_with(|| Arc::new(rustls::ServerConfig::new(rustls::NoClientAuth::new())))
    }
}

#[pymethods]
impl Context {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    #[args(
        server_side = "false",
        server_hostname = "None",
        do_handshake_on_connect = "true"
    )]
    pub fn wrap_socket(
        &mut self,
        socket: &PyAny,
        server_side: bool,
        server_hostname: Option<&str>,
        do_handshake_on_connect: bool,
    ) -> PyResult<SSLSocket> {
        let proto: i32 = socket.getattr("proto")?.extract()?;
        if proto != TCP_PROTO {
            return Err(TypeError::py_err("Expected a TCP Socket".to_owned()));
        }
        let fd: i32 = socket.call_method0("fileno")?.extract()?;

        let session: Box<dyn rustls::Session> = if server_side {
            Box::new(rustls::ServerSession::new(self.get_server_config()))
        } else {
            let server_hostname = server_hostname.ok_or_else(|| {
                TypeError::py_err("server_hostname required for client".to_owned())
            })?;
            let dnsref = get_nameref(server_hostname)?;
            Box::new(rustls::ClientSession::new(
                self.get_client_config()?,
                dnsref,
            ))
        };

        // Safety: If we're being passed a valid socket, `fd` will be a valid socket.
        // TODO(EKF): Assert it's not actually a TcpListener
        let stream = unsafe { TcpStream::from_raw_fd(fd as RawFd) };

        let mut sock = SSLSocket {
            session,
            sock: Box::new(stream),
        };

        if do_handshake_on_connect {
            sock.do_handshake()?
        }

        Ok(sock)
    }
}

fn get_nameref(name: &str) -> PyResult<webpki::DNSNameRef> {
    webpki::DNSNameRef::try_from_ascii_str(name)
        .map_err(|_| TypeError::py_err(format!("Invalid server hostname {:?}", name)))
}

#[pyclass]
struct SSLSocket {
    session: Box<dyn rustls::Session>,
    sock: Box<TcpStream>,
}

#[pymethods]
impl SSLSocket {
    fn do_handshake(&mut self) -> PyResult<()> {
        while self.session.is_handshaking() {
            // prioritise writes so we don't block
            if self.session.wants_write() {
                eprintln!("doing write");
                self.session.write_tls(&mut self.sock)?;
            } else if self.session.wants_read() {
                eprintln!("doing read");
                self.session.read_tls(&mut self.sock)?;
                self.session.process_new_packets().map_err(TLSError::new)?;
            }
        }

        Ok(())
    }

    fn version(&self) -> Option<String> {
        use rustls::ProtocolVersion::*;

        self.session
            .get_protocol_version()
            .map(|proto| match proto {
                TLSv1_0 => "TLSv1".to_owned(),
                TLSv1_1 => "TLSv1.1".to_owned(),
                TLSv1_2 => "TLSv1.2".to_owned(),
                _ => format!("{:?}", proto),
            })
    }
}

#[pyfunction]
fn create_default_context() -> Context {
    Context::new()
}

#[pymodule]
fn jimmies(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pyfunction!(create_default_context))?;
    m.add_class::<Context>()?;
    m.add_class::<SSLSocket>()?;
    Ok(())
}
