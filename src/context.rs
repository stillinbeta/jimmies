use crate::socket::SSLSocket;
use crate::stream::{BorrowedTcpListener, BorrowedTcpStream};
use pyo3::{
    conversion::AsPyPointer,
    exceptions::{NotImplementedError, TypeError, ValueError},
    prelude::*,
};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

#[derive(Clone)]
enum CaData {
    Bytes(Vec<u8>),
    String(String),
}

#[pyclass]
#[derive(Clone, Default)]
pub struct Context {
    client_cfg: Option<Arc<rustls::ClientConfig>>,
    server_cfg: Option<Arc<rustls::ServerConfig>>,

    cafile: Option<String>,
    capath: Option<String>,
    cadata: Option<CaData>,
}

fn get_nameref(name: &str) -> PyResult<webpki::DNSNameRef> {
    webpki::DNSNameRef::try_from_ascii_str(name)
        .map_err(|_| TypeError::py_err(format!("Invalid server hostname {:?}", name)))
}

impl Context {
    fn get_trust_root(&self) -> PyResult<rustls::RootCertStore> {
        match (&self.cafile, &self.capath, &self.cadata) {
            (Some(cafile), _, _) => {
                let mut cafile = BufReader::new(File::open(cafile)?);
                let mut store = rustls::RootCertStore::empty();
                store.add_pem_file(&mut cafile).map_err(|_| ValueError)?;
                Ok(store)
            }
            (_, Some(_capath), _) => {
                // TODO(EKF)
                Err(NotImplementedError.into())
            }
            (_, _, Some(CaData::Bytes(bytes))) => {
                let mut store = rustls::RootCertStore::empty();
                store
                    .add(&rustls::Certificate(bytes.to_vec()))
                    .map_err(|_| ValueError)?;
                Ok(store)
            }
            (_, _, Some(CaData::String(string))) => {
                let mut cert = BufReader::new(string.as_bytes());
                let mut store = rustls::RootCertStore::empty();
                store.add_pem_file(&mut cert).map_err(|_| ValueError)?;
                Ok(store)
            }

            _ => rustls_native_certs::load_native_certs().map_err(|(_partial, err)| err.into()),
        }
    }

    fn make_client_config(&self) -> PyResult<rustls::ClientConfig> {
        let mut cfg = rustls::ClientConfig::new();
        cfg.root_store = self.get_trust_root()?;
        Ok(cfg)
    }

    pub fn get_client_config(&mut self) -> PyResult<&Arc<rustls::ClientConfig>> {
        if self.client_cfg.is_none() {
            let cfg = self.make_client_config()?;
            self.client_cfg = Some(Arc::new(cfg))
        }
        Ok(self.client_cfg.as_ref().unwrap())
    }

    pub fn get_server_config(&mut self) -> &Arc<rustls::ServerConfig> {
        self.server_cfg
            .get_or_insert_with(|| Arc::new(rustls::ServerConfig::new(rustls::NoClientAuth::new())))
    }

    fn get_py_ref(slf: PyRefMut<Self>) -> Py<Context> {
        // SAFETY: we always know slf is a valid pointer
        // TODO(EKF): there seems like there should be a safe way to do this
        unsafe { Py::from_borrowed_ptr(slf.as_ptr()) }
    }
}

#[pymethods]
impl Context {
    #[new]
    #[args(cafile = "None", capath = "None", cadata = "None")]
    pub fn new(
        py: Python,
        cafile: Option<String>,
        capath: Option<String>,
        cadata: Option<PyObject>,
    ) -> PyResult<Self> {
        let cadata = cadata
            .map(|cadata| {
                cadata
                    // Try to pull out a string
                    .extract(py)
                    .map(CaData::String)
                    .or_else(|_| cadata.extract(py).map(CaData::Bytes)) // Now try pulling out bytes
                    .map_err(|_| ValueError::py_err("Unknown type for cadata"))
            })
            .transpose()?;

        Ok(Self {
            cafile,
            capath,
            cadata,

            ..Self::default()
        })
    }

    #[args(
        server_side = "false",
        server_hostname = "None",
        do_handshake_on_connect = "true"
    )]
    pub fn wrap_socket(
        mut slf: PyRefMut<Self>,
        socket: &PyAny,
        server_side: bool,
        server_hostname: Option<&str>,
        do_handshake_on_connect: bool,
    ) -> PyResult<SSLSocket> {
        let mut sock = if server_side {
            let sess = rustls::ServerSession::new(slf.get_server_config());
            let sock: BorrowedTcpListener = socket.extract()?;
            let fd = sock.fd();
            SSLSocket::new_server(Self::get_py_ref(slf), fd, sess, sock)
        } else {
            let server_hostname = server_hostname.ok_or_else(|| {
                TypeError::py_err("server_hostname required for client".to_owned())
            })?;
            let dnsref = get_nameref(server_hostname)?;
            let sess = rustls::ClientSession::new(slf.get_client_config()?, dnsref);
            let sock: BorrowedTcpStream = socket.extract()?;
            let fd = sock.fd();
            SSLSocket::new_client(
                Self::get_py_ref(slf),
                fd,
                server_hostname.to_owned(),
                sess,
                sock,
            )
        };

        if do_handshake_on_connect {
            sock.do_handshake()?
        }

        Ok(sock)
    }
}
