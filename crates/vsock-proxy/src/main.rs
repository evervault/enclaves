use clap::{Arg, Command};
use shared::server::Listener;
use std::{net::AddrParseError, num::ParseIntError};
use thiserror::Error;

#[derive(Debug, Error)]
enum VsockParseError {
    #[error(
        "Failed to parse vsock address. Incorrect number of tokens found. Expected 2, Received {0}"
    )]
    InvalidAddress(usize),
    #[error("Failed to parse tokens in vsock address. Expected 2 numeric tokens separated by a colon (CID:PORT) e.g. 1234:8008")]
    TokenParseError(#[from] ParseIntError),
}

#[derive(Debug, Error)]
enum Error {
    #[error("Failed to parse tcp socket address - {0}")]
    TcpParseError(#[from] AddrParseError),
    #[error(transparent)]
    VsockParseError(#[from] VsockParseError),
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Address {
    Vsock(u32, u32),
    Tcp(std::net::SocketAddr),
}

impl Address {
    fn new_tcp_address(addr: &str) -> Result<Self, Error> {
        let socket_addr = addr.parse()?;
        Ok(Self::Tcp(socket_addr))
    }

    fn new_vsock_address(addr: &str) -> Result<Self, Error> {
        let addr_parts: Vec<&str> = addr.split(':').collect();
        if addr_parts.len() != 2 {
            return Err(Error::VsockParseError(VsockParseError::InvalidAddress(
                addr_parts.len(),
            )));
        }

        let parsed_cid = match addr_parts.get(0).unwrap().trim().parse::<u32>() {
            Ok(cid) => cid,
            Err(e) => return Err(Error::VsockParseError(VsockParseError::from(e))),
        };

        let parsed_port = match addr_parts.get(0).unwrap().trim().parse::<u32>() {
            Ok(port) => port,
            Err(e) => return Err(Error::VsockParseError(VsockParseError::from(e))),
        };

        Ok(Self::Vsock(parsed_cid, parsed_port))
    }

    async fn into_listener(self) -> Result<SourceConnection, tokio::io::Error> {
      match self {
        Self::Tcp(tcp_addr) => {
          let listener = tokio::net::TcpListener::bind(tcp_addr).await?;
          Ok(SourceConnection::Tcp(listener))
        },
        Self::Vsock(cid, port) => {
          let listener = tokio_vsock::VsockListener::bind(cid, port)?;
          Ok(SourceConnection::Vsock(listener))
        }
      }
    }

    async fn into_destination_connection(&self) -> Result<Connection, tokio::io::Error> {
      match self {
        Self::Tcp(tcp_addr) => {
          let socket = tokio::net::TcpStream::connect(tcp_addr).await?;
          Ok(Connection::Tcp(socket))
        },
        Self::Vsock(cid, port) => {
          let socket = tokio_vsock::VsockStream::connect(*cid, *port).await?;
          Ok(Connection::Vsock(socket))
        }
      }
    }
}

#[cfg(test)] 
mod test {
  use super::Address;
  use std::net::{SocketAddr, IpAddr, Ipv4Addr};
 
  #[test]
  fn test_tcp_parse() {
    let parse_address = Address::new_tcp_address("127.0.0.1:443");
    let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
    assert_eq!(parse_address.unwrap(), Address::Tcp(socket_addr));
  }

  #[test]
  fn test_vsock_parse() {
    let address = Address::new_vsock_address("3:8008");
    let vsock_addr = Address::Vsock(3, 8008);
    assert_eq!(vsock_addr, address.unwrap());

    let invalid_address = Address::new_vsock_address("3.14:0000");
    assert!(invalid_address.is_err());

    let too_many_tokens = Address::new_vsock_address("3:8008:9999:0000");
    assert!(too_many_tokens.is_err());
  }
}

#[pin_project::pin_project(project = EnumProj)]
enum Connection {
  Tcp(#[pin] tokio::net::TcpStream),
  Vsock(#[pin] tokio_vsock::VsockStream),
}

impl tokio::io::AsyncRead for Connection {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
      let this = self.project();
      match this {
        EnumProj::Tcp(conn) => {
          conn.poll_read(cx, buf)
        },
        EnumProj::Vsock(conn) => {
          conn.poll_read(cx, buf)
        }
      }
    }
}

impl tokio::io::AsyncWrite for Connection {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
      let this = self.project();
      match this {
        EnumProj::Tcp(conn) => {
          conn.poll_write(cx, buf)
        },
        EnumProj::Vsock(conn) => {
          conn.poll_write(cx, buf)
        }
      }
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), std::io::Error>> {
      let this = self.project();
      match this {
        EnumProj::Tcp(conn) => {
          conn.poll_flush(cx)
        },
        EnumProj::Vsock(conn) => {
          conn.poll_flush(cx)
        }
      }
    }

    fn poll_shutdown(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), std::io::Error>> {
      let this = self.project();
      match this {
        EnumProj::Tcp(conn) => {
          conn.poll_shutdown(cx)
        },
        EnumProj::Vsock(conn) => {
          conn.poll_shutdown(cx)
        }
      }
    }
}

enum SourceConnection {
  Tcp(tokio::net::TcpListener),
  Vsock(tokio_vsock::VsockListener),
}

#[async_trait::async_trait]
impl shared::server::Listener for SourceConnection {
    type Connection = Connection;
    type Error = tokio::io::Error;

    async fn accept(&mut self) -> Result<Self::Connection,Self::Error> {
      match self {
        Self::Tcp(tcp_listener) => {
          let (accepted_conn, _socket) = tcp_listener.accept().await?;
          Ok(Connection::Tcp(accepted_conn))
        },
        Self::Vsock(vsock_listener) => {
          let (vsock_conn, _socket) = vsock_listener.accept().await?;
          Ok(Connection::Vsock(vsock_conn))
        }
      }
    }
}

fn main() {
    let matches = Command::new("vsock-proxy")
        .about("A simple proxy to pipe traffic to/from a vsock connection")
        .arg(
            Arg::new("tcp-source")
                .long("tcp-source")
                .help("The tcp source address for the proxy to bind to.")
                .conflicts_with("vsock-source")
                .required(false),
        )
        .arg(
            Arg::new("tcp-destination")
                .long("tcp-dest")
                .help("The tcp destination address for the proxy to forward to.")
                .conflicts_with("vsock-destination")
                .conflicts_with("tcp-source")
                .required(false),
        )
        .arg(
            Arg::new("vsock-source")
                .long("vsock-source")
                .help("The vsock source address for the proxy to bind to.")
                .required(false),
        )
        .arg(
            Arg::new("vsock-destination")
                .long("vsock-dest")
                .help("The vsock destination address for the proxy to forward to.")
                .conflicts_with("vsock-source")
                .required(false),
        )
        .get_matches();

    let tcp_source = matches.get_one::<String>("tcp-source");
    let vsock_source = matches.get_one::<String>("vsock-source");

    if tcp_source.is_none() && vsock_source.is_none() {
        eprintln!("Error: no source address provided. Either tcp-source or vsock-source must be provided.");
        return;
    }

    let tcp_destination = matches.get_one::<String>("tcp-destination");
    let vsock_destination = matches.get_one::<String>("vsock-destination");

    if tcp_destination.is_none() && vsock_destination.is_none() {
        eprintln!("Error: no destination address provided. Either tcp-destination or vsock-destination must be provided.");
        return;
    }

    let parsed_source_address: Result<Address, Error> = tcp_source
        .map(|tcp_addr| Address::new_tcp_address(tcp_addr.as_str()))
        .or_else(|| vsock_source.map(|vsock_addr| Address::new_vsock_address(vsock_addr.as_str())))
        .expect("Infallible: either tcp or vsock source address must exist.");

    let source_address = match parsed_source_address {
        Ok(source_addr) => source_addr,
        Err(e) => {
            eprintln!("Error: {e}");
            return;
        }
    };

    let parsed_destination: Result<Address, Error> = tcp_destination
        .map(|tcp_addr| Address::new_tcp_address(tcp_addr))
        .or_else(|| vsock_source.map(|vsock_addr| Address::new_vsock_address(vsock_addr)))
        .expect("Infallible: either tcp or vsock address must exist");

    let destination_address = match parsed_destination {
        Ok(dest_addr) => dest_addr,
        Err(e) => {
            eprintln!("Error: {e}");
            return;
        }
    };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("Failed to build tokio runtime");

    runtime.block_on(async move {
        let mut source = match source_address.into_listener().await {
            Ok(source_conn) => source_conn,
            Err(e) => {
                eprintln!("Failed to create source connection - {e}");
                return;
            }
        };

        loop {
          let mut accepted_conn = match source.accept().await {
            Ok(source_conn) => source_conn,
            Err(e) => {
              eprintln!("Failed to accept incoming connection - {e}");
              continue;
            }
          };

          let mut destination = match destination_address.into_destination_connection().await {
              Ok(dest_conn) => dest_conn,
              Err(e) => {
                  eprintln!("Failed to create destination connection - {e}");
                  continue;
              }
          };

          if let Err(e) = tokio::io::copy_bidirectional(&mut accepted_conn, &mut destination).await {
              eprintln!("Error piping connections - {e}");
          }
        }

    });
}
