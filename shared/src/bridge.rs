use crate::server::{error::ServerError, Listener};
use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Debug, Clone, Copy)]
pub enum ContextID {
    Parent,
    Enclave,
}

/// Enum to represent the direction that a client expects to be communicating in used to map to appropriate CIDs.
/// A Client connection with direction of `EnclaveToHost` is sending packets from Enclave to the Host.
/// A Server listener with direction of `EnclaveToHost` is listening in the Enclave to connections from the Host.
#[derive(Debug, Clone, Copy)]
pub enum Direction {
    EnclaveToHost,
    HostToEnclave,
}

impl Direction {
    /// Get the appropriate CID for a VSock connection when listening for connections from the other side of the bridge
    pub fn get_server_cid(&self) -> ContextID {
        match self {
            Self::EnclaveToHost => ContextID::Enclave,
            Self::HostToEnclave => ContextID::Parent,
        }
    }

    /// Get the appropriate CID for a VSock connection when acting as a client connecting to the other side of the bridge
    pub fn get_client_cid(&self) -> ContextID {
        match self {
            Self::EnclaveToHost => ContextID::Parent,
            Self::HostToEnclave => ContextID::Enclave,
        }
    }
}

/// Interface to standardize the API for creating connections between the in-Enclave process and the host process.
/// Standardizes the arguments to open sockets across the bridge.
#[async_trait]
pub trait BridgeInterface {
    type Listener: Listener;
    type ClientConnection: AsyncRead + AsyncWrite;

    /// Open a client connection in the appropriate direction
    async fn get_client_connection(
        port: u16,
        direction: Direction,
    ) -> Result<Self::ClientConnection, ServerError>;

    /// Establish a listener in the appropriate direction
    async fn get_listener(port: u16, direction: Direction) -> Result<Self::Listener, ServerError>;
}

/// Private module encapsulating the Bridge Interface when running on an EC2 connecting interacting over VSock
#[cfg(feature = "enclave")]
mod enclave_bridge {
    use super::*;
    use crate::server::VsockServer;
    use tokio_vsock::VsockStream;

    /// Convert the context id into a u32 to use as a CID when opening a vsock connection
    impl std::convert::From<ContextID> for u32 {
        fn from(value: ContextID) -> Self {
            match value {
                ContextID::Enclave => crate::ENCLAVE_CID,
                ContextID::Parent => crate::PARENT_CID,
            }
        }
    }

    /// Implementor for `BridgeInterface` when using VSock, mainly used through the Bridge export alias behind the `enclave` feature flag.
    pub struct VSockBridge;

    #[async_trait]
    impl BridgeInterface for VSockBridge {
        type Listener = VsockServer;
        type ClientConnection = VsockStream;

        async fn get_client_connection(
            port: u16,
            direction: Direction,
        ) -> Result<Self::ClientConnection, ServerError> {
            Ok(VsockStream::connect(direction.get_client_cid().into(), port.into()).await?)
        }

        async fn get_listener(
            port: u16,
            direction: Direction,
        ) -> Result<Self::Listener, ServerError> {
            VsockServer::bind(direction.get_server_cid().into(), port.into()).await
        }
    }

    /// Alias for the Listener type of the `VSockBridge` implementation of `BridgeInterface`
    pub type BridgeServer = VsockServer;
    /// Alias for the Connection type of the `VSockBridge` implementation of `BridgeInterface`
    pub type BridgeClient = VsockStream;
}
#[cfg(feature = "enclave")]
pub use enclave_bridge::{BridgeClient, BridgeServer, VSockBridge as Bridge};

/// Private module encapsulating the Bridge Interface when running in non-vsock environments. Uses TCP sockets for all bridge communications.
#[cfg(not(feature = "enclave"))]
mod local_bridge {
    use super::*;
    use crate::server::TcpServer;
    use std::net::IpAddr;
    use tokio::net::TcpStream;

    /// Local dev IP address for the enclave process. Defined in the docker-compose file in this repo.
    pub const ENCLAVE_IP: &str = "172.20.0.7";
    /// Local dev IP address for the parent process. Defined in the docker-compose file in this repo.
    pub const PARENT_IP: &str = "172.20.0.8";

    /// Convert the Context ID into an IP address
    impl std::convert::From<ContextID> for IpAddr {
        fn from(value: ContextID) -> Self {
            match value {
                ContextID::Enclave => ENCLAVE_IP.parse().expect("Hardcoded value for local dev"),
                ContextID::Parent => PARENT_IP.parse().expect("Hardcoded value for local dev"),
            }
        }
    }

    /// Implementor for `BridgeInterface` when using TCP sockets, mainly used through the Bridge export alias when the `enclave` feature flag is disabled.
    pub struct TcpBridge;

    #[async_trait]
    impl BridgeInterface for TcpBridge {
        type Listener = TcpServer;
        type ClientConnection = TcpStream;

        async fn get_client_connection(
            port: u16,
            direction: Direction,
        ) -> Result<Self::ClientConnection, ServerError> {
            let ip_addr: IpAddr = direction.get_client_cid().into();
            Ok(TcpStream::connect((ip_addr, port)).await?)
        }

        async fn get_listener(
            port: u16,
            direction: Direction,
        ) -> Result<Self::Listener, ServerError> {
            let ip_addr: IpAddr = direction.get_server_cid().into();
            TcpServer::bind((ip_addr, port)).await
        }
    }

    /// Alias for the Listener type of the `TcpBridge` implementation of `BridgeInterface`
    pub type BridgeServer = TcpServer;
    /// Alias for the Connection type of the `TcpBridge` implementation of `BridgeInterface`
    pub type BridgeClient = TcpStream;
}

#[cfg(not(feature = "enclave"))]
pub use local_bridge::{BridgeClient, BridgeServer, TcpBridge as Bridge};
