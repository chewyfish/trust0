use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::{sync, thread};

use anyhow::Result;

use crate::error::AppError;
use crate::logging::{error, warn};
use crate::net::stream_utils::StreamReaderWriter;
use crate::proxy::event::ProxyEvent;
use crate::proxy::proxy_base::ProxyStream;
use crate::proxy::proxy_channel_and_tcp::ChannelAndTcpStreamProxy;
use crate::proxy::proxy_tcp_and_tcp::TcpAndTcpStreamProxy;
use crate::proxy::proxy_tcp_and_udp::TcpAndUdpStreamProxy;
use crate::target;

/// Used to (uniquely) represent an active proxy session
pub type ProxyKey = String;

/// Used to represent the context for the (Socket Channel <-> TCP) streams proxy
///
/// # Attributes
///
/// * Channel's respective socket address
/// * Receiver for incoming socket channel messages
/// * Sender to send messages to UDP server socket (for client delivery from service)
/// * TCP stream corresponding to the TCP proxy entity
/// * TCP stream reader/writer corresponding to the TCP proxy entity
/// * Channel sender to send back proxy events
///
pub type ChannelAndTcpProxyContext = (
    SocketAddr,
    sync::mpsc::Receiver<ProxyEvent>,
    sync::mpsc::Sender<ProxyEvent>,
    std::net::TcpStream,
    Arc<Mutex<Box<dyn StreamReaderWriter>>>,
    sync::mpsc::Sender<ProxyEvent>,
);

/// Used to represent the context for the (TCP <-> TCP) streams proxy
///
/// # Attributes
///
/// * TCP stream corresponding to the 1st TCP proxy entity
/// * TCP stream corresponding to the 2nd TCP proxy entity
/// * Stream reader/writer corresponding to the 1st TCP proxy entity
/// * Stream reader/writer corresponding to the 2nd TCP proxy entity
/// * Channel sender to send back proxy events
///
pub type TcpAndTcpProxyContext = (
    std::net::TcpStream,
    std::net::TcpStream,
    Arc<Mutex<Box<dyn StreamReaderWriter>>>,
    Arc<Mutex<Box<dyn StreamReaderWriter>>>,
    sync::mpsc::Sender<ProxyEvent>,
);

/// Used to represent the context for the (TCP <-> UDP) streams proxy
///
/// # Attributes
///
/// * TCP stream corresponding to the TCP proxy entity
/// * UDP socket corresponding to the UDP proxy entity
/// * Stream reader/writer corresponding to the TCP proxy entity
/// * Channel sender to send back proxy events
///
pub type TcpAndUdpProxyContext = (
    std::net::TcpStream,
    std::net::UdpSocket,
    Arc<Mutex<Box<dyn StreamReaderWriter>>>,
    sync::mpsc::Sender<ProxyEvent>,
);

/// Proxy executor event message
pub enum ProxyExecutorEvent {
    /// Request to open a new proxy for a channel and TCP entities
    OpenChannelAndTcpProxy(ProxyKey, ChannelAndTcpProxyContext),
    /// Request to open a new proxy for 2 TCP entities
    OpenTcpAndTcpProxy(ProxyKey, TcpAndTcpProxyContext),
    /// Request to open a new proxy for a TCP and UDP entities
    OpenTcpAndUdpProxy(ProxyKey, TcpAndUdpProxyContext),
    /// Request to close an active proxy
    Close(ProxyKey),
}

/// Service proxy executor to handle proxy lifecycle (setup, teardown)
pub struct ProxyExecutor {
    /// Channel sender to send proxy task requests
    proxy_tasks_sender: sync::mpsc::Sender<ProxyExecutorEvent>,
    /// Channel receiver to receive proxy task requests
    proxy_tasks_receiver: sync::mpsc::Receiver<ProxyExecutorEvent>,
    /// Map of active proxy streams (by proxy key)
    proxy_streams: HashMap<ProxyKey, Arc<Mutex<dyn ProxyStream>>>,
    #[cfg(test)]
    /// Polling tasks events limit
    polling_tasks_limit: u8,
}

impl ProxyExecutor {
    /// ProxyExecutor constructor
    ///
    /// # Returns
    ///
    /// A newly constructed [`ProxyExecutor`] object.
    ///
    pub fn new() -> Self {
        let (proxy_tasks_sender, proxy_tasks_receiver) = sync::mpsc::channel();

        Self {
            proxy_tasks_sender,
            proxy_tasks_receiver,
            proxy_streams: HashMap::new(),
            #[cfg(test)]
            polling_tasks_limit: 0,
        }
    }

    /// Get the proxy tasks sender
    ///
    /// # Returns
    ///
    /// A clone of the proxy tasks channel sender.
    ///
    pub fn clone_proxy_tasks_sender(&self) -> sync::mpsc::Sender<ProxyExecutorEvent> {
        self.proxy_tasks_sender.clone()
    }

    /// Listen and process any new proxy request tasks (blocking)
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of poller operation.
    ///
    pub fn poll_new_tasks(&mut self) -> Result<(), AppError> {
        loop {
            #[cfg(test)]
            {
                if self.polling_tasks_limit <= 0 {
                    return Ok(());
                }
                self.polling_tasks_limit -= 1;
            }

            // Get next request task
            let task = self.proxy_tasks_receiver.recv().map_err(|err| {
                AppError::General(format!("Error receiving new event task: err={:?}", &err))
            })?;

            // Process task
            match task {
                // Open new Socket channel <-> TCP stream proxy
                ProxyExecutorEvent::OpenChannelAndTcpProxy(proxy_key, proxy_context) => {
                    let proxy_channel_sender = proxy_context.5.clone();

                    match ChannelAndTcpStreamProxy::new(
                        &proxy_key,
                        &proxy_context.0,
                        proxy_context.1,
                        &proxy_context.2,
                        proxy_context.3,
                        &proxy_context.4,
                        &proxy_context.5,
                    ) {
                        Ok(proxy_stream) => {
                            let proxy_stream = Arc::new(Mutex::new(proxy_stream));

                            if let Err(err) = proxy_stream.lock().unwrap().connect() {
                                error(
                                    &target!(),
                                    &format!(
                                        "Error connecting proxy streams: proxy_stream={}, err={:?}",
                                        &proxy_key, err
                                    ),
                                );
                                continue;
                            }

                            self.proxy_streams.insert(proxy_key.clone(), proxy_stream);
                        }

                        Err(err) => {
                            error(&target!(), &format!("{:?}", err));

                            let proxy_key_copy = proxy_key.clone();
                            if let Err(err) = crate::sync::send_mpsc_channel_message(
                                &proxy_channel_sender,
                                ProxyEvent::Closed(proxy_key.clone()),
                                Box::new(move || {
                                    format!(
                                        "Error sending proxy closed message: proxy_stream={},",
                                        &proxy_key_copy
                                    )
                                }),
                            ) {
                                error(&target!(), &format!("{:?}", &err));
                                continue;
                            }
                        }
                    }
                }

                // Open new TCP stream <-> TCP stream proxy
                ProxyExecutorEvent::OpenTcpAndTcpProxy(proxy_key, proxy_context) => {
                    let proxy_channel_sender = proxy_context.4.clone();

                    match TcpAndTcpStreamProxy::new(
                        &proxy_key,
                        proxy_context.0,
                        proxy_context.1,
                        &proxy_context.2,
                        &proxy_context.3,
                        &proxy_context.4,
                    ) {
                        Ok(proxy_stream) => {
                            let proxy_stream = Arc::new(Mutex::new(proxy_stream));

                            if let Err(err) = proxy_stream.lock().unwrap().connect() {
                                error(
                                    &target!(),
                                    &format!(
                                        "Error connecting proxy streams: proxy_stream={}, err={:?}",
                                        &proxy_key, err
                                    ),
                                );
                                continue;
                            }

                            self.proxy_streams.insert(proxy_key.clone(), proxy_stream);
                        }

                        Err(err) => {
                            error(&target!(), &format!("{:?}", err));

                            let proxy_key_copy = proxy_key.clone();
                            if let Err(err) = crate::sync::send_mpsc_channel_message(
                                &proxy_channel_sender,
                                ProxyEvent::Closed(proxy_key.clone()),
                                Box::new(move || {
                                    format!(
                                        "Error sending proxy closed message: proxy_stream={},",
                                        &proxy_key_copy
                                    )
                                }),
                            ) {
                                error(&target!(), &format!("{:?}", &err));
                                continue;
                            }
                        }
                    }
                }

                // Open new TCP stream <-> UDP stream proxy
                ProxyExecutorEvent::OpenTcpAndUdpProxy(proxy_key, proxy_context) => {
                    let proxy_channel_sender = proxy_context.3.clone();

                    match TcpAndUdpStreamProxy::new(
                        &proxy_key,
                        proxy_context.0,
                        proxy_context.1,
                        &proxy_context.2,
                        &proxy_context.3,
                    ) {
                        Ok(proxy_stream) => {
                            let proxy_stream = Arc::new(Mutex::new(proxy_stream));

                            if let Err(err) = proxy_stream.lock().unwrap().connect() {
                                error(
                                    &target!(),
                                    &format!(
                                        "Error connecting proxy streams: proxy_stream={}, err={:?}",
                                        &proxy_key, err
                                    ),
                                );
                                continue;
                            }

                            self.proxy_streams.insert(proxy_key.clone(), proxy_stream);
                        }

                        Err(err) => {
                            error(&target!(), &format!("{:?}", err));

                            let proxy_key_copy = proxy_key.clone();
                            if let Err(err) = crate::sync::send_mpsc_channel_message(
                                &proxy_channel_sender,
                                ProxyEvent::Closed(proxy_key.clone()),
                                Box::new(move || {
                                    format!(
                                        "Error sending proxy closed message: proxy_stream={},",
                                        &proxy_key_copy
                                    )
                                }),
                            ) {
                                error(&target!(), &format!("{:?}", &err));
                                continue;
                            }
                        }
                    }
                }

                // Close current client->service proxy
                ProxyExecutorEvent::Close(proxy_key) => {
                    match self.proxy_streams.get_mut(&proxy_key) {
                        Some(proxy_stream) => {
                            let proxy_stream = proxy_stream.clone();
                            _ = self.proxy_streams.remove(&proxy_key);

                            thread::spawn(move || {
                                if let Err(err) = proxy_stream.lock().unwrap().disconnect() {
                                    error(&target!(), &format!("Error disconnecting TCP proxy stream: proxy_stream={}, err={:?}", &proxy_key, err));
                                }
                            });
                            continue;
                        }

                        None => {
                            warn(
                                &target!(),
                                &format!("Unknown proxy for closure: proxy_stream={}", &proxy_key),
                            );
                            continue;
                        }
                    }
                }
            }
        }
    }
}

impl Default for ProxyExecutor {
    fn default() -> Self {
        Self::new()
    }
}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::stream_utils;
    use crate::net::stream_utils::{ConnectedTcpStream, ConnectedUdpSocket};
    use std::io::{Read, Write};
    use std::time::Duration;

    fn create_channel_and_tcp_stream_proxy_event(
        proxy_key: &str,
    ) -> Result<(
        SocketAddr,
        sync::mpsc::Sender<ProxyEvent>,
        ConnectedTcpStream,
        sync::mpsc::Receiver<ProxyEvent>,
        ProxyExecutorEvent,
    )> {
        let socket_channel_addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let socket_channel = sync::mpsc::channel();
        let server_socket_channel = sync::mpsc::channel();
        let connected_tcp_stream = ConnectedTcpStream::new()?;
        let client_tcp_stream = stream_utils::clone_std_tcp_stream(
            &connected_tcp_stream.client_stream.0,
            "test-tcpchannel-proxy",
        )?;
        let client_reader_writer: Box<dyn StreamReaderWriter> = Box::new(
            stream_utils::clone_std_tcp_stream(&client_tcp_stream, "test-tcpchannel-proxy")?,
        );
        let proxy_channel = sync::mpsc::channel();
        Ok((
            socket_channel_addr.clone(),
            socket_channel.0,
            connected_tcp_stream,
            proxy_channel.1,
            ProxyExecutorEvent::OpenChannelAndTcpProxy(
                proxy_key.to_string(),
                (
                    socket_channel_addr,
                    socket_channel.1,
                    server_socket_channel.0,
                    client_tcp_stream,
                    Arc::new(Mutex::new(client_reader_writer)),
                    proxy_channel.0,
                ),
            ),
        ))
    }

    fn create_tcp_and_tcp_stream_proxy_event(
        proxy_key: &str,
    ) -> Result<(
        SocketAddr,
        ConnectedTcpStream,
        ConnectedTcpStream,
        sync::mpsc::Receiver<ProxyEvent>,
        ProxyExecutorEvent,
    )> {
        let socket_channel_addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let connected_tcp_stream1 = ConnectedTcpStream::new()?;
        let connected_tcp_stream2 = ConnectedTcpStream::new()?;
        let client_tcp_stream = stream_utils::clone_std_tcp_stream(
            &connected_tcp_stream1.server_stream.0,
            "test-tcptcp-proxy",
        )?;
        let client_reader_writer: Box<dyn StreamReaderWriter> = Box::new(
            stream_utils::clone_std_tcp_stream(&client_tcp_stream, "test-tcptcp-proxy")?,
        );
        let server_tcp_stream = stream_utils::clone_std_tcp_stream(
            &connected_tcp_stream2.client_stream.0,
            "test-tcptcp-proxy",
        )?;
        let server_reader_writer: Box<dyn StreamReaderWriter> = Box::new(
            stream_utils::clone_std_tcp_stream(&server_tcp_stream, "test-tcptcp-proxy-rw")?,
        );
        let proxy_channel = sync::mpsc::channel();
        Ok((
            socket_channel_addr.clone(),
            connected_tcp_stream1,
            connected_tcp_stream2,
            proxy_channel.1,
            ProxyExecutorEvent::OpenTcpAndTcpProxy(
                proxy_key.to_string(),
                (
                    client_tcp_stream,
                    server_tcp_stream,
                    Arc::new(Mutex::new(client_reader_writer)),
                    Arc::new(Mutex::new(server_reader_writer)),
                    proxy_channel.0,
                ),
            ),
        ))
    }

    fn create_tcp_and_udp_stream_proxy_event(
        proxy_key: &str,
    ) -> Result<(
        SocketAddr,
        ConnectedTcpStream,
        ConnectedUdpSocket,
        sync::mpsc::Receiver<ProxyEvent>,
        ProxyExecutorEvent,
    )> {
        let socket_channel_addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let connected_tcp_stream = ConnectedTcpStream::new()?;
        let connected_udp_socket = ConnectedUdpSocket::new()?;
        let client_tcp_stream = stream_utils::clone_std_tcp_stream(
            &connected_tcp_stream.server_stream.0,
            "test-tcpudp-proxy",
        )?;
        let client_reader_writer: Box<dyn StreamReaderWriter> = Box::new(
            stream_utils::clone_std_tcp_stream(&client_tcp_stream, "test-tcpudp-proxy")?,
        );
        let server_udp_socket = stream_utils::clone_std_udp_socket(
            &connected_udp_socket.client_socket.0,
            "test-tcpudp-proxy",
        )?;
        let proxy_channel = sync::mpsc::channel();
        Ok((
            socket_channel_addr.clone(),
            connected_tcp_stream,
            connected_udp_socket,
            proxy_channel.1,
            ProxyExecutorEvent::OpenTcpAndUdpProxy(
                proxy_key.to_string(),
                (
                    client_tcp_stream,
                    server_udp_socket,
                    Arc::new(Mutex::new(client_reader_writer)),
                    proxy_channel.0,
                ),
            ),
        ))
    }

    #[test]
    fn proxyexec_new() {
        let executor = ProxyExecutor::default();

        assert!(executor.proxy_streams.is_empty());

        executor
            .clone_proxy_tasks_sender()
            .send(ProxyExecutorEvent::Close("key1".to_string()))
            .unwrap();

        let received_task = executor.proxy_tasks_receiver.try_recv();
        match received_task {
            Ok(event) => match event {
                ProxyExecutorEvent::Close(key) => assert_eq!(key, "key1".to_string()),
                ProxyExecutorEvent::OpenChannelAndTcpProxy(_, _) => {
                    panic!("Unexpected channel&tcp proxy event")
                }
                ProxyExecutorEvent::OpenTcpAndTcpProxy(_, _) => {
                    panic!("Unexpected tcp&tcp proxy event")
                }
                ProxyExecutorEvent::OpenTcpAndUdpProxy(_, _) => {
                    panic!("Unexpected tcp&udp proxy event")
                }
            },
            Err(err) => panic!("Unexpected channel receive result: err={:?}", &err),
        }
    }

    #[test]
    fn proxyexec_poll_new_tasks_when_valid_channeltcpproxy() {
        let proxy_key = "key1";
        let (
            socket_channel_addr,
            socket_channel_sender,
            mut connected_tcp_stream,
            _proxy_channel_receiver,
            open_proxy_event,
        ) = create_channel_and_tcp_stream_proxy_event(proxy_key).unwrap();

        let mut executor = ProxyExecutor::default();
        executor.polling_tasks_limit = 1;
        executor
            .clone_proxy_tasks_sender()
            .send(open_proxy_event)
            .unwrap();

        if let Err(err) = executor.poll_new_tasks() {
            panic!("Unexpected polling result: err={:?}", &err);
        }

        let proxy_stream = executor.proxy_streams.get_mut(proxy_key);
        assert!(proxy_stream.is_some());

        let data = "hello".as_bytes();
        socket_channel_sender
            .send(ProxyEvent::Message(
                "key1".to_string(),
                socket_channel_addr.clone(),
                data.to_vec(),
            ))
            .unwrap();

        thread::sleep(Duration::from_millis(50));
        if let Err(err) = proxy_stream.unwrap().lock().unwrap().disconnect() {
            panic!("Unexpected proxy stream disconnect result: err={:?}", &err);
        }

        let mut buffer = [0u8; 10];
        connected_tcp_stream
            .server_stream
            .0
            .set_nonblocking(true)
            .unwrap();
        let read_result = connected_tcp_stream.server_stream.0.read(&mut buffer);
        if let Err(err) = read_result {
            panic!("Unexpected tcp stream read result: err={:?}", &err);
        }

        assert_eq!(read_result.unwrap(), 7);

        let mut expected_buffer = [0u8; 10];
        expected_buffer.as_mut_slice()[..2].copy_from_slice(&[0x00u8, 0x05u8] as &[u8]);
        expected_buffer.as_mut_slice()[2..7].copy_from_slice(data);
        assert_eq!(buffer, expected_buffer);
    }

    #[test]
    fn proxyexec_poll_new_tasks_when_valid_tcptcpproxy() {
        let proxy_key = "key1";
        let (
            _socket_channel_addr,
            mut client_tcp_stream,
            mut server_tcp_stream,
            _proxy_channel_receiver,
            open_proxy_event,
        ) = create_tcp_and_tcp_stream_proxy_event(proxy_key).unwrap();

        let mut executor = ProxyExecutor::default();
        executor.polling_tasks_limit = 1;
        executor
            .clone_proxy_tasks_sender()
            .send(open_proxy_event)
            .unwrap();

        if let Err(err) = executor.poll_new_tasks() {
            panic!("Unexpected polling result: err={:?}", &err);
        }

        let proxy_stream = executor.proxy_streams.get_mut(proxy_key);
        assert!(proxy_stream.is_some());

        let data = "hello".as_bytes();
        if let Err(err) = client_tcp_stream.client_stream.0.write_all(data) {
            panic!("Unexpected tcp stream write result: err={:?}", &err);
        }

        thread::sleep(Duration::from_millis(50));
        if let Err(err) = proxy_stream.unwrap().lock().unwrap().disconnect() {
            panic!("Unexpected proxy stream disconnect result: err={:?}", &err);
        }

        let mut buffer = [0u8; 10];
        server_tcp_stream
            .server_stream
            .0
            .set_nonblocking(true)
            .unwrap();
        let read_result = server_tcp_stream.server_stream.0.read(&mut buffer);
        if let Err(err) = read_result {
            panic!("Unexpected tcp stream read result: err={:?}", &err);
        }

        assert_eq!(read_result.unwrap(), 5);

        let mut expected_buffer = [0u8; 10];
        expected_buffer.as_mut_slice()[..5].copy_from_slice(data);
        assert_eq!(buffer, expected_buffer);
    }

    #[test]
    fn proxyexec_poll_new_tasks_when_valid_tcpudpproxy() {
        let proxy_key = "key1";
        let (
            _socket_channel_addr,
            mut client_tcp_stream,
            server_udp_socket,
            _proxy_channel_receiver,
            open_proxy_event,
        ) = create_tcp_and_udp_stream_proxy_event(proxy_key).unwrap();

        let mut executor = ProxyExecutor::default();
        executor.polling_tasks_limit = 1;
        executor
            .clone_proxy_tasks_sender()
            .send(open_proxy_event)
            .unwrap();

        if let Err(err) = executor.poll_new_tasks() {
            panic!("Unexpected polling result: err={:?}", &err);
        }

        let proxy_stream = executor.proxy_streams.get_mut(proxy_key);
        assert!(proxy_stream.is_some());

        let data = &[0x00u8, 0x05u8, b'h', b'e', b'l', b'l', b'o'] as &[u8];
        if let Err(err) = client_tcp_stream.client_stream.0.write_all(data) {
            panic!("Unexpected tcp stream write result: err={:?}", &err);
        }

        thread::sleep(Duration::from_millis(50));
        if let Err(err) = proxy_stream.unwrap().lock().unwrap().disconnect() {
            panic!("Unexpected proxy stream disconnect result: err={:?}", &err);
        }

        let mut buffer = [0u8; 10];
        server_udp_socket
            .server_socket
            .0
            .set_nonblocking(true)
            .unwrap();
        let read_result = server_udp_socket.server_socket.0.recv(&mut buffer);
        if let Err(err) = read_result {
            panic!("Unexpected udp socket read result: err={:?}", &err);
        }

        assert_eq!(read_result.unwrap(), 5);

        let mut expected_buffer = [0u8; 10];
        expected_buffer.as_mut_slice()[..5].copy_from_slice(&data[2..7]);
        assert_eq!(buffer, expected_buffer);
    }

    #[test]
    fn proxyexec_poll_new_tasks_when_invalid_close_key() {
        let proxy_key = "key1";

        let mut executor = ProxyExecutor::default();
        executor.polling_tasks_limit = 1;
        executor
            .clone_proxy_tasks_sender()
            .send(ProxyExecutorEvent::Close(proxy_key.to_string()))
            .unwrap();

        if let Err(err) = executor.poll_new_tasks() {
            panic!("Unexpected polling result: err={:?}", &err);
        }

        assert!(!executor.proxy_streams.contains_key(proxy_key));
    }

    #[test]
    fn proxyexec_poll_new_tasks_when_valid_close_key() {
        let proxy_key = "key1";
        let (
            _socket_channel_addr,
            _client_tcp_stream,
            _server_tcp_stream,
            _proxy_channel_receiver,
            open_proxy_event,
        ) = create_tcp_and_tcp_stream_proxy_event(proxy_key).unwrap();

        let mut executor = ProxyExecutor::default();
        executor.polling_tasks_limit = 2;
        executor
            .clone_proxy_tasks_sender()
            .send(open_proxy_event)
            .unwrap();
        executor
            .clone_proxy_tasks_sender()
            .send(ProxyExecutorEvent::Close(proxy_key.to_string()))
            .unwrap();

        if let Err(err) = executor.poll_new_tasks() {
            panic!("Unexpected polling result: err={:?}", &err);
        }

        assert!(!executor.proxy_streams.contains_key(proxy_key));
    }
}
