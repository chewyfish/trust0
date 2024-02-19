use std::net::Shutdown;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{io, sync, thread};

use anyhow::Result;

use crate::error::AppError;
use crate::logging::{error, info, warn};
use crate::net::stream_utils;
use crate::net::stream_utils::StreamReaderWriter;
use crate::proxy::event::ProxyEvent;
use crate::proxy::proxy_base::ProxyStream;
use crate::target;

const TCP_STREAM_TOKEN: mio::Token = mio::Token(0);
const UDP_SOCKET_TOKEN: mio::Token = mio::Token(1);
const POLLING_DURATION_MSECS: u64 = 1000;

/// Proxy based on 2 connected sockets: TCP stream and a UDP socket
pub struct TcpAndUdpStreamProxy {
    /// Unique key for this proxy
    proxy_key: String,
    /// TCP stream for the TCP proxy entity
    tcp_stream: std::net::TcpStream,
    /// UDP socket for the UDP proxy entity
    udp_socket: std::net::UdpSocket,
    /// Stream reader/writer for the TCP proxy entity
    tcp_stream_reader_writer: Arc<Mutex<Box<dyn StreamReaderWriter>>>,
    /// Channel sender for proxy (management) events
    proxy_channel_sender: sync::mpsc::Sender<ProxyEvent>,
    /// Indicates a request to close the proxy
    closing: Arc<Mutex<bool>>,
    /// Proxy closed/shutdown state value
    closed: Arc<Mutex<bool>>,
}

impl TcpAndUdpStreamProxy {
    /// TcpAndUdpStreamProxy constructor
    ///
    /// # Arguments
    ///
    /// * `proxy_key` - Unique key for this proxy
    /// * `tcp_stream` - TCP stream for the TCP proxy entity
    /// * `udp_socket` - UDP socket for the UDP proxy entity
    /// * `tcp_stream_reader_writer` - Stream reader/writer for the TCP proxy entity
    /// * `proxy_channel_sender` - Channel sender for proxy (management) events
    ///
    /// # Returns
    ///
    /// A [`Result`] containing a newly constructed [`TcpAndUdpStreamProxy`] object.
    ///
    pub fn new(
        proxy_key: &str,
        tcp_stream: std::net::TcpStream,
        udp_socket: std::net::UdpSocket,
        tcp_stream_reader_writer: &Arc<Mutex<Box<dyn StreamReaderWriter>>>,
        proxy_channel_sender: &sync::mpsc::Sender<ProxyEvent>,
    ) -> Result<Self, AppError> {
        // Convert streams to non-blocking
        let tcp_stream = stream_utils::clone_std_tcp_stream(&tcp_stream)?;
        let udp_socket = stream_utils::clone_std_udp_socket(&udp_socket)?;

        tcp_stream.set_nonblocking(true).map_err(|err| {
            AppError::GenWithMsgAndErr(
                format!(
                    "Failed making tcp socket non-blocking: proxy_stream={}",
                    &proxy_key
                ),
                Box::new(err),
            )
        })?;
        udp_socket.set_nonblocking(true).map_err(|err| {
            AppError::GenWithMsgAndErr(
                format!(
                    "Failed making udp socket non-blocking: proxy_stream={}",
                    &proxy_key
                ),
                Box::new(err),
            )
        })?;

        // Instantiate TcpStreamProxy
        Ok(TcpAndUdpStreamProxy {
            proxy_key: proxy_key.to_string(),
            tcp_stream,
            udp_socket,
            tcp_stream_reader_writer: tcp_stream_reader_writer.clone(),
            proxy_channel_sender: proxy_channel_sender.clone(),
            closing: Arc::new(Mutex::new(false)),
            closed: Arc::new(Mutex::new(false)),
        })
    }

    /// Connect tcp IO streams (spawn task to bidirectionally copy data)
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of the connection.
    ///
    pub fn connect(&mut self) -> Result<(), AppError> {
        info(
            &target!(),
            &format!("Starting proxy: proxy_stream={}", &self.proxy_key),
        );

        *self.closing.lock().unwrap() = false;

        // Spawn bidirectional stream IO copy task
        let closing = self.closing.clone();
        let closed = self.closed.clone();
        let tcp_stream = stream_utils::clone_std_tcp_stream(&self.tcp_stream)?;
        let udp_socket = stream_utils::clone_std_udp_socket(&self.udp_socket)?;
        let mut tcp_stream_reader_writer = self.tcp_stream_reader_writer.clone();
        let proxy_key = self.proxy_key.clone();
        let proxy_channel_sender = self.proxy_channel_sender.clone();

        let bidirectional_iocopy_handle = thread::spawn(move || {
            let mut tcp_stream = mio::net::TcpStream::from_std(tcp_stream);
            let mut udp_socket = mio::net::UdpSocket::from_std(udp_socket);

            // Setup MIO poller registry
            let mut poll: mio::Poll;

            match mio::Poll::new() {
                Ok(_poll) => poll = _poll,
                Err(err) => {
                    Self::perform_shutdown(
                        &proxy_key,
                        &tcp_stream,
                        &udp_socket,
                        &proxy_channel_sender,
                        &closed,
                    );
                    return Err(AppError::GenWithMsgAndErr(
                        "Error creating new MIO poller".to_string(),
                        Box::new(err),
                    ));
                }
            }

            if let Err(err) =
                poll.registry()
                    .register(&mut tcp_stream, TCP_STREAM_TOKEN, mio::Interest::READABLE)
            {
                Self::perform_shutdown(
                    &proxy_key,
                    &tcp_stream,
                    &udp_socket,
                    &proxy_channel_sender,
                    &closed,
                );
                return Err(AppError::GenWithMsgAndErr(
                    "Error registering tcp stream in MIO registry".to_string(),
                    Box::new(err),
                ));
            }

            if let Err(err) =
                poll.registry()
                    .register(&mut udp_socket, UDP_SOCKET_TOKEN, mio::Interest::READABLE)
            {
                Self::perform_shutdown(
                    &proxy_key,
                    &tcp_stream,
                    &udp_socket,
                    &proxy_channel_sender,
                    &closed,
                );
                return Err(AppError::GenWithMsgAndErr(
                    "Error registering udp socket in MIO registry".to_string(),
                    Box::new(err),
                ));
            }

            let mut events = mio::Events::with_capacity(256);
            let mut proxy_error = None;

            // IO events processing loop
            'EVENTS: while !*closing.lock().unwrap() {
                match poll.poll(
                    &mut events,
                    Some(Duration::from_millis(POLLING_DURATION_MSECS)),
                ) {
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(err) => {
                        proxy_error = Some(AppError::GenWithMsgAndErr(
                            "Error while polling for IO events".to_string(),
                            Box::new(err),
                        ));
                        *closing.lock().unwrap() = true;
                        continue 'EVENTS;
                    }
                    _ => {}
                }

                for event in events.iter() {
                    match event.token() {
                        TCP_STREAM_TOKEN => {
                            match stream_utils::read_tcp_stream(&mut tcp_stream_reader_writer) {
                                Ok(data) => {
                                    match stream_utils::write_mio_udp_socket(
                                        &udp_socket,
                                        data.as_slice(),
                                    ) {
                                        Ok(()) => {}
                                        Err(err) => match err {
                                            AppError::WouldBlock => continue,
                                            AppError::StreamEOF => break 'EVENTS,
                                            _ => {
                                                proxy_error = Some(err);
                                                *closing.lock().unwrap() = true;
                                                continue 'EVENTS;
                                            }
                                        },
                                    }
                                }
                                Err(err) => {
                                    proxy_error = Some(err);
                                    *closing.lock().unwrap() = true;
                                    continue 'EVENTS;
                                }
                            }

                            if let Err(err) = poll.registry().reregister(
                                &mut tcp_stream,
                                TCP_STREAM_TOKEN,
                                mio::Interest::READABLE,
                            ) {
                                proxy_error = Some(AppError::GenWithMsgAndErr(
                                    "Error registering tcp stream in MIO registry".to_string(),
                                    Box::new(err),
                                ));
                                *closing.lock().unwrap() = true;
                                continue 'EVENTS;
                            }
                        }

                        UDP_SOCKET_TOKEN => {
                            match stream_utils::read_mio_udp_socket(&udp_socket) {
                                Ok((_socket_addr, data)) => {
                                    match stream_utils::write_tcp_stream(
                                        &mut tcp_stream_reader_writer,
                                        data.as_slice(),
                                    ) {
                                        Ok(()) => {}
                                        Err(err) => match err {
                                            AppError::WouldBlock => continue,
                                            AppError::StreamEOF => break 'EVENTS,
                                            _ => {
                                                proxy_error = Some(err);
                                                *closing.lock().unwrap() = true;
                                                continue 'EVENTS;
                                            }
                                        },
                                    }
                                }
                                Err(err) => {
                                    proxy_error = Some(err);
                                    *closing.lock().unwrap() = true;
                                    continue 'EVENTS;
                                }
                            }

                            if let Err(err) = poll.registry().reregister(
                                &mut udp_socket,
                                UDP_SOCKET_TOKEN,
                                mio::Interest::READABLE,
                            ) {
                                proxy_error = Some(AppError::GenWithMsgAndErr(
                                    "Error registering udp socket in MIO registry".to_string(),
                                    Box::new(err),
                                ));
                                *closing.lock().unwrap() = true;
                                continue 'EVENTS;
                            }
                        }

                        _ => {}
                    }
                }
            }

            // Shutdown proxy resources
            Self::perform_shutdown(
                &proxy_key,
                &tcp_stream,
                &udp_socket,
                &proxy_channel_sender,
                &closed,
            );

            match proxy_error {
                Some(err) => Err(err),
                None => Ok(()),
            }
        });

        // Spawn thread to join IO copy thread
        let proxy_key = self.proxy_key.clone();

        thread::spawn(move || {
            let join_result = bidirectional_iocopy_handle.join();
            if join_result.is_err() {
                error(
                    &target!(),
                    &format!(
                        "Error joining proxy IO copy task handle: err={:?}",
                        join_result.as_ref().err().unwrap()
                    ),
                );
            }
            if let Err(err) = join_result.unwrap() {
                match err {
                    AppError::StreamEOF => {}
                    _ => error(&target!(), &format!("{:?}", err)),
                }
            }

            info(
                &target!(),
                &format!("Stopped proxy: proxy_stream={}", &proxy_key),
            );
        });

        *self.closed.lock().unwrap() = false;

        Ok(())
    }

    /// Shutdown proxy resources (called by proxy thread on termination)
    fn perform_shutdown(
        proxy_key: &str,
        tcp_stream: &mio::net::TcpStream,
        _udp_socket: &mio::net::UdpSocket,
        proxy_channel_sender: &sync::mpsc::Sender<ProxyEvent>,
        closed_state: &Arc<Mutex<bool>>,
    ) {
        // Close proxy connection stream
        match tcp_stream.shutdown(Shutdown::Both) {
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotConnected => {}
            Err(err) => error(
                &target!(),
                &format!(
                    "Error shutting down proxy tcp stream 1: proxy_stream={}, err={:?}",
                    &proxy_key, err
                ),
            ),
        }

        if let Err(err) = proxy_channel_sender.send(ProxyEvent::Closed(proxy_key.to_string())) {
            error(
                &target!(),
                &format!(
                    "Error sending proxy closed message: proxy_stream={}, err={:?}",
                    &proxy_key, err
                ),
            );
        }

        *closed_state.lock().unwrap() = true;
    }
}

impl ProxyStream for TcpAndUdpStreamProxy {
    fn disconnect(&mut self) -> Result<(), AppError> {
        if *self.closed.lock().unwrap() {
            warn(
                &target!(),
                &format!("Proxy already stopped: proxy_stream={}", &self.proxy_key),
            );
        } else {
            info(
                &target!(),
                &format!("Stopping proxy: proxy_stream={}", &self.proxy_key),
            );
        }

        *self.closing.lock().unwrap() = true;

        Ok(())
    }
}

unsafe impl Send for TcpAndUdpStreamProxy {}

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::net::stream_utils::{ConnectedTcpStream, ConnectedUdpSocket};
    use anyhow::Result;
    use std::io::ErrorKind::WouldBlock;
    use std::io::{Read, Write};

    fn create_tcp_and_udp_stream_proxy(
        proxy_key: &str,
    ) -> Result<(
        TcpAndUdpStreamProxy,
        ConnectedTcpStream,
        ConnectedUdpSocket,
        (
            sync::mpsc::Sender<ProxyEvent>,
            sync::mpsc::Receiver<ProxyEvent>,
        ),
    )> {
        let connected_tcp_stream = ConnectedTcpStream::new()?;
        let connected_udp_socket = ConnectedUdpSocket::new()?;
        let client_tcp_stream =
            stream_utils::clone_std_tcp_stream(&connected_tcp_stream.server_stream.0)?;
        let client_reader_writer: Box<dyn StreamReaderWriter> =
            Box::new(stream_utils::clone_std_tcp_stream(&client_tcp_stream)?);
        let server_udp_socket =
            stream_utils::clone_std_udp_socket(&connected_udp_socket.client_socket.0)?;
        let proxy_channel = sync::mpsc::channel();
        let proxy = TcpAndUdpStreamProxy::new(
            proxy_key,
            client_tcp_stream,
            server_udp_socket,
            &Arc::new(Mutex::new(client_reader_writer)),
            &proxy_channel.0,
        )?;
        Ok((
            proxy,
            connected_tcp_stream,
            connected_udp_socket,
            proxy_channel,
        ))
    }

    #[test]
    fn tcpudpproxy_new() {
        if let Err(err) = create_tcp_and_udp_stream_proxy("key1") {
            panic!("Unexpected result: err={:?}", &err);
        }
    }

    #[test]
    fn tcpudpproxy_connect_when_tcp_to_udp_copy() {
        let mut proxy_result = create_tcp_and_udp_stream_proxy("key1").unwrap();

        if let Err(err) = proxy_result.0.connect() {
            panic!("Unexpected proxy connect result: err={:?}", &err);
        }

        let data = "hello".as_bytes();
        if let Err(err) = proxy_result.1.client_stream.0.write_all(data) {
            panic!("Unexpected tcp stream write result: err={:?}", &err);
        }

        thread::sleep(Duration::from_millis(10));
        *proxy_result.0.closing.lock().unwrap() = true;

        let mut buffer = [0u8; 10];
        proxy_result
            .2
            .server_socket
            .0
            .set_nonblocking(true)
            .unwrap();
        let read_result = proxy_result.2.server_socket.0.recv(&mut buffer);
        if let Err(err) = read_result {
            panic!("Unexpected udp socket read result: err={:?}", &err);
        }

        assert_eq!(read_result.unwrap(), 5);

        let mut expected_buffer = [0u8; 10];
        expected_buffer.as_mut_slice()[..5].copy_from_slice(data);
        assert_eq!(buffer, expected_buffer);
    }

    #[test]
    fn tcpudpproxy_connect_when_no_tcp_to_udp_copy() {
        let mut proxy_result = create_tcp_and_udp_stream_proxy("key1").unwrap();

        if let Err(err) = proxy_result.0.connect() {
            panic!("Unexpected proxy connect result: err={:?}", &err);
        }

        thread::sleep(Duration::from_millis(10));
        *proxy_result.0.closing.lock().unwrap() = true;

        let mut buffer = [0u8; 10];
        proxy_result
            .2
            .server_socket
            .0
            .set_nonblocking(true)
            .unwrap();
        match proxy_result.2.server_socket.0.recv(&mut buffer) {
            Ok(len) => panic!(
                "Unexpected successful udp socket read result: byteslen={}",
                len
            ),
            Err(err) => {
                if err.kind() != WouldBlock {
                    panic!("Unexpected udp socket read result: err={:?}", &err);
                }
            }
        }
    }

    #[test]
    fn tcpudpproxy_connect_when_udp_to_tcp_copy() {
        let mut proxy_result = create_tcp_and_udp_stream_proxy("key1").unwrap();

        if let Err(err) = proxy_result.0.connect() {
            panic!("Unexpected proxy connect result: err={:?}", &err);
        }

        let data = "hello".as_bytes();
        if let Err(err) = proxy_result
            .2
            .server_socket
            .0
            .send_to(data, proxy_result.2.client_socket.1)
        {
            panic!("Unexpected udp socket write result: err={:?}", &err);
        }

        thread::sleep(Duration::from_millis(10));
        *proxy_result.0.closing.lock().unwrap() = true;

        let mut buffer = [0u8; 10];
        proxy_result
            .1
            .client_stream
            .0
            .set_nonblocking(true)
            .unwrap();
        let read_result = proxy_result.1.client_stream.0.read(&mut buffer);
        if let Err(err) = read_result {
            panic!("Unexpected tcp stream read result: err={:?}", &err);
        }

        assert_eq!(read_result.unwrap(), 5);

        let mut expected_buffer = [0u8; 10];
        expected_buffer.as_mut_slice()[..5].copy_from_slice(data);
        assert_eq!(buffer, expected_buffer);
    }

    #[test]
    fn tcpudpproxy_connect_when_no_udp_to_tcp_copy() {
        let mut proxy_result = create_tcp_and_udp_stream_proxy("key1").unwrap();

        if let Err(err) = proxy_result.0.connect() {
            panic!("Unexpected proxy connect result: err={:?}", &err);
        }

        thread::sleep(Duration::from_millis(10));
        *proxy_result.0.closing.lock().unwrap() = true;

        let mut buffer = [0u8; 10];
        proxy_result
            .1
            .client_stream
            .0
            .set_nonblocking(true)
            .unwrap();
        match proxy_result.1.client_stream.0.read(&mut buffer) {
            Ok(len) => panic!(
                "Unexpected successful tcp stream read result: byteslen={}",
                len
            ),
            Err(err) => {
                if err.kind() != WouldBlock {
                    panic!("Unexpected tcp stream read result: err={:?}", &err);
                }
            }
        }
    }

    #[test]
    fn tcpudpproxy_perform_shutdown() {
        let proxy_result = create_tcp_and_udp_stream_proxy("key1").unwrap();
        let closed = Arc::new(Mutex::new(false));

        let tcp_stream = mio::net::TcpStream::from_std(
            stream_utils::clone_std_tcp_stream(&proxy_result.1.server_stream.0).unwrap(),
        );
        let udp_socket = mio::net::UdpSocket::from_std(
            stream_utils::clone_std_udp_socket(&proxy_result.2.client_socket.0).unwrap(),
        );

        TcpAndUdpStreamProxy::perform_shutdown(
            "key1",
            &tcp_stream,
            &udp_socket,
            &proxy_result.3 .0,
            &closed,
        );

        match proxy_result.3 .1.try_recv() {
            Ok(proxy_event) => match proxy_event {
                ProxyEvent::Closed(key) => assert_eq!(key, "key1".to_string()),
                ProxyEvent::Message(key, addr, data) => panic!(
                    "Unexpected message proxy event: key={}, addr={:?}, addr={:?}",
                    &key, &addr, &data
                ),
            },
            Err(err) => panic!("Unexpected proxy channel result: err={:?}", &err),
        }

        assert!(*closed.lock().unwrap());
    }

    #[test]
    fn tcpudpproxy_disconnect() {
        let mut proxy_result = create_tcp_and_udp_stream_proxy("key1").unwrap();

        *proxy_result.0.closing.lock().unwrap() = false;
        *proxy_result.0.closed.lock().unwrap() = false;

        match proxy_result.0.disconnect() {
            Ok(()) => assert!(*proxy_result.0.closing.lock().unwrap()),
            Err(err) => panic!("Unexpected result: err={:?}", &err),
        }
    }
}
