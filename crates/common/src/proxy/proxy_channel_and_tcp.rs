use std::net::{Shutdown, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{io, sync, thread};

use anyhow::Result;
use bytes::BytesMut;

use crate::error::AppError;
use crate::logging::{error, info, warn};
use crate::net::stream_utils;
use crate::net::stream_utils::StreamReaderWriter;
use crate::proxy::event::ProxyEvent;
use crate::proxy::proxy_base::ProxyStream;
use crate::target;

const TCP_STREAM_TOKEN: mio::Token = mio::Token(0);
const POLLING_DURATION_MSECS: u64 = 1000;

/// Proxy based on a sync channel and a TCP stream
pub struct ChannelAndTcpStreamProxy {
    /// Unique key for this proxy
    proxy_key: String,
    /// Socket address corresponding to channel proxy entity
    socket_channel_addr: SocketAddr,
    /// Channel receiver for inbound proxy events for the channel proxy entity
    socket_channel_receiver: Arc<Mutex<sync::mpsc::Receiver<ProxyEvent>>>,
    /// Channel sender for outbound proxy events for the channel proxy entity
    server_socket_channel_sender: sync::mpsc::Sender<ProxyEvent>,
    /// TCP stream for the TCP proxy entity
    tcp_stream: std::net::TcpStream,
    /// Stream reader/writer for the TCP proxy entity
    tcp_stream_reader_writer: Arc<Mutex<Box<dyn StreamReaderWriter>>>,
    /// Channel sender for proxy (management) events
    proxy_channel_sender: sync::mpsc::Sender<ProxyEvent>,
    /// Indicates a request to close the proxy
    closing: Arc<Mutex<bool>>,
    /// Proxy closed/shutdown state value
    closed: Arc<Mutex<bool>>,
}

impl ChannelAndTcpStreamProxy {
    /// ChannelAndTcpStreamProxy constructor
    ///
    /// # Arguments
    ///
    /// * `proxy_key` - Unique key for this proxy
    /// * `socket_channel_addr` - Socket address corresponding to channel proxy entity
    /// * `socket_channel_receiver` - Channel receiver for inbound proxy events for the channel proxy entity
    /// * `socket_channel_sender` - Channel sender for outbound proxy events for the channel proxy entity
    /// * `tcp_stream` - TCP stream for the TCP proxy entity
    /// * `tcp_stream_reader_writer` - Stream reader/writer for the TCP proxy entity
    /// * `proxy_channel_sender` - Channel sender for proxy (management) events
    ///
    /// # Returns
    ///
    /// A [`Result`] containing a newly constructed [`ChannelAndTcpStreamProxy`] object.
    ///
    pub fn new(
        proxy_key: &str,
        socket_channel_addr: &SocketAddr,
        socket_channel_receiver: sync::mpsc::Receiver<ProxyEvent>,
        server_socket_channel_sender: &sync::mpsc::Sender<ProxyEvent>,
        tcp_stream: std::net::TcpStream,
        tcp_stream_reader_writer: &Arc<Mutex<Box<dyn StreamReaderWriter>>>,
        proxy_channel_sender: &sync::mpsc::Sender<ProxyEvent>,
    ) -> Result<Self, AppError> {
        // Convert tcp stream to non-blocking
        let tcp_stream = stream_utils::clone_std_tcp_stream(&tcp_stream, "tcpchannel-proxy")?;

        let proxy_key_copy = proxy_key.to_string();
        stream_utils::set_std_tcp_stream_blocking_and_delay(
            &tcp_stream,
            false,
            false,
            Box::new(move || format!("proxy_key={}", &proxy_key_copy)),
        )?;

        // Instantiate TcpStreamProxy
        Ok(ChannelAndTcpStreamProxy {
            proxy_key: proxy_key.to_string(),
            socket_channel_addr: *socket_channel_addr,
            socket_channel_receiver: Arc::new(Mutex::new(socket_channel_receiver)),
            server_socket_channel_sender: server_socket_channel_sender.clone(),
            tcp_stream,
            tcp_stream_reader_writer: tcp_stream_reader_writer.clone(),
            proxy_channel_sender: proxy_channel_sender.clone(),
            closing: Arc::new(Mutex::new(false)),
            closed: Arc::new(Mutex::new(false)),
        })
    }

    /// Connect client and server IO streams (spawn tasks to bidirectionally copy data)
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

        // Spawn thread task for copying from socket channel to TCP stream
        let channel_to_tcp_iocopy_handle = {
            let closing = self.closing.clone();
            let closed = self.closed.clone();
            let socket_channel_receiver = self.socket_channel_receiver.clone();
            let tcp_stream = mio::net::TcpStream::from_std(stream_utils::clone_std_tcp_stream(
                &self.tcp_stream,
                "tcpchannel-proxy",
            )?);
            let mut tcp_stream_reader_writer = self.tcp_stream_reader_writer.clone();
            let proxy_key = self.proxy_key.clone();
            let proxy_channel_sender = self.proxy_channel_sender.clone();

            thread::spawn(move || {
                let mut proxy_error = None;

                // IO events processing loop
                'EVENTS: while !*closing.lock().unwrap() {
                    // Get next received socket channel event
                    let socket_event: ProxyEvent =
                        match socket_channel_receiver.lock().unwrap().recv() {
                            Ok(_socket_event) => _socket_event,
                            Err(err) => {
                                proxy_error = Some(AppError::General(format!(
                                    "Error receiving proxy socket channel event: err={:?}",
                                    &err
                                )));
                                *closing.lock().unwrap() = true;
                                continue 'EVENTS;
                            }
                        };

                    // Process event
                    if let ProxyEvent::Message(_, _, data) = socket_event {
                        match stream_utils::encode_proxied_datagram(data.as_slice()) {
                            Ok(encoded_datagram) => {
                                match stream_utils::write_tcp_stream(
                                    &mut tcp_stream_reader_writer,
                                    &encoded_datagram,
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
                                error(
                                    &target!(),
                                    &format!(
                                        "Error encoding proxied datagram, discarding: err={:?}",
                                        &err
                                    ),
                                );
                                continue 'EVENTS;
                            }
                        }
                    }
                }

                // Close proxy connection stream
                Self::perform_shutdown(&proxy_key, &tcp_stream, &proxy_channel_sender, &closed);

                match proxy_error {
                    Some(err) => Err(err),
                    None => Ok(()),
                }
            })
        };

        // Spawn thread task for copying from TCP stream to socket channel
        let tcp_to_channel_iocopy_handle = {
            let closing = self.closing.clone();
            let closed = self.closed.clone();
            let socket_channel_addr = self.socket_channel_addr;
            let server_socket_channel_sender = self.server_socket_channel_sender.clone();
            let mut tcp_stream = mio::net::TcpStream::from_std(stream_utils::clone_std_tcp_stream(
                &self.tcp_stream,
                "tcpchannel-proxy",
            )?);
            let mut tcp_stream_reader_writer = self.tcp_stream_reader_writer.clone();
            let proxy_key = self.proxy_key.clone();
            let proxy_channel_sender = self.proxy_channel_sender.clone();

            thread::spawn(move || {
                // Setup MIO poller registry
                let mut poll: mio::Poll;

                match mio::Poll::new() {
                    Ok(_poll) => poll = _poll,
                    Err(err) => {
                        Self::perform_shutdown(
                            &proxy_key,
                            &tcp_stream,
                            &proxy_channel_sender,
                            &closed,
                        );
                        return Err(AppError::General(format!(
                            "Error creating new MIO poller: err={:?}",
                            &err
                        )));
                    }
                }

                if let Err(err) = poll.registry().register(
                    &mut tcp_stream,
                    TCP_STREAM_TOKEN,
                    mio::Interest::READABLE,
                ) {
                    Self::perform_shutdown(&proxy_key, &tcp_stream, &proxy_channel_sender, &closed);
                    return Err(AppError::General(format!(
                        "Error registering tcp stream in MIO registry: err={:?}",
                        &err
                    )));
                }

                let mut datagram_buffer = BytesMut::with_capacity(0);
                let mut events = mio::Events::with_capacity(4196);
                let mut proxy_error = None;

                // IO events processing loop
                'EVENTS: while !*closing.lock().unwrap() {
                    match poll.poll(
                        &mut events,
                        Some(Duration::from_millis(POLLING_DURATION_MSECS)),
                    ) {
                        Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                        Err(err) => {
                            proxy_error = Some(AppError::General(format!(
                                "Error while polling for IO events: err={:?}",
                                &err
                            )));
                            *closing.lock().unwrap() = true;
                            continue 'EVENTS;
                        }
                        _ => {}
                    }

                    for event in events.iter() {
                        if event.token() == TCP_STREAM_TOKEN {
                            match stream_utils::read_tcp_stream(&mut tcp_stream_reader_writer) {
                                Ok(data) => {
                                    if !data.is_empty() {
                                        datagram_buffer.extend_from_slice(data.as_slice());
                                        loop {
                                            match stream_utils::decode_proxied_datagram(
                                                &mut datagram_buffer,
                                            ) {
                                                Ok(None) => break,
                                                Ok(Some(datagram)) => {
                                                    let proxy_key_copy = proxy_key.clone();
                                                    match crate::sync::send_mpsc_channel_message(
                                                        &server_socket_channel_sender,
                                                        ProxyEvent::Message(
                                                            proxy_key.clone(),
                                                            socket_channel_addr,
                                                            datagram.to_vec(),
                                                        ),
                                                        Box::new(move || {
                                                            format!("Error sending socket message to channel: proxy_stream={},", &proxy_key_copy)
                                                        }),
                                                    ) {
                                                        Ok(()) => {}
                                                        Err(err) => {
                                                            proxy_error = Some(err);
                                                            *closing.lock().unwrap() = true;
                                                            continue 'EVENTS;
                                                        }
                                                    }
                                                }
                                                Err(err) => {
                                                    error(&target!(), &format!("Error decoding proxied datagram, discarding: err={:?}", &err));
                                                    datagram_buffer.clear();
                                                    continue 'EVENTS;
                                                }
                                            }
                                        }
                                    }
                                }
                                Err(err) => {
                                    proxy_error = Some(err);
                                    *closing.lock().unwrap() = true;
                                    continue 'EVENTS;
                                }
                            }
                        }
                    }
                }

                // Close proxy connection stream
                Self::perform_shutdown(&proxy_key, &tcp_stream, &proxy_channel_sender, &closed);

                match proxy_error {
                    Some(err) => Err(err),
                    None => Ok(()),
                }
            })
        };

        // Spawn thread to join IO copy threads
        let proxy_key = self.proxy_key.clone();

        thread::spawn(move || {
            let join_result = channel_to_tcp_iocopy_handle.join();
            if join_result.is_err() {
                error(
                    &target!(),
                    &format!(
                        "Error joining proxy channel to TCP stream IO copy task handle: err={:?}",
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

            let join_result = tcp_to_channel_iocopy_handle.join();
            if join_result.is_err() {
                error(
                    &target!(),
                    &format!(
                        "Error joining proxy TCP stream to channel IO copy task handle: err={:?}",
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
        proxy_channel_sender: &sync::mpsc::Sender<ProxyEvent>,
        closed_state: &Arc<Mutex<bool>>,
    ) {
        // Close proxy connection TCP stream
        match tcp_stream.shutdown(Shutdown::Both) {
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotConnected => {}
            Err(err) => error(
                &target!(),
                &format!(
                    "Error shutting down proxy tcp stream: proxy_stream={}, err={:?}",
                    &proxy_key, err
                ),
            ),
        }

        let proxy_key_copy = proxy_key.to_string();
        if let Err(err) = crate::sync::send_mpsc_channel_message(
            proxy_channel_sender,
            ProxyEvent::Closed(proxy_key.to_string()),
            Box::new(move || {
                format!(
                    "Error sending proxy closed message: proxy_stream={},",
                    &proxy_key_copy
                )
            }),
        ) {
            error(&target!(), &format!("{:?}", &err));
        }

        *closed_state.lock().unwrap() = true;
    }
}

impl ProxyStream for ChannelAndTcpStreamProxy {
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

unsafe impl Send for ChannelAndTcpStreamProxy {}

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::net::stream_utils::ConnectedTcpStream;
    use anyhow::Result;
    use std::io::ErrorKind::WouldBlock;
    use std::io::{Read, Write};
    use std::sync::mpsc::TryRecvError;

    fn create_channel_and_tcp_stream_proxy(
        proxy_key: &str,
        socket_channel_addr: &SocketAddr,
    ) -> Result<(
        ChannelAndTcpStreamProxy,
        sync::mpsc::Sender<ProxyEvent>,
        sync::mpsc::Receiver<ProxyEvent>,
        ConnectedTcpStream,
        (
            sync::mpsc::Sender<ProxyEvent>,
            sync::mpsc::Receiver<ProxyEvent>,
        ),
    )> {
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
        let proxy = ChannelAndTcpStreamProxy::new(
            proxy_key,
            &socket_channel_addr,
            socket_channel.1,
            &server_socket_channel.0,
            client_tcp_stream,
            &Arc::new(Mutex::new(client_reader_writer)),
            &proxy_channel.0,
        )?;
        Ok((
            proxy,
            socket_channel.0,
            server_socket_channel.1,
            connected_tcp_stream,
            proxy_channel,
        ))
    }

    #[test]
    fn channeltcpproxy_new() {
        let socket_channel_addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        if let Err(err) = create_channel_and_tcp_stream_proxy("key1", &socket_channel_addr) {
            panic!("Unexpected result: err={:?}", &err);
        }
    }

    #[test]
    fn channeltcpproxy_connect_when_channel_to_stream_copy() {
        let socket_channel_addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let mut proxy_result =
            create_channel_and_tcp_stream_proxy("key1", &socket_channel_addr).unwrap();

        if let Err(err) = proxy_result.0.connect() {
            panic!("Unexpected proxy connect result: err={:?}", &err);
        }

        let data = "hello".as_bytes();
        proxy_result
            .1
            .send(ProxyEvent::Message(
                "key1".to_string(),
                socket_channel_addr.clone(),
                data.to_vec(),
            ))
            .unwrap();

        thread::sleep(Duration::from_millis(10));
        *proxy_result.0.closing.lock().unwrap() = true;

        let mut buffer = [0u8; 10];
        proxy_result
            .3
            .server_stream
            .0
            .set_nonblocking(true)
            .unwrap();
        let read_result = proxy_result.3.server_stream.0.read(&mut buffer);
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
    fn channeltcpproxy_connect_when_no_channel_to_stream_copy() {
        let socket_channel_addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let mut proxy_result =
            create_channel_and_tcp_stream_proxy("key1", &socket_channel_addr).unwrap();

        if let Err(err) = proxy_result.0.connect() {
            panic!("Unexpected proxy connect result: err={:?}", &err);
        }

        thread::sleep(Duration::from_millis(10));
        *proxy_result.0.closing.lock().unwrap() = true;

        let mut buffer = [0u8; 10];
        proxy_result
            .3
            .server_stream
            .0
            .set_nonblocking(true)
            .unwrap();
        match proxy_result.3.server_stream.0.read(&mut buffer) {
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
    fn channeltcpproxy_connect_when_stream_to_channel_copy_one_message() {
        let socket_channel_addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let mut proxy_result =
            create_channel_and_tcp_stream_proxy("key1", &socket_channel_addr).unwrap();

        if let Err(err) = proxy_result.0.connect() {
            panic!("Unexpected proxy connect result: err={:?}", &err);
        }

        let data = &[0x00u8, 0x05u8, b'h', b'e', b'l', b'l', b'o'] as &[u8];
        if let Err(err) = proxy_result.3.server_stream.0.write_all(data) {
            panic!("Unexpected tcp stream write result: err={:?}", &err);
        }

        thread::sleep(Duration::from_millis(10));
        *proxy_result.0.closing.lock().unwrap() = true;

        let channel_read_result = proxy_result.2.try_recv();
        if let Err(err) = channel_read_result {
            panic!("Unexpected channel read result: err={:?}", &err);
        }

        let expected_data = (b"hello" as &[u8]).to_vec();

        let channel_proxy_event = channel_read_result.unwrap();
        match &channel_proxy_event {
            ProxyEvent::Message(result_key, result_addr, result_data) => {
                assert_eq!(*result_key, "key1".to_string());
                assert_eq!(*result_addr, socket_channel_addr);
                assert_eq!(*result_data, expected_data);
            }
            _ => panic!(
                "Unexpected channel proxy result: evt={:?}",
                &channel_proxy_event
            ),
        }

        let channel_read_result = proxy_result.2.try_recv();
        if let Ok(message) = channel_read_result {
            panic!(
                "Unexpected successful channel read result: msg={:?}",
                &message
            );
        }
    }

    #[test]
    fn channeltcpproxy_connect_when_stream_to_channel_copy_two_messages() {
        let socket_channel_addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let mut proxy_result =
            create_channel_and_tcp_stream_proxy("key1", &socket_channel_addr).unwrap();

        if let Err(err) = proxy_result.0.connect() {
            panic!("Unexpected proxy connect result: err={:?}", &err);
        }

        let data = &[
            0x00u8, 0x05u8, b'h', b'e', b'l', b'l', b'o', 0x00u8, 0x03u8, b'b', b'y', b'e',
        ] as &[u8];
        if let Err(err) = proxy_result.3.server_stream.0.write_all(data) {
            panic!("Unexpected tcp stream write result: err={:?}", &err);
        }

        thread::sleep(Duration::from_millis(10));
        *proxy_result.0.closing.lock().unwrap() = true;

        let channel_read_result = proxy_result.2.try_recv();
        if let Err(err) = channel_read_result {
            panic!("Unexpected channel read result: err={:?}", &err);
        }

        let expected_data = (b"hello" as &[u8]).to_vec();

        let channel_proxy_event = channel_read_result.unwrap();
        match &channel_proxy_event {
            ProxyEvent::Message(result_key, result_addr, result_data) => {
                assert_eq!(*result_key, "key1".to_string());
                assert_eq!(*result_addr, socket_channel_addr);
                assert_eq!(*result_data, expected_data);
            }
            _ => panic!(
                "Unexpected channel proxy result (first message): evt={:?}",
                &channel_proxy_event
            ),
        }

        let channel_read_result = proxy_result.2.try_recv();
        if let Err(err) = channel_read_result {
            panic!("Unexpected channel read result: err={:?}", &err);
        }

        let expected_data = (b"bye" as &[u8]).to_vec();

        let channel_proxy_event = channel_read_result.unwrap();
        match &channel_proxy_event {
            ProxyEvent::Message(result_key, result_addr, result_data) => {
                assert_eq!(*result_key, "key1".to_string());
                assert_eq!(*result_addr, socket_channel_addr);
                assert_eq!(*result_data, expected_data);
            }
            _ => panic!(
                "Unexpected channel proxy result (second message): evt={:?}",
                &channel_proxy_event
            ),
        }

        let channel_read_result = proxy_result.2.try_recv();
        if let Ok(message) = channel_read_result {
            panic!(
                "Unexpected successful channel read result: msg={:?}",
                &message
            );
        }
    }

    #[test]
    fn channeltcpproxy_connect_when_no_stream_to_channel_copy() {
        let socket_channel_addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let mut proxy_result =
            create_channel_and_tcp_stream_proxy("key1", &socket_channel_addr).unwrap();

        if let Err(err) = proxy_result.0.connect() {
            panic!("Unexpected proxy connect result: err={:?}", &err);
        }

        thread::sleep(Duration::from_millis(10));
        *proxy_result.0.closing.lock().unwrap() = true;

        match proxy_result.2.try_recv() {
            Ok(proxy_event) => panic!(
                "Unexpected successful proxy channel result: event={:?}",
                &proxy_event
            ),
            Err(err) => match err {
                TryRecvError::Disconnected => {
                    panic!("Unexpected disconnected proxy channel result")
                }
                TryRecvError::Empty => {}
            },
        }
    }

    #[test]
    fn channeltcpproxy_perform_shutdown() {
        let socket_channel_addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let proxy_result =
            create_channel_and_tcp_stream_proxy("key1", &socket_channel_addr).unwrap();
        let closed = Arc::new(Mutex::new(false));

        let tcp_stream = mio::net::TcpStream::from_std(
            stream_utils::clone_std_tcp_stream(
                &proxy_result.3.client_stream.0,
                "test-tcpchannel-proxy",
            )
            .unwrap(),
        );

        ChannelAndTcpStreamProxy::perform_shutdown(
            "key1",
            &tcp_stream,
            &proxy_result.4 .0,
            &closed,
        );

        match proxy_result.4 .1.try_recv() {
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
    fn channeltcpproxy_disconnect() {
        let socket_channel_addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let mut proxy_result =
            create_channel_and_tcp_stream_proxy("key1", &socket_channel_addr).unwrap();

        *proxy_result.0.closing.lock().unwrap() = false;
        *proxy_result.0.closed.lock().unwrap() = false;

        match proxy_result.0.disconnect() {
            Ok(()) => assert!(*proxy_result.0.closing.lock().unwrap()),
            Err(err) => panic!("Unexpected result: err={:?}", &err),
        }
    }
}
