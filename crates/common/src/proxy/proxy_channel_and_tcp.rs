use std::net::{Shutdown, SocketAddr};
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
const POLLING_DURATION_MSECS: u64 = 1000;

/// Proxy based on a sync channel and a TCP stream
pub struct ChannelAndTcpStreamProxy {
    proxy_key: String,
    socket_channel_addr: SocketAddr,
    socket_channel_receiver: Arc<Mutex<sync::mpsc::Receiver<ProxyEvent>>>,
    server_socket_channel_sender: sync::mpsc::Sender<ProxyEvent>,
    tcp_stream: std::net::TcpStream,
    tcp_stream_reader_writer: Arc<Mutex<Box<dyn StreamReaderWriter>>>,
    proxy_channel_sender: sync::mpsc::Sender<ProxyEvent>,
    closing: Arc<Mutex<bool>>,
    closed: Arc<Mutex<bool>>,
}

impl ChannelAndTcpStreamProxy {
    /// ChannelAndTcpStreamProxy constructor
    pub fn new(
        proxy_key: &str,
        socket_channel_addr: SocketAddr,
        socket_channel_receiver: sync::mpsc::Receiver<ProxyEvent>,
        server_socket_channel_sender: sync::mpsc::Sender<ProxyEvent>,
        tcp_stream: std::net::TcpStream,
        tcp_stream_reader_writer: Arc<Mutex<Box<dyn StreamReaderWriter>>>,
        proxy_channel_sender: sync::mpsc::Sender<ProxyEvent>,
    ) -> Result<Self, AppError> {
        // Convert tcp stream to non-blocking
        let tcp_stream = stream_utils::clone_std_tcp_stream(&tcp_stream)?;

        tcp_stream.set_nonblocking(true).map_err(|err| {
            AppError::GenWithMsgAndErr(
                format!(
                    "Failed making tcp stream non-blocking: stream_addr={}",
                    &proxy_key
                ),
                Box::new(err),
            )
        })?;

        // Instantiate TcpStreamProxy
        Ok(ChannelAndTcpStreamProxy {
            proxy_key: proxy_key.to_string(),
            socket_channel_addr,
            socket_channel_receiver: Arc::new(Mutex::new(socket_channel_receiver)),
            server_socket_channel_sender,
            tcp_stream,
            tcp_stream_reader_writer,
            proxy_channel_sender,
            closing: Arc::new(Mutex::new(false)),
            closed: Arc::new(Mutex::new(false)),
        })
    }

    /// Connect client and server IO streams (spawn tasks to bidirectionally copy data)
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
                                proxy_error = Some(AppError::GenWithMsgAndErr(
                                    "Error receiving proxy socket channel event".to_string(),
                                    Box::new(err),
                                ));
                                *closing.lock().unwrap() = true;
                                continue 'EVENTS;
                            }
                        };

                    // Process event
                    if let ProxyEvent::Message(_, _, data) = socket_event {
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
                        return Err(AppError::GenWithMsgAndErr(
                            "Error creating new MIO poller".to_string(),
                            Box::new(err),
                        ));
                    }
                }

                if let Err(err) = poll.registry().register(
                    &mut tcp_stream,
                    TCP_STREAM_TOKEN,
                    mio::Interest::READABLE,
                ) {
                    Self::perform_shutdown(&proxy_key, &tcp_stream, &proxy_channel_sender, &closed);
                    return Err(AppError::GenWithMsgAndErr(
                        "Error registering tcp stream in MIO registry".to_string(),
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
                        if event.token() == TCP_STREAM_TOKEN {
                            match stream_utils::read_tcp_stream(&mut tcp_stream_reader_writer) {
                                Ok(data) => {
                                    if !data.is_empty() {
                                        match server_socket_channel_sender.send(
                                            ProxyEvent::Message(
                                                proxy_key.clone(),
                                                socket_channel_addr,
                                                data,
                                            ),
                                        ) {
                                            Ok(()) => {}
                                            Err(err) => {
                                                proxy_error = Some(AppError::GenWithMsgAndErr(
                                                    format!("Error sending socket message to channel: proxy_stream={}", &proxy_key),
                                                    Box::new(err)));
                                                *closing.lock().unwrap() = true;
                                                continue 'EVENTS;
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
