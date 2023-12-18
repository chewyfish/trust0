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
pub type ChannelAndTcpProxyContext = (
    SocketAddr,                              // Channel's respective socket address
    sync::mpsc::Receiver<ProxyEvent>,        // receiver for incoming socket channel messages
    sync::mpsc::Sender<ProxyEvent>, // sender to send messages to UDP server socket (for client delivery from svc)
    std::net::TcpStream,            // TCP stream
    Arc<Mutex<Box<dyn StreamReaderWriter>>>, // TCP stream reader/writer
    sync::mpsc::Sender<ProxyEvent>, // channel sender to send back proxy events
);

/// Used to represent the context for the (TCP <-> TCP) streams proxy
pub type TcpAndTcpProxyContext = (
    std::net::TcpStream,                     // 1st TCP stream
    std::net::TcpStream,                     // 2nd TCP stream
    Arc<Mutex<Box<dyn StreamReaderWriter>>>, // 1st stream reader/writer
    Arc<Mutex<Box<dyn StreamReaderWriter>>>, // 2nd stream reader/writer
    sync::mpsc::Sender<ProxyEvent>,          // channel sender to send back proxy events
);

/// Used to represent the context for the (TCP <-> UDP) streams proxy
pub type TcpAndUdpProxyContext = (
    std::net::TcpStream,                     // TCP stream
    std::net::UdpSocket,                     // UDP socket
    Arc<Mutex<Box<dyn StreamReaderWriter>>>, // tcp stream reader/writer
    sync::mpsc::Sender<ProxyEvent>,          // channel sender to send back proxy events
);

/// Proxy executor event message
pub enum ProxyExecutorEvent {
    OpenChannelAndTcpProxy(ProxyKey, ChannelAndTcpProxyContext),
    OpenTcpAndTcpProxy(ProxyKey, TcpAndTcpProxyContext),
    OpenTcpAndUdpProxy(ProxyKey, TcpAndUdpProxyContext),
    Close(ProxyKey),
}

/// Service proxy executor to handle proxy lifecycle (setup, teardown)
pub struct ProxyExecutor {
    proxy_tasks_sender: std::sync::mpsc::Sender<ProxyExecutorEvent>,
    proxy_tasks_receiver: std::sync::mpsc::Receiver<ProxyExecutorEvent>,
    proxy_streams: HashMap<ProxyKey, Arc<Mutex<dyn ProxyStream>>>,
}

impl ProxyExecutor {
    /// ProxyExecutor constructor
    pub fn new() -> Self {
        let (proxy_tasks_sender, proxy_tasks_receiver) = std::sync::mpsc::channel();

        Self {
            proxy_tasks_sender,
            proxy_tasks_receiver,
            proxy_streams: HashMap::new(),
        }
    }

    /// Get a copy of the tasks sender
    pub fn clone_proxy_tasks_sender(&self) -> std::sync::mpsc::Sender<ProxyExecutorEvent> {
        self.proxy_tasks_sender.clone()
    }

    /// Listen and process any new proxy request tasks (blocking)
    pub fn poll_new_tasks(&mut self) -> Result<(), AppError> {
        loop {
            // Get next request task
            let task = self.proxy_tasks_receiver.recv().map_err(|err| {
                AppError::GenWithMsgAndErr(
                    "Error receiving new event task".to_string(),
                    Box::new(err),
                )
            })?;

            // Process task
            match task {
                // Open new Socket channel <-> TCP stream proxy
                ProxyExecutorEvent::OpenChannelAndTcpProxy(proxy_key, proxy_context) => {
                    let proxy_channel_sender = proxy_context.5.clone();

                    match ChannelAndTcpStreamProxy::new(
                        &proxy_key,
                        proxy_context.0,
                        proxy_context.1,
                        proxy_context.2,
                        proxy_context.3,
                        proxy_context.4,
                        proxy_context.5,
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

                            if let Err(err) =
                                proxy_channel_sender.send(ProxyEvent::Closed(proxy_key.clone()))
                            {
                                error(&target!(), &format!("Error sending proxy closed message: proxy_stream={}, err={:?}", &proxy_key, err));
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
                        proxy_context.2,
                        proxy_context.3,
                        proxy_context.4,
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

                            if let Err(err) =
                                proxy_channel_sender.send(ProxyEvent::Closed(proxy_key.clone()))
                            {
                                error(&target!(), &format!("Error sending proxy closed message: proxy_stream={}, err={:?}", &proxy_key, err));
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
                        proxy_context.2,
                        proxy_context.3,
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

                            if let Err(err) =
                                proxy_channel_sender.send(ProxyEvent::Closed(proxy_key.clone()))
                            {
                                error(&target!(), &format!("Error sending proxy closed message: proxy_stream={}, err={:?}", &proxy_key, err));
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
