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
