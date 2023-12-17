use std::{io, sync, thread};
use std::net::Shutdown;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;

use crate::error::AppError;
use crate::logging::{error, info, warn};
use crate::net::stream_utils;
use crate::net::stream_utils::StreamReaderWriter;
use crate::proxy::event::ProxyEvent;
use crate::proxy::proxy_base::ProxyStream;
use crate::target;

const STREAM1_TOKEN: mio::Token = mio::Token(0);
const STREAM2_TOKEN: mio::Token = mio::Token(1);
const POLLING_DURATION_MSECS: u64 = 1000;

/// Proxy based on 2 connected TCP streams
pub struct TcpAndTcpStreamProxy {
    proxy_key: String,
    tcp_stream1: std::net::TcpStream,
    tcp_stream2: std::net::TcpStream,
    stream1_reader_writer: Arc<Mutex<Box<dyn StreamReaderWriter>>>,
    stream2_reader_writer: Arc<Mutex<Box<dyn StreamReaderWriter>>>,
    proxy_channel_sender: sync::mpsc::Sender<ProxyEvent>,
    closing: Arc<Mutex<bool>>,
    closed: Arc<Mutex<bool>>
}

impl TcpAndTcpStreamProxy {

    /// TcpAndTcpStreamProxy constructor
    pub fn new(proxy_key: &str,
               tcp_stream1: std::net::TcpStream,
               tcp_stream2: std::net::TcpStream,
               stream1_reader_writer: Arc<Mutex<Box<dyn StreamReaderWriter>>>,
               stream2_reader_writer: Arc<Mutex<Box<dyn StreamReaderWriter>>>,
               proxy_channel_sender: sync::mpsc::Sender<ProxyEvent>)
        -> Result<Self, AppError> {

        // Convert streams to non-blocking
        let tcp_stream1 = stream_utils::clone_std_tcp_stream(&tcp_stream1)?;
        let tcp_stream2 = stream_utils::clone_std_tcp_stream(&tcp_stream2)?;

        tcp_stream1.set_nonblocking(true).map_err(|err|
            AppError::GenWithMsgAndErr(format!("Failed making stream 1 socket non-blocking: proxy_stream={}", &proxy_key), Box::new(err)))?;
        tcp_stream2.set_nonblocking(true).map_err(|err|
            AppError::GenWithMsgAndErr(format!("Failed making stream 2 socket non-blocking: proxy_stream={}", &proxy_key), Box::new(err)))?;

        // Instantiate TcpStreamProxy
        Ok(TcpAndTcpStreamProxy {
            proxy_key: proxy_key.to_string(),
            tcp_stream1,
            tcp_stream2,
            stream1_reader_writer,
            stream2_reader_writer,
            proxy_channel_sender,
            closing: Arc::new(Mutex::new(false)),
            closed: Arc::new(Mutex::new(false))
        })
    }

    /// Connect tcp IO streams (spawn task to bidirectionally copy data)
    pub fn connect(&mut self) -> Result<(), AppError> {

        info(&target!(), &format!("Starting proxy: proxy_stream={}", &self.proxy_key));

        *self.closing.lock().unwrap() = false;

        // Spawn bidirectional stream IO copy task
        let closing = self.closing.clone();
        let closed = self.closed.clone();
        let tcp_stream1 = stream_utils::clone_std_tcp_stream(&self.tcp_stream1)?;
        let tcp_stream2 = stream_utils::clone_std_tcp_stream(&self.tcp_stream2)?;
        let mut stream1_reader_writer = self.stream1_reader_writer.clone();
        let mut stream2_reader_writer = self.stream2_reader_writer.clone();
        let proxy_key = self.proxy_key.clone();
        let proxy_channel_sender = self.proxy_channel_sender.clone();

        let bidirectional_iocopy_handle = thread::spawn(move || {

            let mut tcp_stream1 = mio::net::TcpStream::from_std(tcp_stream1);
            let mut tcp_stream2 = mio::net::TcpStream::from_std(tcp_stream2);

            // Setup MIO poller registry
            let mut poll: mio::Poll;

            match mio::Poll::new() {
                Ok(_poll) => poll = _poll,
                Err(err) => {
                    Self::perform_shutdown(&proxy_key, &tcp_stream1, &tcp_stream2, &proxy_channel_sender, &closed);
                    return Err(AppError::GenWithMsgAndErr("Error creating new MIO poller".to_string(), Box::new(err)));
                }
            }

            if let Err(err) = poll.registry().register(&mut tcp_stream1,
                                                       STREAM1_TOKEN, mio::Interest::READABLE) {
                Self::perform_shutdown(&proxy_key, &tcp_stream1, &tcp_stream2, &proxy_channel_sender, &closed);
                return Err(AppError::GenWithMsgAndErr("Error registering tcp stream 1 in MIO registry".to_string(), Box::new(err)));
            }

            if let Err(err) = poll.registry().register(&mut tcp_stream2,
                                                       STREAM2_TOKEN, mio::Interest::READABLE) {
                Self::perform_shutdown(&proxy_key, &tcp_stream1, &tcp_stream2, &proxy_channel_sender, &closed);
                return Err(AppError::GenWithMsgAndErr("Error registering tcp stream 2 in MIO registry".to_string(), Box::new(err)));
            }

            let mut events = mio::Events::with_capacity(256);
            let mut proxy_error = None;

            // IO events processing loop
            'EVENTS:
            while !*closing.lock().unwrap() {

                match poll.poll(&mut events, Some(Duration::from_millis(POLLING_DURATION_MSECS))) {
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(err) => {
                        proxy_error = Some(AppError::GenWithMsgAndErr("Error while polling for IO events".to_string(), Box::new(err)));
                        *closing.lock().unwrap() = true;
                        continue 'EVENTS;
                    },
                    _ => {}
                }

                for event in events.iter() {

                    match event.token() {

                        STREAM1_TOKEN => {
                            match stream_utils::read_tcp_stream(&mut stream1_reader_writer) {
                                Ok(data) => {
                                    match stream_utils::write_tcp_stream(&mut stream2_reader_writer, data.as_slice()) {
                                        Ok(()) => {}
                                        Err(err) => match err {
                                            AppError::WouldBlock => continue,
                                            AppError::StreamEOF => break 'EVENTS,
                                            _ => {
                                                proxy_error = Some(err);
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

                            if let Err(err) = poll.registry().reregister(&mut tcp_stream1,
                                                                         STREAM1_TOKEN, mio::Interest::READABLE) {
                                proxy_error = Some(AppError::GenWithMsgAndErr("Error registering tcp stream 1 in MIO registry".to_string(), Box::new(err)));
                                *closing.lock().unwrap() = true;
                                continue 'EVENTS;
                            }
                        }

                        STREAM2_TOKEN => {
                            match stream_utils::read_tcp_stream(&mut stream2_reader_writer) {
                                Ok(data) => {
                                    match stream_utils::write_tcp_stream(&mut stream1_reader_writer, data.as_slice()) {
                                        Ok(()) => {}
                                        Err(err) => match err {
                                            AppError::WouldBlock => continue,
                                            AppError::StreamEOF => break 'EVENTS,
                                            _ => {
                                                proxy_error = Some(err);
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

                            if let Err(err) = poll.registry().reregister(&mut tcp_stream2,
                                                                         STREAM2_TOKEN, mio::Interest::READABLE) {
                                proxy_error = Some(AppError::GenWithMsgAndErr("Error registering tcp stream 2 in MIO registry".to_string(), Box::new(err)));
                                *closing.lock().unwrap() = true;
                                continue 'EVENTS;
                            }
                        }

                        _ => {}
                    }
                }
            }

            // Shutdown proxy resources
            Self::perform_shutdown(&proxy_key, &tcp_stream1, &tcp_stream2, &proxy_channel_sender, &closed);

            match proxy_error {
                Some(err) => Err(err),
                None => Ok(())
            }
        });

        // Spawn thread to join IO copy thread
        let proxy_key = self.proxy_key.clone();

        thread::spawn(move || {
            let join_result = bidirectional_iocopy_handle.join();
            if join_result.is_err() {
                error(&target!(), &format!("Error joining proxy IO copy task handle: err={:?}", join_result.as_ref().err().unwrap()));
            }
            if let Err(err) = join_result.unwrap() {
                match err {
                    AppError::StreamEOF => {}
                    _ => error(&target!(), &format!("{:?}", err))
                }
            }

            info(&target!(), &format!("Stopped proxy: proxy_stream={}", &proxy_key));
        });

        *self.closed.lock().unwrap() = false;

        Ok(())
    }

    /// Shutdown proxy resources (called by proxy thread on termination)
    fn perform_shutdown(proxy_key: &str,
                        tcp_stream1: &mio::net::TcpStream,
                        tcp_stream2: &mio::net::TcpStream,
                        proxy_channel_sender: &sync::mpsc::Sender<ProxyEvent>,
                        closed_state: &Arc<Mutex<bool>>) {

        // Close proxy connection streams
        match tcp_stream1.shutdown(Shutdown::Both) {
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotConnected => {}
            Err(err) => error(&target!(), &format!("Error shutting down proxy tcp stream 1: proxy_stream={}, err={:?}", &proxy_key, err))
        }

        match tcp_stream2.shutdown(Shutdown::Both) {
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotConnected => {}
            Err(err) => error(&target!(), &format!("Error shutting down proxy tcp stream 2: proxy_stream={}, err={:?}", &proxy_key, err))
        }

        if let Err(err) = proxy_channel_sender.send(ProxyEvent::Closed(proxy_key.to_string())) {
            error(&target!(), &format!("Error sending proxy closed message: proxy_stream={}, err={:?}", &proxy_key, err));
        }

        *closed_state.lock().unwrap() = true;
    }
}

impl ProxyStream for TcpAndTcpStreamProxy {

    fn disconnect(&mut self) -> Result<(), AppError> {

        if *self.closed.lock().unwrap() {
            warn(&target!(), &format!("Proxy already stopped: proxy_stream={}", &self.proxy_key));
        } else {
            info(&target!(), &format!("Stopping proxy: proxy_stream={}", &self.proxy_key));
        }

        *self.closing.lock().unwrap() = true;

        Ok(())
    }
}

unsafe impl Send for TcpAndTcpStreamProxy {}
