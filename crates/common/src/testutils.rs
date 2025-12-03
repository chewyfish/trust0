use crate::error::AppError;
use crate::net::tls_client::conn_std::ConnectionEvent;
use once_cell::sync::Lazy;
use std::path::PathBuf;
use std::sync::mpsc::TryRecvError;
use std::sync::{mpsc, Arc, Mutex};
use std::{env, io};

pub static TEST_MUTEX: Lazy<Arc<Mutex<bool>>> = Lazy::new(|| Arc::new(Mutex::new(true)));

pub const XDG_ROOT_DIR_PATHPARTS: [&str; 6] = [
    env!("CARGO_MANIFEST_DIR"),
    "..",
    "..",
    "target",
    "test-common",
    "xdgroot",
];

/// Wraps a byte vector channel sender
pub struct ChannelWriter {
    /// Byte vector channel sender
    pub channel_sender: mpsc::Sender<Vec<u8>>,
}

impl io::Write for ChannelWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.channel_sender
            .send(buf.to_vec())
            .map(|_| buf.len())
            .map_err(io::Error::other)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Receive all pending channel bytes vectors and flatten result
///
/// # Arguments
///
/// * `channel_receiver` - A byte vector channel receiver
///
/// # Returns
///
/// A byte vector of the received channel data (all data flattened to a single byte vector)
///
pub fn gather_rcvd_bytearr_channel_data(channel_receiver: &mpsc::Receiver<Vec<u8>>) -> Vec<u8> {
    let mut rcvd_data: Vec<u8> = vec![];
    loop {
        let rcvd_result = channel_receiver.try_recv();
        if let Err(err) = rcvd_result {
            if let TryRecvError::Empty = err {
                break;
            }
            panic!("Unexpected received bytearray result: err={:?}", &err);
        }
        rcvd_data.append(&mut rcvd_result.unwrap());
    }
    rcvd_data
}

/// Receive all pending channel connection events and return the events
///
/// # Arguments
///
/// * `channel_receiver` - A [`ConnectionEvent`] channel receiver
///
/// # Returns
///
/// A vector of received [`ConnectionEvent`] objects.
///
pub fn gather_rcvd_connection_channel_data(
    channel_receiver: &mpsc::Receiver<ConnectionEvent>,
) -> Vec<ConnectionEvent> {
    let mut rcvd_data: Vec<ConnectionEvent> = vec![];
    loop {
        let rcvd_result = channel_receiver.try_recv();
        if let Err(err) = rcvd_result {
            if let TryRecvError::Empty = err {
                break;
            }
            panic!("Unexpected received connevt result: err={:?}", &err);
        }
        rcvd_data.push(rcvd_result.unwrap());
    }
    rcvd_data
}

/// Set up the XDG environment variables for the testing environment pathing.
///
/// # Returns
///
/// A [`Result`] indicating success/failure of the XDG environment variable settings.
///
pub fn setup_xdg_vars() -> Result<(), AppError> {
    let xdg_root_dir: PathBuf = XDG_ROOT_DIR_PATHPARTS.iter().collect();

    env::set_var(
        "XDG_DATA_HOME",
        xdg_root_dir.clone().join("data").to_str().unwrap(),
    );
    env::set_var(
        "XDG_CONFIG_HOME",
        xdg_root_dir.clone().join("config").to_str().unwrap(),
    );
    env::set_var(
        "XDG_CACHE_HOME",
        xdg_root_dir.clone().join("cache").to_str().unwrap(),
    );

    Ok(())
}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testutils_gather_rcvd_bytearr_channel_data() {
        let channel = mpsc::channel();
        let mut data0 = "hi".as_bytes().to_vec();
        let mut data1 = "there".as_bytes().to_vec();

        channel.0.send(data0.clone()).unwrap();
        channel.0.send(data1.clone()).unwrap();

        let received_data = gather_rcvd_bytearr_channel_data(&channel.1);

        data0.append(&mut data1);
        assert_eq!(received_data, data0);
    }

    #[test]
    fn testutils_gather_rcvd_connection_channel_data() {
        let channel = mpsc::channel();

        channel
            .0
            .send(ConnectionEvent::Write("hi".as_bytes().to_vec()))
            .unwrap();
        channel.0.send(ConnectionEvent::Closed).unwrap();

        let received_events = gather_rcvd_connection_channel_data(&channel.1);

        let expected_events = vec![
            ConnectionEvent::Write("hi".as_bytes().to_vec()),
            ConnectionEvent::Closed,
        ];

        assert_eq!(received_events, expected_events);
    }

    #[test]
    fn testutils_setup_xdg_vars() {
        let result = setup_xdg_vars();

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        assert!(env::var("XDG_DATA_HOME")
            .unwrap()
            .replace(&['/', '\\'], "|")
            .ends_with("|target|test-common|xdgroot|data"));
        assert!(env::var("XDG_CONFIG_HOME")
            .unwrap()
            .replace(&['/', '\\'], "|")
            .ends_with("|target|test-common|xdgroot|config"));
        assert!(env::var("XDG_CACHE_HOME")
            .unwrap()
            .replace(&['/', '\\'], "|")
            .ends_with("|target|test-common|xdgroot|cache"));
    }
}
