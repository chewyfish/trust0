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
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
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
