use std::io;
use std::sync::mpsc;
use std::sync::mpsc::TryRecvError;
use crate::net::tls_client::conn_std::ConnectionEvent;

pub struct ChannelWriter {
    pub channel_sender: mpsc::Sender<Vec<u8>>
}

impl io::Write for ChannelWriter {

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.channel_sender.send(buf.to_vec())
            .map(|_| buf.len())
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

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

pub fn gather_rcvd_connection_channel_data(channel_receiver: &mpsc::Receiver<ConnectionEvent>) -> Vec<ConnectionEvent> {

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
