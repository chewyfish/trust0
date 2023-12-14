use std::io;
use std::sync::mpsc;

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