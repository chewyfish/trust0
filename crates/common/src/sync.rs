use crate::error::AppError;
use std::sync::mpsc;

/// Send a (MPSC) channel message
///
/// # Arguments
///
/// * `channel_sender` - MPSC channel sender (for generic type [`T`]
/// * `channel_msg` - Message to send on channel
/// * `err_msg_fn` - Function, which will return an error string (used on failure)
///
/// # Returns
///
/// A [`Result`] indicating success/failure of the channel sending operation.
///
pub fn send_mpsc_channel_message<T>(
    channel_sender: &mpsc::Sender<T>,
    channel_msg: T,
    err_msg_fn: Box<dyn Fn() -> String>,
) -> Result<(), AppError> {
    channel_sender
        .send(channel_msg)
        .map_err(|err| AppError::General(format!("{}, err={:?}", err_msg_fn(), &err)))
}
/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn sync_send_mpsc_channel_message_when_success() {
        let channel = mpsc::channel();

        if let Err(err) = send_mpsc_channel_message(
            &channel.0,
            "hello".to_string(),
            Box::new(|| "error".to_string()),
        ) {
            panic!("Unexpected result: err={:?}", &err);
        }

        match channel.1.try_recv() {
            Ok(msg) => assert_eq!(msg, "hello".to_string()),
            Err(err) => panic!("Unexpected received channel msg: err={:?}", &err),
        }
    }

    #[test]
    fn sync_send_mpsc_channel_message_when_failure() {
        let channel_sender = mpsc::channel().0;

        if send_mpsc_channel_message(
            &channel_sender,
            "hello".to_string(),
            Box::new(|| "error".to_string()),
        )
        .is_ok()
        {
            panic!("Unexpected successful result");
        }
    }
}
