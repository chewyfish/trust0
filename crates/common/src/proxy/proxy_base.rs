use core::slice;
use std::iter::Iterator;

use crate::error::AppError;

pub const TCP_STREAM1_TOKEN: mio::Token = mio::Token(0);
pub const TCP_STREAM1_CLOSED_TOKEN: mio::Token = mio::Token(1);
pub const TCP_STREAM2_TOKEN: mio::Token = mio::Token(2);
pub const TCP_STREAM2_CLOSED_TOKEN: mio::Token = mio::Token(3);
pub const UDP_SOCKET1_TOKEN: mio::Token = mio::Token(4);
pub const UDP_SOCKET1_CLOSED_TOKEN: mio::Token = mio::Token(5);
pub const UDP_SOCKET2_TOKEN: mio::Token = mio::Token(6);
pub const UDP_SOCKET2_CLOSED_TOKEN: mio::Token = mio::Token(7);

/// Types of proxies
pub enum ProxyType {
    /// Proxy a channel and a TCP stream
    ChannelAndTcp,
    /// Proxy 2 TCP streams
    TcpAndTcp,
    /// Proxy a TCP stream and a UDP socket
    TcpAndUdp,
}

impl ProxyType {
    /// Short unique key for proxy type
    ///
    /// # Returns
    ///
    /// A string representing the proxy (will be unique across all active proxies).
    ///
    pub fn key_value(&self) -> String {
        match self {
            ProxyType::ChannelAndTcp => "C&T".to_string(),
            ProxyType::TcpAndTcp => "T&T".to_string(),
            ProxyType::TcpAndUdp => "T&U".to_string(),
        }
    }
}

/// Trait implemented by all proxy stream types
pub trait ProxyStream: Send {
    /// Disconnect active proxy
    ///
    /// # Returns
    ///
    /// A [`Result`] indicating success/failure of proxy disconnection.
    ///
    fn disconnect(&mut self) -> Result<(), AppError>;
}

/// Used to determine next processable MIO event tokens
pub struct EventTokens {
    pub events: mio::Events,
    pub initial_tokens: Vec<mio::Token>,
    pub ready_tokens: Vec<mio::Token>,
}

impl EventTokens {
    pub fn new(events: mio::Events, initial_tokens: Vec<mio::Token>) -> Self {
        EventTokens {
            events,
            initial_tokens,
            ready_tokens: vec![],
        }
    }

    pub fn iter(&mut self) -> EventTokensIter<'_> {
        self.ready_tokens.clear();
        for event in self.events.iter() {
            let token = match event.is_read_closed() {
                true => match event.token() {
                    TCP_STREAM1_TOKEN => TCP_STREAM1_CLOSED_TOKEN,
                    TCP_STREAM2_TOKEN => TCP_STREAM2_CLOSED_TOKEN,
                    UDP_SOCKET1_TOKEN => UDP_SOCKET1_CLOSED_TOKEN,
                    UDP_SOCKET2_TOKEN => UDP_SOCKET2_CLOSED_TOKEN,
                    _ => panic!("Unknown event token: token={:?}", event.token()),
                },
                false => event.token(),
            };
            self.ready_tokens.push(token);
        }

        EventTokensIter {
            initial_tokens_iter: self.initial_tokens.iter(),
            ready_tokens_iter: self.ready_tokens.iter(),
        }
    }
}

pub struct EventTokensIter<'a> {
    initial_tokens_iter: slice::Iter<'a, mio::Token>,
    ready_tokens_iter: slice::Iter<'a, mio::Token>,
}

impl<'a> Iterator for EventTokensIter<'a> {
    type Item = &'a mio::Token;

    /// Return next queued event token. Prefer initial tokens over [`mio::Events`] 'ready' events.
    ///
    /// Returns
    ///
    /// An optional event token
    ///
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(token) = self.initial_tokens_iter.next() {
            return Some(token);
        }
        self.ready_tokens_iter.next()
    }
}

// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn proxytype_key_value() {
        assert_eq!(ProxyType::ChannelAndTcp.key_value(), "C&T".to_string());
        assert_eq!(ProxyType::TcpAndTcp.key_value(), "T&T".to_string());
        assert_eq!(ProxyType::TcpAndUdp.key_value(), "T&U".to_string());
    }

    #[test]
    fn evttok_new() {
        let init_tokens = vec![mio::Token(0), mio::Token(1)];
        let events = mio::Events::with_capacity(5);

        let event_tokens = EventTokens::new(events, init_tokens);

        assert_eq!(
            event_tokens.initial_tokens,
            vec![mio::Token(0), mio::Token(1)]
        );
    }

    #[test]
    fn evttok_iter() {
        let init_tokens = vec![mio::Token(0), mio::Token(1)];
        let events = mio::Events::with_capacity(5);

        let mut event_tokens = EventTokens::new(events, init_tokens);
        let mut event_tokens_iter = event_tokens.iter();

        assert_eq!(event_tokens_iter.next(), Some(&mio::Token(0)));
        assert_eq!(event_tokens_iter.next(), Some(&mio::Token(1)));
        assert_eq!(event_tokens_iter.next(), None);
    }
}
