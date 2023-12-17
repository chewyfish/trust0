use clap::{ArgMatches, Command};
use clap::error::ErrorKind;
use serde_derive::{Deserialize, Serialize};

use crate::control::response;
use crate::error::AppError;

// Protocol text
pub const PROTOCOL_REQUEST_ABOUT: &str = "about";
pub const PROTOCOL_REQUEST_CONNECTIONS: &str = "connections";
pub const PROTOCOL_REQUEST_HELP: &str = "help";
pub const PROTOCOL_REQUEST_PING: &str = "ping";
pub const PROTOCOL_REQUEST_PROXIES: &str = "proxies";
pub const PROTOCOL_REQUEST_SERVICES: &str = "services";
pub const PROTOCOL_REQUEST_START: &str = "start";
pub const PROTOCOL_REQUEST_STOP: &str = "stop";
pub const PROTOCOL_REQUEST_VERSION: &str = "version";
pub const PROTOCOL_REQUEST_QUIT: &str = "quit";
pub const PROTOCOL_REQUEST_EXIT: &str = "exit";

// Help templates
const PARSER_TEMPLATE: &str = "\
        {all-args}
    ";

const COMMAND_TEMPLATE: &str = "\
        {about-with-newline}\n\
        {usage-heading}\n    {usage}\n\
        \n\
        {all-args}{after-help}\
    ";

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub enum Request {
    #[default]
    None,
    About,
    Connections,
    Ping,
    Proxies,
    Services,
    Start { service_name: String, local_port: u16 },
    Stop { service_name: String },
    Quit
}

pub struct RequestProcessor {
    command_processor: Command
}

impl RequestProcessor {

    /// ReplProtocol constructor
    pub fn new() -> Self {
        Self {
            command_processor: Self::create_command()
        }
    }

    /// Parse request command request text
    pub fn parse(&self, line: &str) -> Result<Request, AppError> {

        let line = line.trim();
        let line_as_args = shlex::split(line).ok_or(
            AppError::GenWithCodeAndMsg(response::CODE_BAD_REQUEST, format!("Invalid command line: line={}", line)))?;

        let parsed_command = self.command_processor.clone()
            .try_get_matches_from(line_as_args);

        if parsed_command.is_err() {
            let parse_error = parsed_command.err().unwrap();
            return match parse_error.kind() {
                ErrorKind::DisplayHelp => Err(AppError::GenWithCodeAndMsg(response::CODE_OK, parse_error.to_string())),
                ErrorKind::DisplayVersion => Err(AppError::GenWithCodeAndMsg(response::CODE_OK, parse_error.to_string())),
                _ => Err(AppError::GenWithCodeAndMsg(response::CODE_BAD_REQUEST, parse_error.to_string()))
            }
        }

        match parsed_command.unwrap().subcommand() {
            Some((PROTOCOL_REQUEST_ABOUT, _matches)) => Ok(Request::About),
            Some((PROTOCOL_REQUEST_CONNECTIONS, _matches)) => Ok(Request::Connections),
            Some((PROTOCOL_REQUEST_PING, _matches)) => Ok(Request::Ping),
            Some((PROTOCOL_REQUEST_PROXIES, _matches)) => Ok(Request::Proxies),
            Some((PROTOCOL_REQUEST_SERVICES, _matches)) => Ok(Request::Services),
            Some((PROTOCOL_REQUEST_START, matches)) => Self::parse_start_request(matches),
            Some((PROTOCOL_REQUEST_STOP, matches)) => Self::parse_stop_request(matches),
            Some((PROTOCOL_REQUEST_QUIT, _matches)) => Ok(Request::Quit),
            Some((name, _matches)) => {
                if name.is_empty() {
                    Ok(Request::None)
                } else {
                    Err(AppError::GenWithCodeAndMsg(response::CODE_BAD_REQUEST, format!("Unknown command: cmd={}", name)))
                }
            },
            None => unreachable!("subcommand required"),
        }
    }

    /// Parse "start" request
    fn parse_start_request(arg_matches: &ArgMatches) -> Result<Request, AppError> {

        let service_name = arg_matches.get_one::<String>("service");
        let local_port = arg_matches.get_one::<u16>("port");

        if service_name.is_none() {
            return Err(AppError::General(format!("Service name is required for the \"{}\" command", PROTOCOL_REQUEST_START)));
        }
        if local_port.is_none() {
            return Err(AppError::General(format!("Local port is required for the \"{}\" command", PROTOCOL_REQUEST_START)));
        }

        Ok(Request::Start {
            service_name: service_name.unwrap().clone(),
            local_port: *local_port.unwrap() })
    }

    /// Parse "stop" request
    fn parse_stop_request(arg_matches: &ArgMatches) -> Result<Request, AppError> {

        let service_name = arg_matches.get_one::<String>("service");

        if service_name.is_none() {
            return Err(AppError::General(format!("Service name is required for the \"{}\" command", PROTOCOL_REQUEST_STOP)));
        }

        Ok(Request::Stop { service_name: service_name.unwrap().clone() })
    }

    /// Create command processor
    fn create_command() -> Command {

        Command::new("repl")
            .multicall(true)
            //.disable_colored_help(true)
            .arg_required_else_help(true)
            .subcommand_required(true)
            .subcommand_value_name("COMMAND")
            .subcommand_help_heading("COMMANDS")
            .help_template(PARSER_TEMPLATE)
            .subcommand(
                Command::new(PROTOCOL_REQUEST_ABOUT)
                    .about("Display context information for connected mTLS device user")
                    .help_template(COMMAND_TEMPLATE),
            )
            .subcommand(
                Command::new(PROTOCOL_REQUEST_CONNECTIONS)
                    .about("List current service proxy connections")
                    .help_template(COMMAND_TEMPLATE),
            )
            .subcommand(
                Command::new(PROTOCOL_REQUEST_PING)
                    .about("Simple gateway heartbeat request")
                    .help_template(COMMAND_TEMPLATE),
            )
            .subcommand(
                Command::new(PROTOCOL_REQUEST_PROXIES)
                    .about("List active service proxies, ready for new connections")
                    .help_template(COMMAND_TEMPLATE),
            )
            .subcommand(
                Command::new(PROTOCOL_REQUEST_SERVICES)
                    .about("List authorized services for connected mTLS device user")
                    .help_template(COMMAND_TEMPLATE),
            )
            .subcommand(
                Command::new(PROTOCOL_REQUEST_START)
                    .about("Startup proxy to authorized service via secure client-gateway proxy")
                    .help_template(COMMAND_TEMPLATE)
                    .args(&[
                        clap::arg!(-s --service <SERVICE_NAME> "Corresponding service name for new proxy"),
                        clap::arg!(-p --port <LOCAL_PORT> "Client local port for service proxy")
                            .value_parser(clap::value_parser!(u16).range(1..))
                    ])
            )
            .subcommand(
                Command::new(PROTOCOL_REQUEST_STOP)
                    .about("Shutdown active service proxy (previously started)")
                    .help_template(COMMAND_TEMPLATE)
                    .args(&[
                        clap::arg!(-s --service <SERVICE_NAME> "Corresponding service name for proxy")
                    ])
            )
            .subcommand(
                Command::new(PROTOCOL_REQUEST_QUIT)
                    .alias(PROTOCOL_REQUEST_EXIT)
                    .about("Quit the control plane (and corresponding service connections)")
                    .help_template(COMMAND_TEMPLATE),
            )
    }
}

impl Default for RequestProcessor {
    fn default() -> Self {
        Self::new()
    }
}

/// Unit tests
#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn reqproc_parse_when_invalid_request() {

        let request_processor = RequestProcessor::new();

        match request_processor.parse("INVALID") {
            Ok(request) => panic!("Unexpected successful result: req={:?}", request),
            Err(err) => {
                assert!(err.get_code().is_some());
                assert_eq!(err.get_code().unwrap(), response::CODE_BAD_REQUEST);
            }
        }
    }

    #[test]
    fn reqproc_parse_when_help_request() {

        let request_processor = RequestProcessor::new();

        let result = request_processor.parse(PROTOCOL_REQUEST_HELP);

        if let Ok(request) = result {
            panic!("Unexpected successful result: req={:?}", request);
        }

        let parse_error = result.err().unwrap();

        assert!(parse_error.get_code().is_some());
        assert_eq!(response::CODE_OK, parse_error.get_code().unwrap());

        let expected_msg = "Response: code=200, msg=COMMANDS:\n  about        Display context information for connected mTLS device user\n  connections  List current service proxy connections\n  ping         Simple gateway heartbeat request\n  proxies      List active service proxies, ready for new connections\n  services     List authorized services for connected mTLS device user\n  start        Startup proxy to authorized service via secure client-gateway proxy\n  stop         Shutdown active service proxy (previously started)\n  quit         Quit the control plane (and corresponding service connections)\n  help         Print this message or the help of the given subcommand(s)\n".to_string();

        assert_eq!(parse_error.to_string(), expected_msg);
    }

    #[test]
    fn reqproc_parse_when_connections_request() {

        let request_processor = RequestProcessor::new();

        let result = request_processor.parse(PROTOCOL_REQUEST_CONNECTIONS);

        match result {
            Ok(request) => {
                match request {
                    Request::Connections => {}
                    _ => panic!("Unexpected successful result: req={:?}", request)
                }
            }
            Err(err) => panic!("Unexpected result: err={:?}", err)
        }
    }

    #[test]
    fn reqproc_parse_when_ping_request() {

        let request_processor = RequestProcessor::new();

        let result = request_processor.parse(PROTOCOL_REQUEST_PING);

        match result {
            Ok(request) => {
                match request {
                    Request::Ping => {}
                    _ => panic!("Unexpected successful result: req={:?}", request)
                }
            }
            Err(err) => panic!("Unexpected result: err={:?}", err)
        }
    }

    #[test]
    fn reqproc_parse_when_proxies_request() {

        let request_processor = RequestProcessor::new();

        let result = request_processor.parse(PROTOCOL_REQUEST_PROXIES);

        match result {
            Ok(request) => {
                match request {
                    Request::Proxies => {}
                    _ => panic!("Unexpected successful result: req={:?}", request)
                }
            }
            Err(err) => panic!("Unexpected result: err={:?}", err)
        }
    }

    #[test]
    fn reqproc_parse_when_services_request() {

        let request_processor = RequestProcessor::new();

        let result = request_processor.parse(PROTOCOL_REQUEST_SERVICES);

        match result {
            Ok(request) => {
                match request {
                    Request::Services => {}
                    _ => panic!("Unexpected successful result: req={:?}", request)
                }
            }
            Err(err) => panic!("Unexpected result: err={:?}", err)
        }
    }

    #[test]
    fn reqproc_parse_when_start_request() {

        let request_processor = RequestProcessor::new();

        let req_service_name = "svc1";
        let req_local_port = 3000;
        let request_str = format!("{} -s {} -p {}", PROTOCOL_REQUEST_START, req_service_name, req_local_port);

        let result = request_processor.parse(&request_str);

        match result {
            Ok(request) => {
                match request {
                    Request::Start { service_name, local_port } => {
                        assert_eq!(service_name, req_service_name);
                        assert_eq!(local_port, req_local_port);
                    }
                    _ => panic!("Unexpected successful result: req={:?}", request)
                }
            }
            Err(err) => panic!("Unexpected result: err={:?}", err)
        }
    }

    #[test]
    fn reqproc_parse_when_stop_request() {

        let request_processor = RequestProcessor::new();

        let req_service_name = "svc1";
        let request_str = format!("{} -s {}", PROTOCOL_REQUEST_STOP, req_service_name);

        let result = request_processor.parse(&request_str);

        match result {
            Ok(request) => {
                match request {
                    Request::Stop { service_name } => {
                        assert_eq!(service_name, req_service_name);
                    }
                    _ => panic!("Unexpected successful result: req={:?}", request)
                }
            }
            Err(err) => panic!("Unexpected result: err={:?}", err)
        }
    }

    #[test]
    fn reqproc_parse_when_quit_request() {

        let request_processor = RequestProcessor::new();

        let result = request_processor.parse(PROTOCOL_REQUEST_QUIT);

        match result {
            Ok(request) => {
                match request {
                    Request::Quit => {}
                    _ => panic!("Unexpected successful result: req={:?}", request)
                }
            }
            Err(err) => panic!("Unexpected result: err={:?}", err)
        }
    }

}