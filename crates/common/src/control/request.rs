use clap::{ArgMatches, Command};
use clap::error::ErrorKind;
use serde_derive::{Deserialize, Serialize};

use crate::control::response;
use crate::error::AppError;

// Protocol text
const PROTOCOL_REQUEST_ABOUT: &str = "about";
const PROTOCOL_REQUEST_CONNECTIONS: &str = "connections";
const PROTOCOL_REQUEST_PING: &str = "ping";
const PROTOCOL_REQUEST_PROXIES: &str = "proxies";
const PROTOCOL_REQUEST_SERVICES: &str = "services";
const PROTOCOL_REQUEST_START: &str = "start";
const PROTOCOL_REQUEST_STOP: &str = "stop";
const PROTOCOL_REQUEST_QUIT: &str = "quit";
const PROTOCOL_REQUEST_EXIT: &str = "exit";

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

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
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
            local_port: local_port.unwrap().clone() })
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
