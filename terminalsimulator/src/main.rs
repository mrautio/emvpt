use pcsc::{Context, Card, Scope, ShareMode, Protocols, MAX_BUFFER_SIZE, MAX_ATR_SIZE};
use regex::Regex;
use log::{error, warn, info, debug};
use log4rs;
use clap::{App, Arg};
use std::io::{self};
use std::{thread, time};
use std::str;

use emvpt::*;

static mut INTERACTIVE : bool = false;
static mut PIN_OPTION : Option<String> = None;

pub enum ReaderError {
    ReaderConnectionFailed(String),
    ReaderNotFound,
    CardConnectionFailed(String),
    CardNotFound
}

pub struct SmartCardConnection {
    ctx : Option<Context>,
    card : Option<Card>,
    pub contactless : bool
}

impl ApduInterface for SmartCardConnection {
    fn send_apdu(&self, apdu : &[u8]) -> Result<Vec<u8>, ()> {
        let mut output : Vec<u8> = Vec::new();

        let mut apdu_response_buffer = [0; MAX_BUFFER_SIZE];
        output.extend_from_slice(self.card.as_ref().unwrap().transmit(apdu, &mut apdu_response_buffer).unwrap());

        Ok(output)
    }
}

impl SmartCardConnection {
    pub fn new() -> SmartCardConnection {
        SmartCardConnection {
            ctx : None,
            card : None,
            contactless : false
        }
    }

    fn is_contactless_reader(&self, reader_name : &str) -> bool {
        if Regex::new(r"^ACS ACR12").unwrap().is_match(reader_name) {
            debug!("Card reader is deemed contactless");
            return true;
        }

        false
    }

    pub fn connect_to_card(&mut self) -> Result<(), ReaderError> {
        if !self.ctx.is_some() {
            self.ctx = match Context::establish(Scope::User) {
                Ok(ctx) => Some(ctx),
                Err(err) => {
                    return Err(ReaderError::ReaderConnectionFailed(format!("Failed to establish context: {}", err)));
                }
            };
        }

        let ctx = self.ctx.as_ref().unwrap();
        let readers_size = match ctx.list_readers_len() {
            Ok(readers_size) => readers_size,
            Err(err) => {
                return Err(ReaderError::ReaderConnectionFailed(format!("Failed to list readers size: {}", err)));
            }
        };

        let mut readers_buf = vec![0; readers_size];
        let readers = match ctx.list_readers(&mut readers_buf) {
            Ok(readers) => readers,
            Err(err) => {
                return Err(ReaderError::ReaderConnectionFailed(format!("Failed to list readers: {}", err)));
            }
        };

        for reader in readers {
            self.card = match ctx.connect(reader, ShareMode::Shared, Protocols::ANY) {
                Ok(card) => {
                    self.contactless = self.is_contactless_reader(reader.to_str().unwrap());

                    debug!("Card reader: {:?}, contactless:{}", reader, self.contactless);

                    Some(card)
                },
                _ => None
            };

            if self.card.is_some() {
                break;
            }
        }

        if self.card.is_some() {
            const MAX_NAME_SIZE : usize = 2048;
            let mut names_buffer = [0; MAX_NAME_SIZE];
            let mut atr_buffer = [0; MAX_ATR_SIZE];
            let card_status = self.card.as_ref().unwrap().status2(&mut names_buffer, &mut atr_buffer).unwrap();

            // https://www.eftlab.com/knowledge-base/171-atr-list-full/
            debug!("Card ATR:\n{:?}", card_status.atr());
            debug!("Card protocol: {:?}", card_status.protocol2().unwrap());
        } else {
            return Err(ReaderError::CardNotFound);
        }

        Ok(())
    }
}

fn pse_application_select(applications : &Vec<EmvApplication>) -> Result<EmvApplication, ()> {
    let user_interactive = unsafe { INTERACTIVE };

    if user_interactive && applications.len() > 1 {
        println!("Select payment application:");
        for i in 0..applications.len() {
            println!("{:02}. {}", i+1, str::from_utf8(&applications[i].label).unwrap());
        }

        print!("> ");

        let mut stdin_buffer = String::new();
        io::stdin().read_line(&mut stdin_buffer).unwrap();

        return Ok(applications[stdin_buffer.trim().parse::<usize>().unwrap() - 1].clone());
    }

    Ok(applications[0].clone())
}

fn pin_entry() -> Result<String, ()> {
    let user_interactive = unsafe { INTERACTIVE };
    unsafe {
        if PIN_OPTION.is_some() {
            return Ok(PIN_OPTION.as_ref().unwrap().to_string());
        }
    }


    let mut stdin_buffer = String::new();
    if user_interactive {
        println!("Enter PIN:");
        print!("> ");

        io::stdin().read_line(&mut stdin_buffer).unwrap();

        return Ok(stdin_buffer.trim().to_string());
    }

    Ok("".to_string())
}

fn amount_entry() -> Result<u64, ()> {
    let user_interactive = unsafe { INTERACTIVE };

    if user_interactive {
        println!("Enter amount:");
        print!("> ");
        let mut stdin_buffer = String::new();
        io::stdin().read_line(&mut stdin_buffer).unwrap();

        return Ok(format!("{:.0}", stdin_buffer.trim().parse::<f64>().unwrap() * 100.0).parse::<u64>().unwrap());
    }

    Ok(1)
}

fn run() -> Result<Option<String>, String> {
    log4rs::init_file("config/log4rs.yaml", Default::default()).unwrap();

    let matches = App::new("Minimum Viable Payment Terminal")
        .version("0.1")
        .about("EMV transaction simulation")
        .arg(Arg::with_name("interactive")
            .long("interactive")
            .help("Simulate payment terminal purchase sequence"))
        .arg(Arg::with_name("print-tags")
            .long("print-tags")
            .help("Print all read or generated tags"))
        .arg(Arg::with_name("pin")
            .short("p")
            .long("pin")
            .value_name("PIN CODE")
            .help("Card PIN code")
            .takes_value(true))
        .arg(Arg::with_name("settings")
            .short("s")
            .long("settings")
            .value_name("settings file")
            .help("Settings file location")
            .takes_value(true))
        .get_matches();

    unsafe {
        INTERACTIVE = matches.is_present("interactive");
        if matches.is_present("pin") {
            PIN_OPTION = Some(matches.value_of("pin").unwrap().to_string());
        }
    }
    let user_interactive = unsafe { INTERACTIVE };

    let print_tags = matches.is_present("print-tags");

    let mut connection = EmvConnection::new(&matches.value_of("settings").unwrap_or("config/settings.yaml").to_string()).unwrap();

    connection.pse_application_select_callback = Some(&pse_application_select);
    connection.pin_callback = Some(&pin_entry);
    connection.amount_callback = Some(&amount_entry);

    let purchase_amount = connection.amount_callback.unwrap()().unwrap();

    let mut smart_card_connection = SmartCardConnection::new();

    if let Err(err) = smart_card_connection.connect_to_card() {
        match err {
            ReaderError::CardNotFound => {
                if user_interactive {
                    println!("Please insert card");

                    loop {
                        match smart_card_connection.connect_to_card() {
                            Ok(_) => break,
                            Err(err) => {
                                match err {
                                    ReaderError::CardNotFound => {
                                        thread::sleep(time::Duration::from_millis(250));
                                    },
                                    _ => return Err("Could not connect to the reader".to_string())
                                }
                            }
                        }
                    }
                } else {
                    return Err("Card not found.".to_string());
                }
            },
            _ => return Err("Could not connect to the reader".to_string())
        }
    }

    connection.contactless = smart_card_connection.contactless;
    connection.interface = Some(&smart_card_connection);

    let application = connection.select_payment_application().unwrap();

    connection.process_settings().unwrap();
    connection.add_tag("9F02", bcdutil::ascii_to_bcd_n(format!("{}", purchase_amount).as_bytes(), 6).unwrap());

    connection.handle_get_processing_options().unwrap();

    connection.handle_public_keys(&application).unwrap();

    connection.handle_card_verification_methods().unwrap();

    connection.handle_terminal_risk_management().unwrap();

    connection.handle_terminal_action_analysis().unwrap();

    let mut purchase_successful = false;

    match connection.handle_1st_generate_ac().unwrap() {
        CryptogramType::AuthorisationRequestCryptogram => {
            if let CryptogramType::TransactionCertificate = connection.handle_2nd_generate_ac().unwrap() {
                purchase_successful = true;
            }
        },
        CryptogramType::TransactionCertificate => { purchase_successful = true; },
        CryptogramType::ApplicationAuthenticationCryptogram => { purchase_successful = false; }
    }

    if purchase_successful {
        info!("Purchase successful!");
    } else {
        warn!("Purchase unsuccessful!");
    }

    if print_tags {
        connection.print_tags();
    }

    Ok(None)
}

fn main() {
    std::process::exit(match run() {
        Ok(None) => 0,
        Ok(msg) => {
            warn!("{:?}", msg);
            0
        },
        Err(err) => {
            error!("{:?}", err);
            1
        }
    });
}
