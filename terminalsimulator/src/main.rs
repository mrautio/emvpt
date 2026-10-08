use clap::{Parser, ValueEnum};
use hex;
use log::{debug, error, info, warn};
use log4rs;
use pcsc::{Card, Context, Protocols, Scope, ShareMode, MAX_ATR_SIZE, MAX_BUFFER_SIZE};
use regex::Regex;
use std::io::{self};
use std::path::PathBuf;
use std::str;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::{thread, time};

use emvpt::*;

static INTERACTIVE: AtomicBool = AtomicBool::new(false);
static PIN_OPTION: OnceLock<Option<String>> = OnceLock::new();

pub enum ReaderError {
    ReaderConnectionFailed(String),
    ReaderNotFound,
    CardConnectionFailed(String),
    CardNotFound,
}

/// Card interface of the transaction
#[derive(Clone, Copy, PartialEq, ValueEnum)]
pub enum CardInterface {
    /// Deduce the interface from the card reader name
    Auto,
    /// Contact chip transaction
    Contact,
    /// Contactless transaction
    Contactless,
}

pub struct SmartCardConnection {
    ctx: Option<Context>,
    card: Option<Card>,
    pub contactless: bool,
    interface: CardInterface,
}

impl ApduInterface for SmartCardConnection {
    fn send_apdu(&self, apdu: &[u8]) -> Result<Vec<u8>, EmvError> {
        let Some(card) = self.card.as_ref() else {
            return Err(EmvError::Interface("Card not connected".to_string()));
        };

        let mut apdu_response_buffer = [0; MAX_BUFFER_SIZE];
        let response = card
            .transmit(apdu, &mut apdu_response_buffer)
            .map_err(|err| EmvError::Interface(format!("Transmit failed: {}", err)))?;

        Ok(response.to_vec())
    }
}

impl SmartCardConnection {
    pub fn new(interface: CardInterface) -> SmartCardConnection {
        SmartCardConnection {
            ctx: None,
            card: None,
            contactless: false,
            interface: interface,
        }
    }

    // Dual interface readers list the contactless interface as a separate PICC / contactless reader
    fn is_contactless_reader(reader_name: &str) -> bool {
        Regex::new(r"(?i)^ACS ACR12|PICC|contactless")
            .unwrap()
            .is_match(reader_name)
    }

    pub fn connect_to_card(&mut self) -> Result<(), ReaderError> {
        if !self.ctx.is_some() {
            self.ctx = match Context::establish(Scope::User) {
                Ok(ctx) => Some(ctx),
                Err(err) => {
                    return Err(ReaderError::ReaderConnectionFailed(format!(
                        "Failed to establish context: {}",
                        err
                    )));
                }
            };
        }

        let ctx = self.ctx.as_ref().unwrap();
        let readers_size = match ctx.list_readers_len() {
            Ok(readers_size) => readers_size,
            Err(err) => {
                return Err(ReaderError::ReaderConnectionFailed(format!(
                    "Failed to list readers size: {}",
                    err
                )));
            }
        };

        let mut readers_buf = vec![0; readers_size];
        let readers = match ctx.list_readers(&mut readers_buf) {
            Ok(readers) => readers,
            Err(err) => {
                return Err(ReaderError::ReaderConnectionFailed(format!(
                    "Failed to list readers: {}",
                    err
                )));
            }
        };

        // With an explicit interface the readers of that interface are tried first. A reader that does not look like one of
        // that interface is still used if it is the only one with a card, the interface is then taken as given.
        let mut readers: Vec<_> = readers
            .map(|reader| {
                let contactless_reader =
                    SmartCardConnection::is_contactless_reader(&reader.to_string_lossy());
                (reader, contactless_reader)
            })
            .collect();
        match self.interface {
            CardInterface::Auto => (),
            CardInterface::Contact => readers.sort_by_key(|(_, contactless)| *contactless),
            CardInterface::Contactless => readers.sort_by_key(|(_, contactless)| !*contactless),
        }

        for (reader, contactless_reader) in readers {
            self.card = match ctx.connect(reader, ShareMode::Shared, Protocols::ANY) {
                Ok(card) => {
                    self.contactless = match self.interface {
                        CardInterface::Auto => contactless_reader,
                        CardInterface::Contact => false,
                        CardInterface::Contactless => true,
                    };

                    if self.contactless != contactless_reader {
                        warn!(
                            "Card reader {:?} is deemed {}, {} interface used as requested",
                            reader,
                            if contactless_reader {
                                "contactless"
                            } else {
                                "contact"
                            },
                            if self.contactless {
                                "contactless"
                            } else {
                                "contact"
                            }
                        );
                    }

                    debug!(
                        "Card reader: {:?}, contactless:{}",
                        reader, self.contactless
                    );

                    Some(card)
                }
                _ => None,
            };

            if self.card.is_some() {
                break;
            }
        }

        if self.card.is_some() {
            const MAX_NAME_SIZE: usize = 2048;
            let mut names_buffer = [0; MAX_NAME_SIZE];
            let mut atr_buffer = [0; MAX_ATR_SIZE];
            let card_status = self
                .card
                .as_ref()
                .unwrap()
                .status2(&mut names_buffer, &mut atr_buffer)
                .unwrap();

            // https://www.eftlab.com/knowledge-base/171-atr-list-full/
            debug!(
                "Card ATR:\n{}",
                format!("{:02X?}", card_status.atr()).replace(
                    |c: char| !(c.is_ascii_alphanumeric() || c.is_ascii_whitespace()),
                    ""
                )
            );
            debug!("Card protocol: {:?}", card_status.protocol2().unwrap());
        } else {
            return Err(ReaderError::CardNotFound);
        }

        Ok(())
    }
}

fn pse_application_select(applications: &[EmvApplication]) -> Result<EmvApplication, EmvError> {
    let user_interactive = INTERACTIVE.load(Ordering::Relaxed);

    if user_interactive && applications.len() > 1 {
        println!("Select payment application:");
        for i in 0..applications.len() {
            println!(
                "{:02}. {}",
                i + 1,
                String::from_utf8_lossy(&applications[i].label)
            );
        }

        print!("> ");

        let mut stdin_buffer = String::new();
        io::stdin()
            .read_line(&mut stdin_buffer)
            .map_err(|err| EmvError::Callback(err.to_string()))?;

        return stdin_buffer
            .trim()
            .parse::<usize>()
            .ok()
            .and_then(|i| applications.get(i.checked_sub(1)?))
            .cloned()
            .ok_or_else(|| EmvError::Callback("Invalid application selection".to_string()));
    }

    Ok(applications[0].clone())
}

fn pin_entry() -> Result<String, EmvError> {
    let user_interactive = INTERACTIVE.load(Ordering::Relaxed);
    if let Some(Some(pin)) = PIN_OPTION.get() {
        return Ok(pin.clone());
    }

    if user_interactive {
        println!("Enter PIN:");
        print!("> ");

        return rpassword::read_password()
            .map(|pin| pin.trim().to_string())
            .map_err(|err| EmvError::Callback(err.to_string()));
    }

    Ok("".to_string())
}

fn amount_entry() -> Result<u64, EmvError> {
    let user_interactive = INTERACTIVE.load(Ordering::Relaxed);

    if user_interactive {
        println!("Enter amount:");
        print!("> ");
        let mut stdin_buffer = String::new();
        io::stdin()
            .read_line(&mut stdin_buffer)
            .map_err(|err| EmvError::Callback(err.to_string()))?;

        return match stdin_buffer.trim().parse::<f64>() {
            Ok(amount) if amount >= 0.0 => Ok((amount * 100.0).round() as u64),
            _ => Err(EmvError::Callback("Invalid amount".to_string())),
        };
    }

    Ok(1)
}

#[derive(Parser)]
#[command(version = "0.1")]
#[command(about = "EMV transaction simulation", long_about = None)]
struct Args {
    /// Simulate payment terminal purchase sequence
    #[arg(long, default_value_t = false)]
    interactive: bool,

    /// Print all read or generated tags
    #[arg(long = "print-tags", default_value_t = false)]
    print_tags: bool,

    /// Censor sensitive data from the output
    #[arg(long = "censor-sensitive-fields", default_value_t = false)]
    censor_sensitive_fields: bool,

    /// Exit after connecting the card
    #[arg(long = "stop-after-connect", default_value_t = false)]
    stop_after_connect: bool,

    /// Stop processing transaction after card data has been read
    #[arg(long = "stop-after-read", default_value_t = false)]
    stop_after_read: bool,

    /// Card PIN code to be used when PIN code is required
    #[arg(short, long, value_name = "PIN CODE")]
    pin: Option<String>,

    /// Terminal settings file
    #[arg(
        short,
        long,
        value_name = "settings file",
        default_value = "config/settings.yaml"
    )]
    settings: PathBuf,

    /// Print TLV data in human readable form
    #[arg(long, value_name = "TLV")]
    print_tlv: Option<String>,

    /// Card interface, auto deduces it from the card reader name
    #[arg(long, value_enum, default_value_t = CardInterface::Auto)]
    interface: CardInterface,
}

fn run() -> Result<Option<String>, String> {
    log4rs::init_file("config/log4rs.yaml", Default::default()).unwrap();

    let args = Args::parse();

    INTERACTIVE.store(args.interactive, Ordering::Relaxed);
    let _ = PIN_OPTION.set(args.pin);
    let user_interactive = INTERACTIVE.load(Ordering::Relaxed);
    let censor_sensitive_fields = args.censor_sensitive_fields;
    let stop_after_connect = args.stop_after_connect;
    let stop_after_read = args.stop_after_read;
    let print_tags = args.print_tags;
    let print_tlv = args.print_tlv;

    let mut connection =
        EmvConnection::new(&args.settings.to_string_lossy()).map_err(|err| err.to_string())?;

    connection.settings.censor_sensitive_fields = censor_sensitive_fields;
    connection.pse_application_select_callback = Some(Box::new(pse_application_select));
    connection.pin_callback = Some(Box::new(pin_entry));

    if print_tlv.is_some() {
        let tlv_hex_data = print_tlv
            .unwrap()
            .replace(|c: char| !(c.is_ascii_alphanumeric()), "");
        info!("input TLV: {}", tlv_hex_data);
        let tlv_data = hex::decode(&tlv_hex_data).map_err(|err| err.to_string())?;
        connection.process_tlv(&tlv_data[..], 0);
        return Ok(None);
    }

    let purchase_amount = amount_entry().map_err(|err| err.to_string())?;

    let mut smart_card_connection = SmartCardConnection::new(args.interface);

    if let Err(err) = smart_card_connection.connect_to_card() {
        match err {
            ReaderError::CardNotFound => {
                if user_interactive {
                    println!("Please insert card");

                    loop {
                        match smart_card_connection.connect_to_card() {
                            Ok(_) => break,
                            Err(err) => match err {
                                ReaderError::CardNotFound => {
                                    thread::sleep(time::Duration::from_millis(250));
                                }
                                _ => return Err("Could not connect to the reader".to_string()),
                            },
                        }
                    }
                } else {
                    return Err("Card not found.".to_string());
                }
            }
            _ => return Err("Could not connect to the reader".to_string()),
        }
    }

    if stop_after_connect {
        return Ok(None);
    }

    connection.contactless = smart_card_connection.contactless;
    connection.interface = Some(Box::new(smart_card_connection));

    let purchase_successful = purchase(&mut connection, purchase_amount, stop_after_read)
        .map_err(|err| format!("Transaction terminated: {}", err))?;

    match purchase_successful {
        Some(true) => info!("Purchase successful!"),
        Some(false) => warn!("Purchase unsuccessful!"),
        None => (),
    }

    if print_tags {
        connection.print_tags();
    }

    Ok(None)
}

/// Purchase sequence made of the transaction steps of the library, None when stopped after reading the card data
fn purchase(
    connection: &mut EmvConnection,
    purchase_amount: u64,
    stop_after_read: bool,
) -> Result<Option<bool>, EmvError> {
    let application = connection.select_payment_application()?;

    connection.process_settings()?;
    connection.add_tag(
        "9F02",
        bcdutil::ascii_to_bcd_n(format!("{}", purchase_amount).as_bytes(), 6)
            .map_err(|_| EmvError::Callback("Amount does not fit in 12 digits".to_string()))?,
    );

    connection.handle_get_processing_options()?;

    if stop_after_read {
        return Ok(None);
    }

    connection.handle_public_keys(&application)?;

    connection.handle_card_verification_methods()?;

    connection.handle_terminal_risk_management()?;

    connection.handle_terminal_action_analysis()?;

    let purchase_successful = match connection.handle_1st_generate_ac()? {
        CryptogramType::AuthorisationRequestCryptogram => {
            connection.handle_2nd_generate_ac()? == CryptogramType::TransactionCertificate
        }
        CryptogramType::TransactionCertificate => true,
        CryptogramType::ApplicationAuthenticationCryptogram => false,
    };

    Ok(Some(purchase_successful))
}

fn main() {
    std::process::exit(match run() {
        Ok(None) => 0,
        Ok(msg) => {
            warn!("{:?}", msg);
            0
        }
        Err(err) => {
            error!("{:?}", err);
            1
        }
    });
}
