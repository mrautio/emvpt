use log::{error, warn, debug};
use log4rs;
use clap::{App, Arg};
use std::io::{self};
use std::{thread, time};
use std::str;

use emvpt::*;

fn run() -> Result<Option<String>, String> {
    log4rs::init_file("../config/log4rs.yaml", Default::default()).unwrap();

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
        .get_matches();

    let interactive = matches.is_present("interactive");
    let print_tags = matches.is_present("print-tags");

    let mut connection = EmvConnection::new().unwrap();

    let mut purchase_amount : Option<String> = None;

    if interactive {
        println!("Enter amount:");
        print!("> ");
        let mut stdin_buffer = String::new();
        io::stdin().read_line(&mut stdin_buffer).unwrap();

        purchase_amount = Some(format!("{:.0}", stdin_buffer.trim().parse::<f64>().unwrap() * 100.0));
    }

    //return Ok(None);

    if let Err(err) = connection.connect_to_card() {
        match err {
            ReaderError::CardNotFound => {
                if interactive {
                    println!("Please insert card");

                    loop {
                        match connection.connect_to_card() {
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

    let applications = connection.handle_select_payment_system_environment().unwrap();

    let mut application_number : usize = 0;

    if interactive && applications.len() > 1 {
        println!("Select payment application:");
        for i in 0..applications.len() {
            println!("{:02}. {}", i+1, str::from_utf8(&applications[i].label).unwrap());
        }

        print!("> ");

        let mut stdin_buffer = String::new();
        io::stdin().read_line(&mut stdin_buffer).unwrap();

        application_number = stdin_buffer.trim().parse::<usize>().unwrap() - 1;
    }

    if print_tags {
        connection.print_tags();
    }

    let application = &applications[application_number];
    connection.handle_select_payment_application(application).unwrap();

    connection.process_settings().unwrap();
    if purchase_amount.is_some() {
        connection.add_tag("9F02", ascii_to_bcd_n(purchase_amount.unwrap().as_bytes(), 6).unwrap());
    }

    let data_authentication = connection.handle_get_processing_options().unwrap();

    let (issuer_pk_modulus, issuer_pk_exponent) = connection.get_issuer_public_key(application).unwrap();

    let tag_9f46_icc_pk_certificate = connection.get_tag_value("9F46").unwrap();
    let tag_9f47_icc_pk_exponent = connection.get_tag_value("9F47").unwrap();
    let tag_9f48_icc_pk_remainder = connection.get_tag_value("9F48");
    let (icc_pk_modulus, icc_pk_exponent) = connection.get_icc_public_key(
        tag_9f46_icc_pk_certificate, tag_9f47_icc_pk_exponent, tag_9f48_icc_pk_remainder,
        &issuer_pk_modulus[..], &issuer_pk_exponent[..],
        &data_authentication[..]).unwrap();

    if connection.settings.terminal.capabilities.dda && connection.icc.capabilities.dda {
        if let Err(_) = connection.handle_dynamic_data_authentication(&icc_pk_modulus[..], &icc_pk_exponent[..]) {
            connection.settings.terminal.tvr.dda_failed = true;
        }
    }

    let purchase_amount = str::from_utf8(&bcd_to_ascii(&connection.get_tag_value("9F02").unwrap()[..]).unwrap()[..]).unwrap().parse::<u32>().unwrap();

    let cvm_rules = connection.icc.cvm_rules.clone();
    for rule in cvm_rules {
        let mut skip_if_not_supported = false;
        let mut success = false;

        match rule.condition {
            CvmConditionCode::UnattendedCash | CvmConditionCode::ManualCash | CvmConditionCode::PurchaseWithCashback => {
                // TODO: conditions currently never supported, maybe should implement it more flexible
                continue;
            },
            CvmConditionCode::CvmSupported => {
                skip_if_not_supported = true;
            }
            // TODO: verify that ICC and terminal currencies are the same or provide conversion
            CvmConditionCode::IccCurrencyUnderX => {
                if purchase_amount >= rule.amount_x {
                    continue;
                }
            },
            CvmConditionCode::IccCurrencyOverX => {
                if purchase_amount <= rule.amount_x {
                    continue;
                }
            }
            CvmConditionCode::IccCurrencyUnderY => {
                if purchase_amount >= rule.amount_y {
                    continue;
                }
            },
            CvmConditionCode::IccCurrencyOverY => {
                if purchase_amount <= rule.amount_y {
                    continue;
                }
            },
            _ => ()
        }

        match rule.code {
            CvmCode::FailCvmProcessing => success = false,
            CvmCode::EncipheredPinOnline => {
                debug!("Enciphered PIN online is not supported");

                if skip_if_not_supported {
                    continue;
                }

                success = false;
            },
            CvmCode::PlaintextPin | CvmCode::PlaintextPinAndSignature | CvmCode::EncipheredPinOffline | CvmCode::EncipheredPinOfflineAndSignature => {
                let enciphered_pin = match rule.code {
                    CvmCode::EncipheredPinOffline | CvmCode::EncipheredPinOfflineAndSignature => true,
                    _ => false
                };

                let mut ascii_pin : Option<&str> = None;

                if matches.is_present("pin") {
                    ascii_pin = matches.value_of("pin");
                }

                let mut stdin_buffer = String::new();
                if interactive {
                    println!("Enter PIN:");
                    print!("> ");

                    io::stdin().read_line(&mut stdin_buffer).unwrap();

                    ascii_pin = Some(&stdin_buffer.trim());
                }

                if ascii_pin.is_some() {
                    if enciphered_pin && connection.settings.terminal.capabilities.enciphered_pin {
                        let mut icc_pin_pk_modulus = icc_pk_modulus.clone();
                        let mut icc_pin_pk_exponent = icc_pk_exponent.clone();

                        let tag_9f2d_icc_pin_pk_certificate = connection.get_tag_value("9F2D");
                        let tag_9f2e_icc_pin_pk_exponent = connection.get_tag_value("9F2E");
                        if tag_9f2d_icc_pin_pk_certificate.is_some() && tag_9f2e_icc_pin_pk_exponent.is_some() {
                            let tag_9f2f_icc_pin_pk_remainder = connection.get_tag_value("9F2F");

                            // ICC has a separate ICC PIN Encipherement public key
                            match connection.get_icc_public_key(
                                tag_9f2d_icc_pin_pk_certificate.unwrap(), tag_9f2e_icc_pin_pk_exponent.unwrap(), tag_9f2f_icc_pin_pk_remainder,
                                &issuer_pk_modulus[..], &issuer_pk_exponent[..],
                                &data_authentication[..]) {
                                Ok((modulus, exponent)) => {
                                    icc_pin_pk_modulus = modulus;
                                    icc_pin_pk_exponent = exponent;

                                    success = match connection.handle_verify_enciphered_pin(ascii_pin.unwrap().as_bytes(), &icc_pin_pk_modulus[..], &icc_pin_pk_exponent[..]) {
                                        Ok(_) => true,
                                        Err(_) => false
                                    };
                                },
                                Err(_) => {
                                    success = false;
                                }
                            };

                        } else {
                            success = match connection.handle_verify_enciphered_pin(ascii_pin.unwrap().as_bytes(), &icc_pin_pk_modulus[..], &icc_pin_pk_exponent[..]) {
                                Ok(_) => true,
                                Err(_) => false
                            };
                        }

                    } else if connection.settings.terminal.capabilities.plaintext_pin {
                        success = match connection.handle_verify_plaintext_pin(ascii_pin.unwrap().as_bytes()) {
                            Ok(_) => true,
                            Err(_) => false
                        };
                    } else if skip_if_not_supported {
                        continue;
                    }
                }
            },
            CvmCode::Signature | CvmCode::NoCvm => {
                success = true;
            }
        }

        if success {
            connection.settings.terminal.tvr.cardholder_verification_was_not_successful = false;
            connection.add_tag("9F34", CvmRule::into_9f34_value(Ok(rule)));
            break;
        } else {
            connection.settings.terminal.tvr.cardholder_verification_was_not_successful = true;
            connection.add_tag("9F34", CvmRule::into_9f34_value(Err(rule)));

            if ! skip_if_not_supported {
                break;
            }
        }
    }

    if ! connection.get_tag_value("9F34").is_some() {
        connection.settings.terminal.tvr.cardholder_verification_was_not_successful = true;

        // "no CVM performed"
        connection.add_tag("9F34", b"\x3F\x00\x01".to_vec());
    }

    connection.handle_generate_ac().unwrap();

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
