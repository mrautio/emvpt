use pcsc::{Context, Card, Scope, ShareMode, Protocols, Error, MAX_BUFFER_SIZE, MAX_ATR_SIZE};
use hexplay::HexViewBuilder;
use iso7816_tlv::ber::{Tlv, Tag, Value};
use std::collections::HashMap;
use std::str;
use std::convert::TryFrom;
use std::io::{self};
use std::{thread, time};
use serde::{Deserialize, Serialize};
use log::LevelFilter;
use log::{error, info, warn, debug, trace};
use log4rs::append::console::ConsoleAppender;
use log4rs::config::{Appender, Config, Root};
use clap::{App, Arg};
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand::{Rng};
use openssl::rsa::{Rsa, Padding};
use openssl::bn::BigNum;
use openssl::sha;
use hex;
use chrono::{NaiveDate, Datelike, Utc};

macro_rules! get_bit {
    ($byte:expr, $bit:expr) => (if $byte & (1 << $bit) != 0 { true } else { false });
}

struct EmvConnection {
    tags : HashMap<String, Vec<u8>>,
    ctx : Option<Context>,
    card : Option<Card>
}

enum ReaderError {
    ReaderConnectionFailed(String),
    ReaderNotFound,
    CardConnectionFailed(String),
    CardNotFound
}

impl EmvConnection {
    fn new() -> Result<EmvConnection, String> {
        Ok ( EmvConnection { tags : HashMap::new(), ctx : None, card : None } )
    }

    fn connect_to_card(&mut self) -> Result<(), ReaderError> {
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
                return Err(ReaderError::ReaderConnectionFailed(format!("Failed to list readers: {}", err)));
            }
        };

        let mut readers_buf = vec![0; readers_size];
        let mut readers = match ctx.list_readers(&mut readers_buf) {
            Ok(readers) => readers,
            Err(err) => {
                return Err(ReaderError::ReaderConnectionFailed(format!("Failed to list readers: {}", err)));
            }
        };

        let reader = match readers.next() {
            Some(reader) => reader,
            None => {
                return Err(ReaderError::ReaderNotFound);
            }
        };

        // Connect to the card.
        self.card = match ctx.connect(reader, ShareMode::Shared, Protocols::ANY) {
            Ok(card) => Some(card),
            Err(Error::NoSmartcard) => {
                return Err(ReaderError::CardNotFound);
            },
            Err(err) => {
                return Err(ReaderError::CardConnectionFailed(format!("Could not connect to the card: {}", err)));
            }
        };

        const MAX_NAME_SIZE : usize = 2048;
        let mut names_buffer = [0; MAX_NAME_SIZE];
        let mut atr_buffer = [0; MAX_ATR_SIZE];
        let card_status = self.card.as_ref().unwrap().status2(&mut names_buffer, &mut atr_buffer).unwrap();

        // https://www.eftlab.com/knowledge-base/171-atr-list-full/
        debug!("Card reader: {:?}", reader);
        debug!("Card ATR:\n{}", HexViewBuilder::new(card_status.atr()).finish());
        debug!("Card protocol: {:?}", card_status.protocol2().unwrap());

        Ok(())
    }

    fn get_tag_value(&self, tag_name : &str) -> Option<&Vec<u8>> {
        self.tags.get(tag_name)
    }

    fn add_tag(&mut self, tag_name : &str, value : Vec<u8>) {
        if tag_name == "80" {
            return;
        }

        let old_tag = self.tags.get(tag_name);
        if old_tag.is_some() {
            warn!("Overriding tag {:?} from {:02X?} to {:02X?}", tag_name, old_tag.unwrap(), value);
        }

        self.tags.insert(tag_name.to_string(), value);
    }

    fn send_apdu_select(&mut self, aid : &[u8]) -> (Vec<u8>, Vec<u8>) {
        self.tags.clear();

        let apdu_command_select   = b"\x00\xA4\x04\x00";

        let mut select_command = apdu_command_select.to_vec();
        select_command.push(aid.len() as u8);
        select_command.extend_from_slice(aid);

        self.send_apdu(&select_command)
    }

    fn send_apdu<'apdu>(&mut self, apdu : &'apdu [u8]) -> (Vec<u8>, Vec<u8>) {
        let mut apdu_response_buffer = [0; MAX_BUFFER_SIZE];

        let mut response_data : Vec<u8> = Vec::new();
        let mut response_trailer : Vec<u8>;

        let mut new_apdu_command;
        let mut apdu_command = apdu;
        loop {
            // Send an APDU command.
            debug!("Sending APDU:\n{}", HexViewBuilder::new(&apdu_command).finish());
            let apdu_response = self.card.as_ref().unwrap().transmit(apdu_command, &mut apdu_response_buffer).unwrap();

            response_data.extend_from_slice(&apdu_response[0..apdu_response.len()-2]);

            // response codes: https://www.eftlab.com/knowledge-base/complete-list-of-apdu-responses/
            response_trailer = vec![apdu_response[apdu_response.len()-2], apdu_response[apdu_response.len()-1]];
            debug!("APDU response status: {:02X?}", response_trailer);

            // Automatically query more data, if available from the ICC
            const SW1_BYTES_AVAILABLE : u8 = 0x61;
            const SW1_WRONG_LENGTH : u8    = 0x6C;

            if response_trailer[0] == SW1_BYTES_AVAILABLE {
                trace!("APDU response({} bytes):\n{}", response_data.len(), HexViewBuilder::new(&response_data).finish());

                let mut available_data_length = response_trailer[1];

                // NOTE: EMV doesn't have a use case where ICC would pass bigger records than what is passable with a single ADPU response
                if available_data_length == 0x00 {
                    // there are more than 255 bytes available, query the maximum
                    available_data_length = 0xFF;
                }

                let apdu_command_get_response = b"\x00\xC0\x00\x00";
                new_apdu_command = apdu_command_get_response.to_vec();
                new_apdu_command.push(available_data_length);

                apdu_command = &new_apdu_command[..];
            } else if response_trailer[0] == SW1_WRONG_LENGTH {
                trace!("APDU response({} bytes):\n{}", response_data.len(), HexViewBuilder::new(&response_data).finish());

                let available_data_length = response_trailer[1];
                assert!(available_data_length > 0x00);

                new_apdu_command = apdu.to_vec();
                let new_apdu_command_length = new_apdu_command.len();
                new_apdu_command[new_apdu_command_length - 1] = available_data_length;

                apdu_command = &new_apdu_command[..];
            } else {
                break;
            }
        }

        debug!("APDU response({} bytes):\n{}", response_data.len(), HexViewBuilder::new(&response_data).finish());

        if !response_data.is_empty() {
            debug!("APDU TLV parse:");

            self.process_tlv(&response_data[..], 0);
        }

        (response_trailer, response_data)
    }

    fn print_tag(emv_tag : &EmvTag, level: u8) {
        let mut padding = String::with_capacity(level as usize);
        for _ in 0..level {
            padding.push(' ');
        }
        debug!("{}-{}: {}", padding, emv_tag.tag, emv_tag.name);
    }
    fn print_tag_value(v : &Vec<u8>, level: u8) {
        let mut padding = String::with_capacity(level as usize);
        for _ in 0..level {
            padding.push(' ');
        }
        debug!("{}-data: {:02X?} = {}", padding, v, String::from_utf8_lossy(&v).replace(|c: char| !(c.is_ascii_alphanumeric() || c.is_ascii_punctuation()), "."));

    }

    fn process_tlv(&mut self, buf: &[u8], level: u8) {
        let emv_definition_data = r#"
            {
                "6F":   { "tag":"6F", "name":"File Control Information (FCI) Template" },
                "84":   { "tag":"84", "name":"Dedicated File (DF) Name" },
                "A5":   { "tag":"A5", "name":"File Control Information (FCI) Proprietary Template" },
                "88":   { "tag":"88", "name":"Short File Identifier (SFI)" },
                "5F2D": { "tag":"5F2D", "name":"Language Preference" },
                "BF0C": { "tag":"BF0C", "name":"File Control Information (FCI) Issuer Discretionary Data" },
                "70":   { "tag":"70", "name":"EMV Proprietary Template" },
                "61":   { "tag":"61", "name":"Application Template" },
                "4F":   { "tag":"4F", "name":"Application Identifier (AID)" },
                "50":   { "tag":"50", "name":"Application Label" },
                "87":   { "tag":"87", "name":"Application Priority Indicator" },
                "80":   { "tag":"80", "name":"Response Message Template Format 1" },
                "57":   { "tag":"57", "name":"Track 2 Equivalent Data" },
                "5F20": { "tag":"5F20", "name":"Cardholder Name" },
                "9F1F": { "tag":"9F1F", "name":"Track 1 Discretionary Data" },
                "90":   { "tag":"90", "name":"Issuer Public Key Certificate" },
                "8F":   { "tag":"8F", "name":"Certification Authority Public Key Index" },
                "9F32": { "tag":"9F32", "name":"Issuer Public Key Exponent" },
                "92":   { "tag":"92", "name":"Issuer Public Key Remainder" },
                "9F47": { "tag":"9F47", "name":"Integrated Circuit Card (ICC) Public Key Exponent" },
                "9F46": { "tag":"9F46", "name":"Integrated Circuit Card (ICC) Public Key Certificate" },
                "5F25": { "tag":"5F25", "name":"Application Effective Date" },
                "5F24": { "tag":"5F24", "name":"Application Expiration Date" },
                "5A":   { "tag":"5A", "name":"Application Primary Account Number (PAN)" },
                "5F34": { "tag":"5F34", "name":"Application Primary Account Number (PAN) Sequence Number" },
                "9F07": { "tag":"9F07", "name":"Application Usage Control" },
                "8E":   { "tag":"8E", "name":"Cardholder Verification Method (CVM) List" },
                "9F0D": { "tag":"9F0D", "name":"Issuer Action Code – Default" },
                "9F0E": { "tag":"9F0E", "name":"Issuer Action Code – Denial" },
                "9F0F": { "tag":"9F0F", "name":"Issuer Action Code – Online" },
                "9F4A": { "tag":"9F4A", "name":"Static Data Authentication Tag List" },
                "8C":   { "tag":"8C", "name":"Card Risk Management Data Object List 1 (CDOL1)" },
                "8D":   { "tag":"8D", "name":"Card Risk Management Data Object List 2 (CDOL2)" },
                "5F28": { "tag":"5F28", "name":"Issuer Country Code" },
                "9F42": { "tag":"9F42", "name":"Application Currency Code" },
                "9F44": { "tag":"9F44", "name":"Application Currency Exponent" },
                "9F49": { "tag":"9F49", "name":"Dynamic Data Authentication Data Object List (DDOL)" },
                "9F08": { "tag":"9F08", "name":"Application Version Number" },
                "9F02": { "tag":"9F02", "name":"Amount, Authorised (Numeric)" },
                "9F03": { "tag":"9F03", "name":"Amount, Other (Numeric)" },
                "9F1A": { "tag":"9F1A", "name":"Terminal Country Code" },
                "95":   { "tag":"95", "name":"Terminal Verification Results" },
                "5F2A": { "tag":"5F2A", "name":"Transaction Currency Code" },
                "9A":   { "tag":"9A", "name":"Transaction Date" },
                "9C":   { "tag":"9C", "name":"Transaction Type" },
                "9F37": { "tag":"9F37", "name":"Unpredictable Number" },
                "8A":   { "tag":"8A", "name":"Authorisation Response Code" },
                "9F4B": { "tag":"9F4B", "name":"Signed Dynamic Application Data" },
                "9F48": { "tag":"9F48", "name":"Integrated Circuit Card (ICC) Public Key Remainder" },
                "9F27": { "tag":"9F27", "name":"Cryptogram Information Data (CID)" },
                "9F36": { "tag":"9F36", "name":"Application Transaction Counter (ATC)" },
                "9F26": { "tag":"9F26", "name":"Application Cryptogram (AC)" },
                "9F10": { "tag":"9F10", "name":"Issuer Application Data (IAD)" },
                "82":   { "tag":"82", "name":"Application Interchange Profile (AIP)" },
                "94":   { "tag":"94", "name":"Application File Locator (AFL)" },
                "9F35": { "tag":"9F35", "name":"Terminal Type" },
                "9F45": { "tag":"9F45", "name":"Data Authentication Code" },
                "9F4C": { "tag":"9F4C", "name":"ICC Dynamic Number" },
                "9F34": { "tag":"9F34", "name":"Cardholder Verification Method (CVM) Results" },
                "9F11": { "tag":"9F11", "name":"Issuer Code Table Index" },
                "9F12": { "tag":"9F12", "name":"Application Preferred Name" },
                "77":   { "tag":"77", "name":"Response Message Template Format 2" },
                "73":   { "tag":"73", "name":"Directory Discretionary Template" },
                "9F2E": { "tag":"9F2E", "name":"Integrated Circuit Card (ICC) PIN Encipherment Public Key Exponent" },
                "9F2F": { "tag":"9F2F", "name":"Integrated Circuit Card (ICC) PIN Encipherment Public Key Remainder" },
                "9F2D": { "tag":"9F2D", "name":"Integrated Circuit Card (ICC) PIN Encipherment Public Key Certificate" }
            }"#;

        let emv_tags : HashMap<String, EmvTag> = serde_json::from_str(emv_definition_data).unwrap();

        let tlv_data = parse_tlv(&buf);
        if !tlv_data.is_some() {
            return;
        }
        let tlv_data = tlv_data.unwrap();

        let tag_name = hex::encode(tlv_data.tag().to_bytes()).to_uppercase();

        match emv_tags.get(tag_name.as_str()) {
            Some(emv_tag) => {
                EmvConnection::print_tag(&emv_tag, level);
            },
            _ => {
                let unknown_tag = EmvTag { tag: tag_name.clone(), name: "Unknown tag".to_string() };
                EmvConnection::print_tag(&unknown_tag, level);
            }
        }

        match tlv_data.value() {
            Value::Constructed(v) => {
                for tlv_tag in v {
                    self.process_tlv(&tlv_tag.to_vec(), level + 1);
                }
            },
            Value::Primitive(v) => {
                self.add_tag(&tag_name, v.to_vec());

                EmvConnection::print_tag_value(v, level);
            }
        };
    }

    fn handle_get_processing_options(&mut self) -> Result<Vec<u8>, ()> {
        debug!("GET PROCESSING OPTIONS:");
        let get_processing_options_command = b"\x80\xA8\x00\x00\x02\x83\x00".to_vec();
        let (response_trailer, response_data) = self.send_apdu(&get_processing_options_command);
        if !is_success_response(&response_trailer) {
            warn!("Could not get processing options");
            return Err(());
        }

        if response_data[0] == 0x80 {
            self.add_tag("82", response_data[2..4].to_vec());
            self.add_tag("94", response_data[4..].to_vec());
        } else if response_data[0] != 0x77 {
            warn!("Unrecognized response");
            return Err(());
        }

        let tag_94_afl = self.get_tag_value("94").unwrap().clone();

        info!("Read card AFL information:");

        let mut data_authentication : Vec<u8> = Vec::new();
        assert_eq!(tag_94_afl.len() % 4, 0);
        let mut records : Vec<u8> = Vec::new();
        for i in (0..tag_94_afl.len()).step_by(4) {
            let short_file_identifier : u8 = tag_94_afl[i] >> 3;
            let record_index_start : u8 = tag_94_afl[i+1];
            let record_index_end : u8 = tag_94_afl[i+2];
            let mut data_authentication_records : u8 = tag_94_afl[i+3];

            for record_index in record_index_start..record_index_end+1 {
                if let Some(data) = self.read_record(short_file_identifier, record_index) {
                    assert_eq!(data[0], 0x70);
                    records.extend(&data);

                    // Add data authentication input            
                    // ref EMV Book 3, 10.3 Offline Data Authentication
                    if data_authentication_records > 0 {
                        data_authentication_records -= 1;

                        if short_file_identifier <= 10 {
                            if let Value::Constructed(tag_70_tags) = parse_tlv(&data[..]).unwrap().value() {
                                for tag in tag_70_tags {
                                    data_authentication.extend(tag.to_vec());
                                }
                            }
                        } else {
                            data_authentication.extend_from_slice(&data[..]);
                        }
                        
                        trace!("Data authentication building: short_file_identifier:{}, data_authentication_records:{}, record_index:{}/{}, data:{:02X?}", short_file_identifier, data_authentication_records, record_index, record_index_end, data_authentication);
                    }
                }
            }
        }

        debug!("AFL data authentication:\n{}", HexViewBuilder::new(&data_authentication).finish());

        let tag_82_aip = self.get_tag_value("82").unwrap();

        let auc_b1 : u8 = tag_82_aip[0];
        // bit 7 = RFU
        if get_bit!(auc_b1, 6) {
            info!("SDA supported");
        }
        if get_bit!(auc_b1, 5) {
            info!("DDA supported");
        }
        if get_bit!(auc_b1, 4) {
            info!("Cardholder verification is supported");

// 2020-07-18T22:09:33.408059800+03:00 DEBUG emvpt -  -8E: Cardholder Verification Method (CVM) List
// 2020-07-18T22:09:33.409053800+03:00 DEBUG emvpt -  -data: [00, 00, 00, 00, 00, 00, 00, 00, 42, 01, 44, 03, 41, 03, 5E, 03, 42, 03, 1F, 03] = ........B.D.A.^.B...

            let tag_8e_cvm_list = self.get_tag_value("8E").unwrap();
            let amount1 = &tag_8e_cvm_list[0..4];
            let amount2 = &tag_8e_cvm_list[4..8];

            let tag_84_cvm_rules = &tag_8e_cvm_list[8..];
            assert_eq!(tag_84_cvm_rules.len() % 2, 0);
            for i in (0..tag_84_cvm_rules.len()).step_by(2) {
                let cvm_rule = &tag_84_cvm_rules[i..i+2];
                let cvm_code = cvm_rule[0];
                let cvm_condition_code = cvm_rule[1];

                info!("CVM rule: {}", i / 2);
                // bit 7 = RFU
                if get_bit!(cvm_code, 6) {
                    info!("Apply succeeding CV Rule if this CVM is unsuccessful");
                } else {
                    info!("Fail cardholder verification if this CVM is unsuccessful");
                }

                let cvm_code = (cvm_code << 2) >> 2;
                if cvm_code == 0b0000_0000 {
                    info!("Fail CVM processing");
                } else if cvm_code == 0b0000_0001 {
                    info!("Plaintext PIN verification performed by ICC");
                } else if cvm_code == 0b0000_0010 {
                    info!("Enciphered PIN verified online");
                } else if cvm_code == 0b0000_0011 {
                    info!("Plaintext PIN verification performed by ICC and signature (paper)");
                } else if cvm_code == 0b0000_0100 {
                    info!("Enciphered PIN verification performed by ICC");
                } else if cvm_code == 0b0000_0101 {
                    info!("Enciphered PIN verification performed by ICC and signature (paper)");
                } else if cvm_code == 0b0001_1110 {
                    info!("Signature (paper)");
                } else if cvm_code == 0b0001_1111 {
                    info!("No CVM required");
                } else {
                    warn!("Unknown CVM code! {:b}", cvm_code);
                }

                if cvm_condition_code == 0x00 {
                    info!("Always");
                } else if cvm_condition_code == 0x01 {
                    info!("If unattended cash");
                } else if cvm_condition_code == 0x02 {
                    info!("If not unattended cash and not manual cash and not purchase with cashback");
                } else if cvm_condition_code == 0x03 {
                    info!("If terminal supports the CVM");
                } else if cvm_condition_code == 0x04 {
                    info!("If manual cash");
                } else if cvm_condition_code == 0x05 {
                    info!("If purchase with cashback");
                } else if cvm_condition_code == 0x06 {
                    info!("If transaction is in the application currency and is under {:02X?} value", amount1);
                } else if cvm_condition_code == 0x07 {
                    info!("If transaction is in the application currency and is over {:02X?} value", amount1);
                } else if cvm_condition_code == 0x08 {
                    info!("If transaction is in the application currency and is under {:02X?} value", amount2);
                } else if cvm_condition_code == 0x09 {
                    info!("If transaction is in the application currency and is over {:02X?} value", amount2);
                } else {
                    warn!("Unknown CVM condition code! {:02X?}", cvm_condition_code);
                }

            }
        }
        if get_bit!(auc_b1, 3) {
            info!("Terminal risk management is to be performed");
        }
        if get_bit!(auc_b1, 2) {
            // Issuer Authentication using the EXTERNAL AUTHENTICATE command is supported
            info!("Issuer authentication is supported");
        }
        // bit 1 = RFU
        if get_bit!(auc_b1, 0) {
            info!("CDA supported");
        }

        let tag_9f07_application_usage_control = self.get_tag_value("9F07").unwrap();
        let auc_b1 : u8 = tag_9f07_application_usage_control[0];
        let auc_b2 : u8 = tag_9f07_application_usage_control[1];
        if get_bit!(auc_b1, 7) {
            info!("Valid for domestic cash transactions");
        }
        if get_bit!(auc_b1, 6) {
            info!("Valid for international cash transactions");
        }
        if get_bit!(auc_b1, 5) {
            info!("Valid for domestic goods");
        }
        if get_bit!(auc_b1, 4) {
            info!("Valid for international goods");
        }
        if get_bit!(auc_b1, 3) {
            info!("Valid for domestic services");
        }
        if get_bit!(auc_b1, 2) {
            info!("Valid for international services");
        }
        if get_bit!(auc_b1, 1) {
            info!("Valid at ATMs");
        }
        if get_bit!(auc_b1, 0) {
            info!("Valid at terminals other than ATMs");
        }
        if get_bit!(auc_b2, 7) {
            info!("Domestic cashback allowed");
        }
        if get_bit!(auc_b2, 6) {
            info!("International cashback allowed");
        }
        // 5 - 0 bits are RFU

        Ok(data_authentication)
    }

    fn handle_verify_plaintext_pin(&mut self, ascii_pin : &[u8]) -> Result<(), ()> {
        debug!("Verify plaintext PIN:");

        let pin_bcd_cn = ascii_to_bcd_cn(ascii_pin, 6).unwrap();

        let apdu_command_verify = b"\x00\x20\x00";
        let mut verify_command = apdu_command_verify.to_vec();
        let p2_pin_type_qualifier = 0b1000_0000;
        verify_command.push(p2_pin_type_qualifier);
        verify_command.push(0x08); // data length
        verify_command.push(0b0010_0000 + ascii_pin.len() as u8); // control + PIN length
        verify_command.extend_from_slice(&pin_bcd_cn[..]);
        verify_command.push(0xFF); // filler

        let (response_trailer, _) = self.send_apdu(&verify_command);
        if !is_success_response(&response_trailer) {
            warn!("Could not verify PIN");
            //Incorrect PIN = 63, C4
            return Err(());
        }

        info!("Pin OK");
        Ok(())
    }

    fn handle_verify_enciphered_pin(&mut self, ascii_pin : &[u8], icc_pin_pk_modulus : &[u8], icc_pin_pk_exponent : &[u8]) -> Result<(), ()> {
        debug!("Verify enciphered PIN:");

        let pin_bcd_cn = ascii_to_bcd_cn(ascii_pin, 6).unwrap();

        let mut rng = ChaCha20Rng::from_entropy();
        const PK_MAX_SIZE : usize = 248; // ref. EMV Book 2, B2.1 RSA Algorithm
        let mut random_padding = [0u8; PK_MAX_SIZE];
        rng.try_fill(&mut random_padding[..]).unwrap();

        let icc_unpredictable_number = self.handle_get_challenge().unwrap();

        // EMV Book 2, 7.1 Keys and Certificates, 7.2 PIN Encipherment and Verification

        let mut plaintext_data = Vec::new();
        plaintext_data.push(0x7F);
        // PIN block
        plaintext_data.push(0b0010_0000 + ascii_pin.len() as u8); // control + PIN length
        plaintext_data.extend_from_slice(&pin_bcd_cn[..]);
        plaintext_data.push(0xFF);
        // ICC Unpredictable Number
        plaintext_data.extend_from_slice(&icc_unpredictable_number[..]);
        // Random pagging Nic - 17 (FIXME)
        plaintext_data.extend_from_slice(&random_padding[0..icc_pin_pk_modulus.len()-17]);

        let icc_pin_pk = RsaPublicKey::new(icc_pin_pk_modulus, icc_pin_pk_exponent);
        let ciphered_pin_data = icc_pin_pk.public_encrypt(&plaintext_data[..]).unwrap();

        let apdu_command_verify = b"\x00\x20\x00";
        let mut verify_command = apdu_command_verify.to_vec();
        let p2_pin_type_qualifier = 0b1000_1000;
        verify_command.push(p2_pin_type_qualifier);
        verify_command.push(ciphered_pin_data.len() as u8);
        verify_command.extend_from_slice(&ciphered_pin_data[..]);

        let (response_trailer, _) = self.send_apdu(&verify_command);
        if !is_success_response(&response_trailer) {
            warn!("Could not verify PIN");
            //Incorrect PIN = 63, C4
            return Err(());
        }

        info!("Pin OK");
        Ok(())
    }

    fn handle_generate_ac(&mut self) -> Result<(), ()> {
        debug!("Generate Application Cryptogram (GENERATE AC):");

        self.add_tag("95", b"\x00\x00\x00\x00\x00".to_vec());
        let amount2 = 0;
        self.add_tag("9F03", ascii_to_bcd_n(amount2.to_string().as_bytes(), 6).unwrap());
        // https://www.iso.org/obp/ui/#iso:code:3166:FI
        let terminal_country = 246;
        self.add_tag("9F1A", ascii_to_bcd_n(terminal_country.to_string().as_bytes(), 2).unwrap()); // FI
        // https://www.currency-iso.org/dam/downloads/lists/list_one.xml
        let currency = 978;
        self.add_tag("5F2A", ascii_to_bcd_n(currency.to_string().as_bytes(), 2).unwrap()); // EUR

        let today = Utc::today().naive_utc();
        let transaction_date_ascii_yymmdd = format!("{:02}{:02}{:02}",today.year()-2000, today.month(), today.day());
        self.add_tag("9A", ascii_to_bcd_cn(transaction_date_ascii_yymmdd.as_bytes(), 3).unwrap());

        // http://www.fintrnmsgtool.com/iso-processing-code.html
        self.add_tag("9C", b"\x21".to_vec()); // Deposit (Credit)
        let terminal_type = 23;
        self.add_tag("9F35", ascii_to_bcd_n(terminal_type.to_string().as_bytes(), 1).unwrap()); // "Offline only", ref. EMV Book 4, A1 Terminal Type
        // "An issuer assigned value that is retained by the terminal during the verification process of the Signed Static Application Data"
        // found on one card that does not support SDA... i.e. card requires value but does not provide it
        self.add_tag("9F45", b"\x00\x00".to_vec());
        // EMV Book 4, A4 CVM Results
        //b1: CVM code
        //b2: CVM condition code
        //b3: unknown/failed/success
        self.add_tag("9F34", b"\x41\x03\x02".to_vec()); // "unencrypted PIN successful"


        let cdol_data = self.get_tag_list_tag_values(&self.get_tag_value("8C").unwrap()[..]).unwrap();
        assert!(cdol_data.len() <= 0xFF);

        let p1_tc_proceed_offline = 0b0100_0000;

        let apdu_command_generate_ac = b"\x80\xAE";
        let mut generate_ac_command = apdu_command_generate_ac.to_vec();
        generate_ac_command.push(p1_tc_proceed_offline);
        generate_ac_command.push(0x00);
        generate_ac_command.push(cdol_data.len() as u8);
        generate_ac_command.extend_from_slice(&cdol_data);
        generate_ac_command.push(0x00);

        let (response_trailer, response_data) = self.send_apdu(&generate_ac_command);
        if !is_success_response(&response_trailer) {
            // 67 00 = wrong length (i.e. CDOL data incorrect)
            warn!("Could not process generate ac");
            return Err(());
        }

        if response_data[0] == 0x80 {
            self.add_tag("9F27", response_data[2..3].to_vec());
            self.add_tag("9F36", response_data[3..5].to_vec());
            self.add_tag("9F26", response_data[5..13].to_vec());
            if response_data.len() > 13 {
                self.add_tag("9F10", response_data[13..].to_vec());
            } 
        } else if response_data[0] != 0x77 {
            warn!("Unrecognized response");
            return Err(());
        }

        //let tag_9f27_cryptogram_information_data = connection.get_tag_value("9F27").unwrap();
        //let tag_9f36_application_transaction_counter = connection.get_tag_value("9F36").unwrap();
        //let tag_9f26_application_cryptogram = connection.get_tag_value("9F26").unwrap();
        //let tag_9f10_issuer_application_data = connection.get_tag_value("9F10");

        Ok(())
    }

    fn read_record(&mut self, short_file_identifier : u8, record_index : u8) -> Option<Vec<u8>> {
        let mut records : Vec<u8> = Vec::new();

        let apdu_command_read = b"\x00\xB2";

        let mut read_record = apdu_command_read.to_vec();
        read_record.push(record_index);
        read_record.push((short_file_identifier << 3) | 0x04);

        const RECORD_LENGTH_DEFAULT : u8 = 0x00;
        read_record.push(RECORD_LENGTH_DEFAULT);

        let (response_trailer, response_data) = self.send_apdu(&read_record);

        if is_success_response(&response_trailer) {
            records.extend_from_slice(&response_data);
        }

        if !records.is_empty() {
            return Some(records);
        }

        None
    }

    fn handle_select_payment_system_environment(&mut self) -> Result<Vec<EmvApplication>, ()> {
        debug!("Selecting Payment System Environment (PSE):");
        let contact_pse_name = "1PAY.SYS.DDF01";

        let pse_name = contact_pse_name;

        let (response_trailer, _) = self.send_apdu_select(&pse_name.as_bytes());
        if !is_success_response(&response_trailer) {
            warn!("Could not select {:?}", pse_name);
            return Err(());
        }

        let sfi_data = self.get_tag_value("88").unwrap().clone();
        assert_eq!(sfi_data.len(), 1);
        let short_file_identifier = sfi_data[0];

        debug!("Read available AIDs:");

        let mut all_applications : Vec<EmvApplication> = Vec::new();

        for record_index in 0x01..0xFF {
            match self.read_record(short_file_identifier, record_index) {
                Some(data) => {
                    if data[0] != 0x70 {
                        warn!("Expected template data");
                        return Err(());
                    }

                    if let Value::Constructed(application_templates) = parse_tlv(&data).unwrap().value() {
                        for tag_61_application_template in application_templates {
                            if let Value::Constructed(application_template) = tag_61_application_template.value() {
                                self.tags.clear();

                                for application_template_child_tag in application_template {
                                    if let Value::Primitive(value) = application_template_child_tag.value() {
                                        let tag_name = hex::encode(application_template_child_tag.tag().to_bytes()).to_uppercase();
                                        self.add_tag(&tag_name, value.to_vec());
                                    }
                                }

                                let tag_4f_aid = self.get_tag_value("4F").unwrap();
                                let tag_50_label = self.get_tag_value("50").unwrap();
                                
                                if let Some(tag_87_priority) = self.get_tag_value("87") {
                                    all_applications.push(EmvApplication {
                                        aid: tag_4f_aid.clone(),
                                        label: tag_50_label.clone(),
                                        priority: tag_87_priority.clone()
                                    });
                                } else {
                                    debug!("Skipping application. AID:{:02X?}, label:{:?}", tag_4f_aid, str::from_utf8(&tag_50_label).unwrap());
                                }

                            }
                        }
                    }

                },
                None => break
            };
        }

        if all_applications.is_empty() {
            warn!("No application records found!");
            return Err(());
        }

        Ok(all_applications)
    }

    fn handle_select_payment_application(&mut self, application : &EmvApplication) -> Result<(), ()> {
        info!("Selecting application. AID:{:02X?}, label:{:?}, priority:{:02X?}", application.aid, str::from_utf8(&application.label).unwrap(), application.priority);
        let (response_trailer, _) = self.send_apdu_select(&application.aid);
        if !is_success_response(&response_trailer) {
            warn!("Could not select payment application! {:02X?}, {:?}", application.aid, application.label);
            return Err(());
        }

        Ok(())
    }

    fn handle_get_data(&mut self, tag : &[u8]) -> Result<Vec<u8>, ()> {
        debug!("GET DATA:");

        assert_eq!(tag.len(), 2);
        assert_eq!(tag[0], 0x9F);
        //allowed tags: 9F36, 9F13, 9F17 or 9F4F

        let apdu_command_get_data = b"\x80\xCA";

        let mut get_data_command = apdu_command_get_data.to_vec();
        get_data_command.extend_from_slice(tag);
        get_data_command.push(0x05);

        let (response_trailer, response_data) = self.send_apdu(&get_data_command[..]);
        if !is_success_response(&response_trailer) {
            // 67 00 = wrong length (i.e. CDOL data incorrect)
            warn!("Could not process get data");
            return Err(());
        }

        let mut output : Vec<u8> = Vec::new();
        output.extend_from_slice(&response_data);

        Ok(output)
    }

    fn handle_get_challenge(&mut self) -> Result<Vec<u8>, ()> {
        debug!("GET CHALLENGE:");

        let apdu_command_get_challenge = b"\x00\x84\x00\x00\x00";

        let (response_trailer, response_data) = self.send_apdu(&apdu_command_get_challenge[..]);
        if !is_success_response(&response_trailer) {
            // 67 00 = wrong length (i.e. CDOL data incorrect)
            warn!("Could not process get challenge");
            return Err(());
        }

        let mut output : Vec<u8> = Vec::new();
        output.extend_from_slice(&response_data);

        Ok(output)
    }

    fn get_issuer_public_key(&self, application : &EmvApplication) -> Result<(Vec<u8>, Vec<u8>), ()> {

        // ref. https://www.emvco.com/wp-content/uploads/2017/05/EMV_v4.3_Book_2_Security_and_Key_Management_20120607061923900.pdf - 6.3 Retrieval of Issuer Public Key

        let ca_json_data = r#"
        {
            "A000000003": {
                "issuer": "Visa",
                "certificates": {
                    "92": {
                        "modulus": "996AF56F569187D09293C14810450ED8EE3357397B18A2458EFAA92DA3B6DF6514EC060195318FD43BE9B8F0CC669E3F844057CBDDF8BDA191BB64473BC8DC9A730DB8F6B4EDE3924186FFD9B8C7735789C23A36BA0B8AF65372EB57EA5D89E7D14E9C7B6B557460F10885DA16AC923F15AF3758F0F03EBD3C5C2C949CBA306DB44E6A2C076C5F67E281D7EF56785DC4D75945E491F01918800A9E2DC66F60080566CE0DAF8D17EAD46AD8E30A247C9F",
                        "exponent": "03"
                    }
                }
            },
            "A000000004": {
                "issuer": "MasterCard",
                "certificates": {
                    "FA": {
                        "modulus": "A90FCD55AA2D5D9963E35ED0F440177699832F49C6BAB15CDAE5794BE93F934D4462D5D12762E48C38BA83D8445DEAA74195A301A102B2F114EADA0D180EE5E7A5C73E0C4E11F67A43DDAB5D55683B1474CC0627F44B8D3088A492FFAADAD4F42422D0E7013536C3C49AD3D0FAE96459B0F6B1B6056538A3D6D44640F94467B108867DEC40FAAECD740C00E2B7A8852D",
                        "exponent": "03"
                    }
                }
            }
        }"#;
        let ca_data : HashMap<String, CertificateAuthority> = serde_json::from_str(ca_json_data).unwrap();

        let tag_92_issuer_pk_remainder = self.get_tag_value("92").unwrap();
        let tag_9f32_issuer_pk_exponent = self.get_tag_value("9F32").unwrap();
        let tag_90_issuer_public_key_certificate = self.get_tag_value("90").unwrap();

        let rid = &application.aid[0..5];
        let tag_8f_ca_pk_index = self.get_tag_value("8F").unwrap();
     
        let ca_pk = get_ca_public_key(&ca_data, &rid[..], &tag_8f_ca_pk_index[..]).unwrap();

        let issuer_certificate = ca_pk.public_decrypt(&tag_90_issuer_public_key_certificate[..]).unwrap();
        let issuer_certificate_length = issuer_certificate.len();

        if issuer_certificate[1] != 0x02 {
            warn!("Incorrect issuer certificate type {:02X?}", issuer_certificate[1]);
            return Err(());
        }

        let checksum_position = 15 + issuer_certificate_length - 36;

        let issuer_certificate_iin    = &issuer_certificate[2..6];
        let issuer_certificate_expiry = &issuer_certificate[6..8];
        let issuer_certificate_serial = &issuer_certificate[8..11];
        let issuer_certificate_hash_algorithm = &issuer_certificate[11..12];
        let issuer_pk_algorithm = &issuer_certificate[12..13];
        let issuer_pk_length = &issuer_certificate[13..14];
        let issuer_pk_exponent_length = &issuer_certificate[14..15];
        let issuer_pk_leftmost_digits = &issuer_certificate[15..checksum_position];
        debug!("Issuer Identifier:{:02X?}", issuer_certificate_iin);
        debug!("Issuer expiry:{:02X?}", issuer_certificate_expiry);
        debug!("Issuer serial:{:02X?}", issuer_certificate_serial);
        debug!("Issuer hash algo:{:02X?}", issuer_certificate_hash_algorithm);
        debug!("Issuer pk algo:{:02X?}", issuer_pk_algorithm);
        debug!("Issuer pk length:{:02X?}", issuer_pk_length);
        debug!("Issuer pk exp length:{:02X?}", issuer_pk_exponent_length);
        debug!("Issuer pk leftmost digits:{:02X?}", issuer_pk_leftmost_digits);

        assert_eq!(issuer_certificate_hash_algorithm[0], 0x01); // SHA-1
        assert_eq!(issuer_pk_algorithm[0], 0x01); // RSA as defined in EMV Book 2, B2.1 RSA Algorihm

        let issuer_certificate_checksum = &issuer_certificate[checksum_position..checksum_position + 20];

        let mut checksum_data : Vec<u8> = Vec::new();
        checksum_data.extend_from_slice(&issuer_certificate[1..checksum_position]);
        checksum_data.extend_from_slice(&tag_92_issuer_pk_remainder[..]);
        checksum_data.extend_from_slice(&tag_9f32_issuer_pk_exponent[..]);

        let cert_checksum = sha::sha1(&checksum_data[..]);

        assert_eq!(cert_checksum, issuer_certificate_checksum);

        let tag_5a_pan = self.get_tag_value("5A").unwrap();
        let ascii_pan = bcd_to_ascii(&tag_5a_pan[..]).unwrap();
        let ascii_iin = bcd_to_ascii(&issuer_certificate_iin).unwrap();
        assert_eq!(ascii_iin, &ascii_pan[0..ascii_iin.len()]);

        is_certificate_expired(&issuer_certificate_expiry[..]);

        let mut issuer_pk_modulus : Vec<u8> = Vec::new();
        issuer_pk_modulus.extend_from_slice(issuer_pk_leftmost_digits);
        issuer_pk_modulus.extend_from_slice(&tag_92_issuer_pk_remainder[..]);
        trace!("Issuer PK modulus:\n{}", HexViewBuilder::new(&issuer_pk_modulus[..]).finish());

        Ok((issuer_pk_modulus, tag_9f32_issuer_pk_exponent.to_vec()))
    }


    fn get_icc_public_key(&self, icc_pk_certificate : &Vec<u8>, icc_pk_exponent : &Vec<u8>, icc_pk_remainder : Option<&Vec<u8>>, issuer_pk_modulus : &[u8], issuer_pk_exponent : &[u8], data_authentication : &[u8]) -> Result<(Vec<u8>, Vec<u8>), ()> {
        // ICC public key retrieval: EMV Book 2, 6.4 Retrieval of ICC Public Key
        debug!("Retrieving ICC public key {:02X?}", &icc_pk_certificate[0..2]);

        let tag_9f46_icc_pk_certificate = icc_pk_certificate;

        let issuer_pk = RsaPublicKey::new(issuer_pk_modulus, issuer_pk_exponent);
        let icc_certificate = issuer_pk.public_decrypt(&tag_9f46_icc_pk_certificate[..]).unwrap();
        let icc_certificate_length = icc_certificate.len();
        if icc_certificate[1] != 0x04 {
            warn!("Incorrect ICC certificate type {:02X?}", icc_certificate[1]);
            return Err(());
        }

        let checksum_position = 21 + icc_certificate_length-42;

        let icc_certificate_pan = &icc_certificate[2..12];
        let icc_certificate_expiry = &icc_certificate[12..14];
        //let icc_certificate_serial = &icc_certificate[14..17];
        let icc_certificate_hash_algo = &icc_certificate[17..18];
        let icc_certificate_pk_algo = &icc_certificate[18..19];
        //let icc_certificate_pk_length = &icc_certificate[19..20];
        //let icc_certificate_pk_exp_length = &icc_certificate[20..21];
        let icc_certificate_pk_leftmost_digits = &icc_certificate[21..checksum_position];

        assert_eq!(icc_certificate_hash_algo[0], 0x01); // SHA-1
        assert_eq!(icc_certificate_pk_algo[0], 0x01); // RSA as defined in EMV Book 2, B2.1 RSA Algorihm

        let tag_9f47_icc_pk_exponent = icc_pk_exponent;

        let mut checksum_data : Vec<u8> = Vec::new();
        checksum_data.extend_from_slice(&icc_certificate[1..checksum_position]);

        let tag_9f48_icc_pk_remainder = icc_pk_remainder;
        if let Some(tag_9f48_icc_pk_remainder) = tag_9f48_icc_pk_remainder {
            checksum_data.extend_from_slice(&tag_9f48_icc_pk_remainder[..]);
        }

        checksum_data.extend_from_slice(&tag_9f47_icc_pk_exponent[..]);

        checksum_data.extend_from_slice(data_authentication);

        let static_data_authentication_tag_list_tag_values = self.get_tag_list_tag_values(&self.get_tag_value("9F4A").unwrap()[..]).unwrap();

        checksum_data.extend_from_slice(&static_data_authentication_tag_list_tag_values[..]);

        let cert_checksum = sha::sha1(&checksum_data[..]);

        let icc_certificate_checksum = &icc_certificate[checksum_position .. checksum_position + 20];

        trace!("Checksum data: {:02X?}", &checksum_data[..]);
        trace!("Calculated checksum: {:02X?}", cert_checksum);
        trace!("Stored ICC checksum: {:02X?}", icc_certificate_checksum);
        assert_eq!(cert_checksum, icc_certificate_checksum);

        let tag_5a_pan = self.get_tag_value("5A").unwrap();
        let ascii_pan = bcd_to_ascii(&tag_5a_pan[..]).unwrap();
        let icc_ascii_pan = bcd_to_ascii(&icc_certificate_pan).unwrap();
        assert_eq!(icc_ascii_pan, ascii_pan);

        is_certificate_expired(&icc_certificate_expiry[..]);


        let mut icc_pk_modulus : Vec<u8> = Vec::new();
        
        let icc_certificate_pk_leftmost_digits_length = icc_certificate_pk_leftmost_digits.iter()
            .rev().position(|c| -> bool { *c != 0xBB }).map(|i| icc_certificate_pk_leftmost_digits.len() - i).unwrap();

        icc_pk_modulus.extend_from_slice(&icc_certificate_pk_leftmost_digits[..icc_certificate_pk_leftmost_digits_length]);

        if let Some(tag_9f48_icc_pk_remainder) = tag_9f48_icc_pk_remainder {
            icc_pk_modulus.extend_from_slice(&tag_9f48_icc_pk_remainder[..]);
        }

        trace!("ICC PK modulus ({} bytes):\n{}", icc_pk_modulus.len(), HexViewBuilder::new(&icc_pk_modulus[..]).finish());

        Ok((icc_pk_modulus, tag_9f47_icc_pk_exponent.to_vec()))
    }

    fn handle_dynamic_data_authentication(&mut self, icc_pk_modulus : &[u8], icc_pk_exponent : &[u8]) -> Result<(),()> {
        debug!("Perform Dynamic Data Authentication (DDA):");

        let mut rng = ChaCha20Rng::from_entropy();
        let mut tag_9f37_unpredictable_number = [0u8; 4];
        rng.try_fill(&mut tag_9f37_unpredictable_number[..]).unwrap();
        self.add_tag("9F37", tag_9f37_unpredictable_number.to_vec());

        let ddol_default_value = b"\x9f\x37\x04".to_vec();
        let tag_9f49_ddol = match self.get_tag_value("9F49") {
            Some(ddol) => ddol,
            // fall-back to a default DDOL
            None => &ddol_default_value
        };

        let ddol_data = self.get_tag_list_tag_values(&tag_9f49_ddol[..]).unwrap();

        let mut auth_data : Vec<u8> = Vec::new();
        auth_data.extend_from_slice(&ddol_data[..]);

        let apdu_command_internal_authenticate = b"\x00\x88\x00\x00";
        let mut internal_authenticate_command = apdu_command_internal_authenticate.to_vec();
        internal_authenticate_command.push(auth_data.len() as u8);
        internal_authenticate_command.extend_from_slice(&auth_data[..]);
        internal_authenticate_command.push(0x00);

        let (response_trailer, response_data) = self.send_apdu(&internal_authenticate_command);
        if !is_success_response(&response_trailer) {
            warn!("Could not process internal authenticate");
            return Err(());
        }

        if response_data[0] == 0x80 {
            self.add_tag("9F4B", response_data[3..].to_vec());
        } else if response_data[0] != 0x77 {
            warn!("Unrecognized response");
            return Err(());
        }

        let tag_9f4b_signed_data = self.get_tag_value("9F4B").unwrap();
        trace!("9F4B signed data result moduluslength:{}, ({} bytes):\n{}", icc_pk_modulus.len(), tag_9f4b_signed_data.len(), HexViewBuilder::new(&tag_9f4b_signed_data[..]).finish());

        let icc_pk = RsaPublicKey::new(icc_pk_modulus, icc_pk_exponent);
        let tag_9f4b_signed_data_decrypted = icc_pk.public_decrypt(&tag_9f4b_signed_data[..]).unwrap();
        let tag_9f4b_signed_data_decrypted_length = tag_9f4b_signed_data_decrypted.len();
        if tag_9f4b_signed_data_decrypted[1] != 0x05 {
            warn!("Unrecognized format");
            return Err(());
        }

        let tag_9f4b_signed_data_decrypted_hash_algo = tag_9f4b_signed_data_decrypted[2];
        assert_eq!(tag_9f4b_signed_data_decrypted_hash_algo, 0x01);

        let tag_9f4b_signed_data_decrypted_dynamic_data_length = tag_9f4b_signed_data_decrypted[3] as usize;
        
        let tag_9f4b_signed_data_decrypted_dynamic_data = &tag_9f4b_signed_data_decrypted[4..4+tag_9f4b_signed_data_decrypted_dynamic_data_length];
        let tag_9f4c_icc_dynamic_number = &tag_9f4b_signed_data_decrypted_dynamic_data[1..];
        self.add_tag("9F4C", tag_9f4c_icc_dynamic_number.to_vec());

        let checksum_position = tag_9f4b_signed_data_decrypted_length - 21;
        let mut checksum_data : Vec<u8> = Vec::new();
        checksum_data.extend_from_slice(&tag_9f4b_signed_data_decrypted[1..checksum_position]);
        checksum_data.extend_from_slice(&auth_data[..]);

        let signed_data_checksum = sha::sha1(&checksum_data[..]);

        let tag_9f4b_signed_data_decrypted_checksum = &tag_9f4b_signed_data_decrypted[checksum_position..checksum_position+20];

        assert_eq!(signed_data_checksum, tag_9f4b_signed_data_decrypted_checksum);

        Ok(())
    }

    // EMV has some tags that don't conform to ISO/IEC 7816
    fn is_non_conforming_one_byte_tag(&self, tag : u8) -> bool {
        if tag == 0x95 {
            return true;
        }

        false
    }

    fn get_tag_list_tag_values(&self, tag_list : &[u8]) -> Result<Vec<u8>, ()> {
        let mut output : Vec<u8> = Vec::new();

        if tag_list.len() < 2 {
            let tag_name = hex::encode(&tag_list[0..1]).to_uppercase();
            let value = match self.get_tag_value(&tag_name) {
                Some(value) => value,
                None => {
                    warn!("tag {:?} has no value", tag_name);
                    return Err(());
                }
            };

            output.extend_from_slice(&value[..]);
        } else {
            let mut i = 0;
            loop {
                let tag_value_length : usize;

                let mut tag_name = hex::encode(&tag_list[i..i+1]).to_uppercase();

                if Tag::try_from(tag_name.as_str()).is_ok() || self.is_non_conforming_one_byte_tag(tag_list[i]) {
                    tag_value_length = tag_list[i+1] as usize;
                    i += 2;
                } else {
                    tag_name = hex::encode(&tag_list[i..i+2]).to_uppercase();
                    if Tag::try_from(tag_name.as_str()).is_ok() {
                        tag_value_length = tag_list[i+2] as usize;
                        i += 3;
                    } else {
                        warn!("Incorrect tag {:?}", tag_name);
                        return Err(());
                    }
                }

                let value = match self.get_tag_value(&tag_name) {
                    Some(value) => value,
                    None => {
                        warn!("tag {:?} has no value", tag_name);
                        return Err(());
                    }
                };

                if value.len() != tag_value_length {
                    warn!("tag {:?} value length {:02X} does not match tag list value length {:02X}", tag_name, value.len(), tag_value_length);
                    return Err(());
                }

                output.extend_from_slice(&value[..]);

                if i >= tag_list.len() {
                    break;
                }
            }
        }

        Ok(output)
    }
}

struct EmvApplication {
    aid : Vec<u8>,
    label : Vec<u8>,
    priority : Vec<u8>
}

#[derive(Serialize, Deserialize)]
struct EmvTag {
    tag: String,
    name: String
}
 
#[derive(Serialize, Deserialize)]
struct RsaPublicKey {
    modulus: String,
    exponent: String
}

impl RsaPublicKey {
    fn new(modulus : &[u8], exponent : &[u8]) -> RsaPublicKey {
        RsaPublicKey { modulus: hex::encode_upper(modulus), exponent: hex::encode_upper(exponent) }
    }

    fn public_encrypt(&self, plaintext_data : &[u8]) -> Result<Vec<u8>, ()> {
        let pk_modulus_raw = hex::decode(&self.modulus).unwrap();
        let pk_modulus = BigNum::from_slice(&pk_modulus_raw[..]).unwrap();
        let pk_exponent = BigNum::from_slice(&(hex::decode(&self.exponent).unwrap())[..]).unwrap();

        let rsa = Rsa::from_public_components(pk_modulus, pk_exponent).unwrap();

        let mut encrypt_output = [0u8; 4096];

        let length = match rsa.public_encrypt(plaintext_data, &mut encrypt_output[..], Padding::NONE) {
            Ok(length) => length,
            Err(_) => {
                warn!("Could not decrypt data");
                return Err(());
            }
        };

        let mut data = Vec::new();
        data.extend_from_slice(&encrypt_output[..length]);

        trace!("Encrypt result ({} bytes):\n{}", data.len(), HexViewBuilder::new(&data[..]).finish());

        if data.len() != pk_modulus_raw.len() {
            warn!("Data length discrepancy");
            return Err(());
        }

        Ok(data)
    }

    fn public_decrypt(&self, cipher_data : &[u8]) -> Result<Vec<u8>, ()> {
        let pk_modulus_raw = hex::decode(&self.modulus).unwrap();
        let pk_modulus = BigNum::from_slice(&pk_modulus_raw[..]).unwrap();
        let pk_exponent = BigNum::from_slice(&(hex::decode(&self.exponent).unwrap())[..]).unwrap();

        let rsa = Rsa::from_public_components(pk_modulus, pk_exponent).unwrap();

        let mut decrypt_output = [0u8; 4096];

        let length = match rsa.public_decrypt(cipher_data, &mut decrypt_output[..], Padding::NONE) {
            Ok(length) => length,
            Err(_) => {
                warn!("Could not decrypt data");
                return Err(());
            }
        };

        let mut data = Vec::new();
        data.extend_from_slice(&decrypt_output[..length]);

        trace!("Decrypt result ({} bytes):\n{}", data.len(), HexViewBuilder::new(&data[..]).finish());

        if data.len() != pk_modulus_raw.len() {
            warn!("Data length discrepancy");
            return Err(());
        }
        if data[0] != 0x6A {
            warn!("Data header incorrect");
            return Err(());
        }
        if data[data.len() - 1] != 0xBC {
            warn!("Data trailer incorrect");
            return Err(());
        }

        Ok(data)
    }
}

#[derive(Serialize, Deserialize)]
struct CertificateAuthority {
    issuer: String,
    certificates: HashMap<String, RsaPublicKey>
}

fn is_success_response(response_trailer : &Vec<u8>) -> bool {
    let mut success = false;

    if response_trailer.len() >= 2
        && response_trailer[0] == 0x90 && response_trailer[1] == 0x00 {
        success = true;
    }

    success
}

fn initialize_logging() {
    let stdout = ConsoleAppender::builder().build();
    let stdout_append_name = "stdout";

    let config = Config::builder()
        .appender(Appender::builder().build(stdout_append_name, Box::new(stdout)))
        .build(Root::builder().appender(stdout_append_name).build(LevelFilter::Trace))
        .unwrap();

    let _handle = log4rs::init_config(config).unwrap();
}

fn parse_tlv(raw_data : &[u8]) -> Option<Tlv> {
    let (tlv_data, leftover_buffer) = Tlv::parse(raw_data);
    if leftover_buffer.len() > 0 {
        trace!("Could not parse as TLV: {:02X?}", leftover_buffer);
    }

    let tlv_data : Option<Tlv> = match tlv_data {
        Ok(tlv) => Some(tlv),
        Err(_) => None

    };

    return tlv_data;
}

fn bcd_to_ascii(bcd_data : &[u8]) -> Result<Vec<u8>, ()> {
    let mut ascii_output : Vec<u8> = Vec::with_capacity(bcd_data.len() * 2);

    const ASCII_CHARACTER_0 : u8 = 0x30;

    for i in 0..bcd_data.len() {
        let byte = bcd_data[i];
        let n2 = byte >> 4;
        let n1 = byte & 0xF;

        if byte == 0xFF {
            break;
        }
        ascii_output.push(ASCII_CHARACTER_0 + n2);

        if n1 != 0xF {
            ascii_output.push(ASCII_CHARACTER_0 + n1);
        } else if i != bcd_data.len() - 1 {
            return Err(());
        }

        if n1 > 0x9 || n2 > 0x9 {
            return Err(());
        }
    }

    Ok(ascii_output)
}

//cn = 12 34 56 78 90 12 3F FF
fn ascii_to_bcd_cn(ascii_data : &[u8], size : usize) -> Result<Vec<u8>, ()> {
    let mut bcd_output : Vec<u8> = Vec::with_capacity(size);

    assert!(ascii_data.len() <= size * 2);

    const ASCII_CHARACTER_0 : u8 = 0x30;

    for i in (0..ascii_data.len()).step_by(2) {
        let b1 = ascii_data[i] - ASCII_CHARACTER_0;
        if b1 > 0x9 {
            return Err(());
        }

        let mut b2 = 0xF;
        if i + 1 < ascii_data.len() {
            b2 = ascii_data[i + 1] - ASCII_CHARACTER_0;
            if b2 > 0x9 {
                return Err(());
            }
        }

        let bcd_byte = b2 + (b1 << 4);

        bcd_output.push(bcd_byte);
    }

    for _ in bcd_output.len()..size {
        let bcd_byte = 0xFF;
        bcd_output.push(bcd_byte);
    }

    assert_eq!(bcd_output.len(), size);

    Ok(bcd_output)
}

//n = 00 00 00 01 23 45
fn ascii_to_bcd_n(ascii_data : &[u8], size : usize) -> Result<Vec<u8>, ()> {
    let mut bcd_output : Vec<u8> = Vec::with_capacity(size);

    assert!(ascii_data.len() <= size * 2);

    const ASCII_CHARACTER_0 : u8 = 0x30;

    let mut ascii_data_aligned : Vec<u8> = Vec::new();
    if ascii_data.len() % 2 == 1 {
        ascii_data_aligned.push(ASCII_CHARACTER_0);
    }
    ascii_data_aligned.extend_from_slice(&ascii_data[..]);

    for _ in ascii_data_aligned.len()/2..size {
        let bcd_byte = 0x00;
        bcd_output.push(bcd_byte);
    }

    for i in (0..ascii_data_aligned.len()).step_by(2) {
        let b1 = ascii_data_aligned[i] - ASCII_CHARACTER_0;
        if b1 > 0x9 {
            return Err(());
        }

        let b2 = ascii_data_aligned[i+1] - ASCII_CHARACTER_0;
        if b2 > 0x9 {
            return Err(());
        }

        let bcd_byte = b2 + (b1 << 4);

        bcd_output.push(bcd_byte);
    }

    assert_eq!(bcd_output.len(), size);

    Ok(bcd_output)
}

fn get_ca_public_key<'a>(ca_data : &'a HashMap<String, CertificateAuthority>, rid : &[u8], index : &[u8]) -> Option<&'a RsaPublicKey> {
    match ca_data.get(&hex::encode_upper(&rid)) {
        Some(ca) => {
            match ca.certificates.get(&hex::encode_upper(&index)) {
                Some(pk) => Some(pk),
                _ => None
            }
        },
        _ => None
    }
}

fn is_certificate_expired(date_bcd : &[u8]) -> bool {
    let today = Utc::today().naive_utc();
    let expiry_date = NaiveDate::parse_from_str(&format!("01{:02X?}", date_bcd), "%d[%m, %y]").unwrap();
    let duration = today.signed_duration_since(expiry_date).num_days();

    if duration > 30 {
        warn!("Certificate expiry date (MMYY) {:02X?} is {} days in the past", date_bcd, duration.to_string());

        return true;
    }

    false
}


fn run() -> Result<Option<String>, String> {
    initialize_logging();

    let matches = App::new("Minimum Viable Payment Terminal")
        .version("0.1")
        .about("EMV transaction simulation")
        .arg(Arg::with_name("interactive")
            .long("interactive")
            .help("Simulate payment terminal purchase sequence"))
        .arg(Arg::with_name("pin")
            .short("p")
            .long("pin")
            .value_name("PIN CODE")
            .help("Card PIN code")
            .takes_value(true))
        .get_matches();

    let interactive = matches.is_present("interactive");

    let mut connection = EmvConnection::new().unwrap();

    let mut purchase_amount = "1".to_string();

    if interactive {
        println!("Enter amount:");
        print!("> ");
        let mut stdin_buffer = String::new();
        io::stdin().read_line(&mut stdin_buffer).unwrap();

        purchase_amount = format!("{:.0}", stdin_buffer.trim().parse::<f64>().unwrap() * 100.0);
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

    let application = &applications[application_number];
    connection.handle_select_payment_application(application).unwrap();

    connection.add_tag("9F02", ascii_to_bcd_n(purchase_amount.as_bytes(), 6).unwrap());

    let search_tag = b"\x9f\x36";
    connection.handle_get_data(&search_tag[..]).unwrap(); // TODO: just testing, this not needed

    let data_authentication = connection.handle_get_processing_options().unwrap();

    let (issuer_pk_modulus, issuer_pk_exponent) = connection.get_issuer_public_key(application).unwrap();

    let tag_9f46_icc_pk_certificate = connection.get_tag_value("9F46").unwrap();
    let tag_9f47_icc_pk_exponent = connection.get_tag_value("9F47").unwrap();
    let tag_9f48_icc_pk_remainder = connection.get_tag_value("9F48");
    let (icc_pk_modulus, icc_pk_exponent) = connection.get_icc_public_key(
        tag_9f46_icc_pk_certificate, tag_9f47_icc_pk_exponent, tag_9f48_icc_pk_remainder,
        &issuer_pk_modulus[..], &issuer_pk_exponent[..],
        &data_authentication[..]).unwrap();

    connection.handle_dynamic_data_authentication(&icc_pk_modulus[..], &icc_pk_exponent[..]).unwrap();

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
        //connection.handle_verify_plaintext_pin(ascii_pin.unwrap().as_bytes()).unwrap();

        let mut icc_pin_pk_modulus = icc_pk_modulus;
        let mut icc_pin_pk_exponent = icc_pk_exponent;

        let tag_9f2d_icc_pin_pk_certificate = connection.get_tag_value("9F2D");
        let tag_9f2e_icc_pin_pk_exponent = connection.get_tag_value("9F2E");
        if tag_9f2d_icc_pin_pk_certificate.is_some() && tag_9f2e_icc_pin_pk_exponent.is_some() {
            let tag_9f2f_icc_pin_pk_remainder = connection.get_tag_value("9F2F");

            // ICC has a separate ICC PIN Encipherement public key
            let (icc_pin_pk_modulus2, icc_pin_pk_exponent2) = connection.get_icc_public_key(
                tag_9f2d_icc_pin_pk_certificate.unwrap(), tag_9f2e_icc_pin_pk_exponent.unwrap(), tag_9f2f_icc_pin_pk_remainder,
                &issuer_pk_modulus[..], &issuer_pk_exponent[..],
                &data_authentication[..]).unwrap();

            icc_pin_pk_modulus = icc_pin_pk_modulus2;
            icc_pin_pk_exponent = icc_pin_pk_exponent2;
        }

        connection.handle_verify_enciphered_pin(ascii_pin.unwrap().as_bytes(), &icc_pin_pk_modulus[..], &icc_pin_pk_exponent[..]).unwrap();
    }

    connection.handle_generate_ac().unwrap();

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
