use pcsc::{Context, Card, Scope, ShareMode, Protocols, Error, MAX_BUFFER_SIZE, MAX_ATR_SIZE};
use hexplay::HexViewBuilder;
use iso7816_tlv::ber::{Tlv, Tag, Value};
use std::collections::HashMap;
use std::str;
use std::convert::TryFrom;
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
use chrono::{DateTime, NaiveDate, TimeZone, Utc};

macro_rules! get_bit {
    ($byte:expr, $bit:expr) => (if $byte & (1 << $bit) != 0 { true } else { false });
}

struct EmvConnection {
    tags : HashMap<String, Vec<u8>>,
    ctx : Context,
    card : Card
}

impl EmvConnection {
    fn new() -> Result<EmvConnection, String> {

        let ctx = match Context::establish(Scope::User) {
            Ok(ctx) => ctx,
            Err(err) => {
                return Err(format!("Failed to establish context: {}", err));
            }
        };

        const MAX_READER_SIZE : usize = 2048;
        let mut readers_buf = [0; MAX_READER_SIZE];
        let mut readers = match ctx.list_readers(&mut readers_buf) {
            Ok(readers) => readers,
            Err(err) => {
                return Err(format!("Failed to list readers: {}", err));
            }
        };

        let reader = match readers.next() {
            Some(reader) => reader,
            None => {
                return Err(format!("No readers are connected."));
            }
        };

        // Connect to the card.
        let card = match ctx.connect(reader, ShareMode::Shared, Protocols::ANY) {
            Ok(card) => card,
            Err(Error::NoSmartcard) => {
                return Err(format!("No card found in the reader"));
            },
            Err(err) => {
                return Err(format!("Could not connect to the card: {}", err));
            }
        };

        let mut names_buffer = [0; MAX_READER_SIZE];
        let mut atr_buffer = [0; MAX_ATR_SIZE];
        let card_status = card.status2(&mut names_buffer, &mut atr_buffer).unwrap();

        // https://www.eftlab.com/knowledge-base/171-atr-list-full/
        info!("Card reader: {:?}", reader);
        info!("Card ATR:\n{}", HexViewBuilder::new(card_status.atr()).finish());
        info!("Card protocol: {:?}", card_status.protocol2().unwrap());

        Ok ( EmvConnection { tags : HashMap::new(), ctx : ctx, card : card } )
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
            let apdu_response = self.card.transmit(apdu_command, &mut apdu_response_buffer).unwrap();

            response_data.extend_from_slice(&apdu_response[0..apdu_response.len()-2]);

            // response codes: https://www.eftlab.com/knowledge-base/complete-list-of-apdu-responses/
            response_trailer = vec![apdu_response[apdu_response.len()-2], apdu_response[apdu_response.len()-1]];
            debug!("APDU response status: {:02X?}", response_trailer);

            // Automatically query more data, if available from the ICC
            const SW1_BYTES_AVAILABLE : u8 = 0x61;
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
                "94":   { "tag":"94", "name":"Application File Locator (AFL)" }                
            }"#;

        let emv_tags : HashMap<String, EmvTag> = serde_json::from_str(emv_definition_data).unwrap();

        let tlv_data = parse_tlv(&buf);

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

        let tag_82_aip = self.get_tag_value("82").unwrap();

        let aip_b1 : u8 = tag_82_aip[0];
        // bit 0 = RFU
        if get_bit!(aip_b1, 1) {
            info!("SDA supported");
        }
        if get_bit!(aip_b1, 2) {
            info!("DDA supported");
        }
        if get_bit!(aip_b1, 3) {
            info!("Cardholder verification is supported");
        }
        if get_bit!(aip_b1, 4) {
            info!("Terminal risk management is to be performed");
        }
        if get_bit!(aip_b1, 5) {
            info!("Issuer authentication is supported");
        }
        // bit 6 = RFU
        if get_bit!(aip_b1, 7) {
            info!("CDA supported");
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

                        let data_authentication_data;
                        if short_file_identifier <= 10 {
                            data_authentication_data = &data[3..];
                        } else {
                            data_authentication_data = &data[..];
                        }
                        data_authentication.extend_from_slice(&data_authentication_data);

                        trace!("Data authentication building: short_file_identifier:{}, data_authentication_records:{}, record_index:{}/{}, data:{:02X?}", short_file_identifier, data_authentication_records, record_index, record_index_end, data_authentication_data);
                    }
                }
            }
        }

        debug!("AFL data authentication:\n{}", HexViewBuilder::new(&data_authentication).finish());

        Ok(data_authentication)
    }

    fn handle_verify(&mut self, ascii_pin : &[u8]) -> Result<(), ()> {
        debug!("Verify PIN:");

        let pin_bcd_nc = ascii_to_bcd_cn(ascii_pin, 6).unwrap();

        let apdu_command_verify = b"\x00\x20\x00";
        let mut verify_command = apdu_command_verify.to_vec();
        let p2_pin_type_qualifier = 0b1000_0000;
        verify_command.push(p2_pin_type_qualifier);
        verify_command.push(0x08); // data length
        verify_command.push(0b0010_0000 + ascii_pin.len() as u8); // control + PIN length
        verify_command.extend_from_slice(&pin_bcd_nc[..]);
        verify_command.push(0xFF); // filler

        let (response_trailer, response_data) = self.send_apdu(&verify_command);
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

        // TODO: handle CDOL1 dynamically
        // -8C: Card Risk Management Data Object List 1 (CDOL1)
        // -data: [9F02, 06, 9F03, 06, 9F1A, 02, 95, 05, 5F2A, 02, 9A, 03, 9C, 01, 9F37, 04] = ..........._*......7.

        let tag_9f02_amount_authorised           = b"\x00\x00\x00\x00\x00\x01";
        let tag_9f03_amount_other                = b"\x00\x00\x00\x00\x00\x00";
        // https://www.iso.org/obp/ui/#iso:code:3166:FI
        let tag_9f1a_terminal_country_code       = b"\x02\x46"; // FI
        let tag_95_terminal_verification_results = b"\x00\x00\x00\x00\x00";
        // https://www.currency-iso.org/dam/downloads/lists/list_one.xml
        let tag_5f2a_transaction_currency_code   = b"\x09\x78"; // EUR
        // YYMMDD
        let tag_9a_transaction_date              = b"\x20\x07\x15";
        // http://www.fintrnmsgtool.com/iso-processing-code.html
        let tag_9c_transaction_type              = b"\x21"; // Deposit (Credit)
        let tag_9f37_unpredictable_number        = b"\x00\x00\x00\x00";

        let mut cdol_data = Vec::new();
        cdol_data.extend_from_slice(&tag_9f02_amount_authorised[..]);
        cdol_data.extend_from_slice(&tag_9f03_amount_other[..]);
        cdol_data.extend_from_slice(&tag_9f1a_terminal_country_code[..]);
        cdol_data.extend_from_slice(&tag_95_terminal_verification_results[..]);
        cdol_data.extend_from_slice(&tag_5f2a_transaction_currency_code[..]);
        cdol_data.extend_from_slice(&tag_9a_transaction_date[..]);
        cdol_data.extend_from_slice(&tag_9c_transaction_type[..]);
        cdol_data.extend_from_slice(&tag_9f37_unpredictable_number[..]);

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

        let mut record_length = 0x00;
        read_record.push(record_length);

        let read_record_length = read_record.len();

        let (response_trailer, response_data) = self.send_apdu(&read_record);

        const SW1_WRONG_LENGTH : u8 = 0x6C;
        if response_trailer[0] == SW1_WRONG_LENGTH {
            record_length = response_trailer[1];
            read_record[read_record_length - 1] = record_length;
            let (response_trailer, response_data) = self.send_apdu(&read_record);

            if is_success_response(&response_trailer) {
                records.extend_from_slice(&response_data);
            }
        } else if is_success_response(&response_trailer) {
            records.extend_from_slice(&response_data);
        }

        if !records.is_empty() {
            return Some(records);
        }

        None
    }

    fn handle_select_payment_system_environment(&mut self) -> Result<Vec<EmvApplication>, ()> {
        debug!("Selecting Payment System Environment (PSE):");
        let contact_pse_name      = "1PAY.SYS.DDF01";

        let pse_name = contact_pse_name;

        let (response_trailer, response_data) = self.send_apdu_select(&pse_name.as_bytes());
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

                    if let Value::Constructed(application_templates) = parse_tlv(&data).value() {
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
        info!("Selecting application. AID:{:02X?}, label:{:?}", application.aid, str::from_utf8(&application.label).unwrap());
        let (response_trailer, _) = self.send_apdu_select(&application.aid);
        if !is_success_response(&response_trailer) {
            warn!("Could not select payment application! {:02X?}, {:?}", application.aid, application.label);
            return Err(());
        }

        Ok(())
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

        debug!("Issuer cert expiry (MMYY): {:?}", str::from_utf8(&bcd_to_ascii(&issuer_certificate_expiry).unwrap()).unwrap());
        // TODO: validate expiry

        let mut issuer_pk_modulus : Vec<u8> = Vec::new();
        issuer_pk_modulus.extend_from_slice(issuer_pk_leftmost_digits);
        issuer_pk_modulus.extend_from_slice(&tag_92_issuer_pk_remainder[..]);
        trace!("Issuer PK modulus:\n{}", HexViewBuilder::new(&issuer_pk_modulus[..]).finish());

        Ok((issuer_pk_modulus, tag_9f32_issuer_pk_exponent.to_vec()))
    }

    fn get_icc_public_key(&self, issuer_pk_modulus : &[u8], issuer_pk_exponent : &[u8], data_authentication : &[u8]) -> Result<(Vec<u8>, Vec<u8>), ()> {
        // ICC public key retrieval: EMV Book 2, 6.4 Retrieval of ICC Public Key
        debug!("Retrieving ICC public key");

        let tag_9f46_icc_pk_certificate = self.get_tag_value("9F46").unwrap();

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
        let icc_certificate_serial = &icc_certificate[14..17];
        let icc_certificate_hash_algo = &icc_certificate[17..18];
        let icc_certificate_pk_algo = &icc_certificate[18..19];
        let icc_certificate_pk_length = &icc_certificate[19..20];
        let icc_certificate_pk_exp_length = &icc_certificate[20..21];
        let icc_certificate_pk_leftmost_digits = &icc_certificate[21..checksum_position];

        assert_eq!(icc_certificate_hash_algo[0], 0x01); // SHA-1
        assert_eq!(icc_certificate_pk_algo[0], 0x01); // RSA as defined in EMV Book 2, B2.1 RSA Algorihm

        let tag_9f47_icc_pk_exponent = self.get_tag_value("9F47").unwrap().clone();

        let mut checksum_data : Vec<u8> = Vec::new();
        checksum_data.extend_from_slice(&icc_certificate[1..checksum_position]);
        checksum_data.extend_from_slice(&tag_9f47_icc_pk_exponent[..]);
        // NOT PRESENT: 9f48: Integrated Circuit Card (ICC) Public Key Remainder
        // checksum_data.extend_from_slice( 9f48 if exists ) TODO

        checksum_data.extend_from_slice(data_authentication);

        let tag_9f4a_static_data_authentication_tag_list = self.get_tag_value("9F4A").unwrap();
        // TODO: handle list
        assert_eq!(tag_9f4a_static_data_authentication_tag_list[0], 0x82);

        let tag_82_aip = self.get_tag_value("82").unwrap();
        checksum_data.extend_from_slice(&tag_82_aip[..]);

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

        trace!("ICC cert expiry (MMYY): {:?}", str::from_utf8(&bcd_to_ascii(&icc_certificate_expiry).unwrap()).unwrap());


        let mut icc_pk_modulus : Vec<u8> = Vec::new();
        
        let icc_certificate_pk_leftmost_digits_length = icc_certificate_pk_leftmost_digits.iter()
            .rev()
            .position(|c| -> bool { *c != 0xBB })
            .map(|i| icc_certificate_pk_leftmost_digits.len() - i).unwrap();

        icc_pk_modulus.extend_from_slice(&icc_certificate_pk_leftmost_digits[..icc_certificate_pk_leftmost_digits_length]);

        // NOT PRESENT: 9f48: Integrated Circuit Card (ICC) Public Key Remainder
        // icc_pk_modulus.extend_from_slice( 9f48 if exists ) TODO

        trace!("ICC PK modulus ({} bytes):\n{}", icc_pk_modulus.len(), HexViewBuilder::new(&icc_pk_modulus[..]).finish());

        Ok((icc_pk_modulus, tag_9f47_icc_pk_exponent))
    }

    fn handle_dynamic_data_authentication(&mut self, icc_pk_modulus : &[u8], icc_pk_exponent : &[u8]) -> Result<(),()> {
        debug!("Perform Dynamic Data Authentication (DDA):");

        let tag_9f49_ddol = self.get_tag_value("9F49").unwrap();
        // TODO parse DDOL - if DDOL does not exist then fall-back for 9F37 ddol

        let mut rng = ChaCha20Rng::from_entropy();
        let mut tag_9f37_unpredictable_number = [0u8; 4];
        rng.try_fill(&mut tag_9f37_unpredictable_number[..]).unwrap();

        let mut auth_data : Vec<u8> = Vec::new();
        auth_data.extend_from_slice(&tag_9f37_unpredictable_number[..]);

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
        assert_eq!(tag_9f4b_signed_data_decrypted[1], 0x05);

        let tag_9f4b_signed_data_decrypted_hash_algo = tag_9f4b_signed_data_decrypted[2];
        let tag_9f4b_signed_data_decrypted_data_length = tag_9f4b_signed_data_decrypted[3];

        let checksum_position = tag_9f4b_signed_data_decrypted_length - 21;
        let mut checksum_data : Vec<u8> = Vec::new();
        checksum_data.extend_from_slice(&tag_9f4b_signed_data_decrypted[1..checksum_position]);
        checksum_data.extend_from_slice(&auth_data[..]);

        let signed_data_checksum = sha::sha1(&checksum_data[..]);

        let tag_9f4b_signed_data_decrypted_checksum = &tag_9f4b_signed_data_decrypted[checksum_position..checksum_position+20];

        assert_eq!(signed_data_checksum, tag_9f4b_signed_data_decrypted_checksum);

        Ok(())
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

fn parse_tlv(raw_data : &[u8]) -> Tlv {
    let (tlv_data, leftover_buffer) = Tlv::parse(raw_data);
    if leftover_buffer.len() > 0 {
        warn!("Could not parse as TLV: {:02X?}", leftover_buffer);
    }

    let tlv_data = tlv_data.unwrap();

    return tlv_data;
}

// iso7816_tlv::ber::Tlv.find / find_all doesn't seem to work when earching constructed tags...
fn find_first_tag<'a>(tag_name : &str, tlv_data : &'a Tlv) -> Option<&'a Tlv> {
    //trace!("Looking for tag {:?} in {:02X?}", tag_name, tlv_data.to_vec());

    let tag = Tag::try_from(tag_name).unwrap();
    if tlv_data.tag().to_bytes() == tag.to_bytes() {
        return Some(tlv_data);
    }

    match tlv_data.value() {
        Value::Constructed(tlv_tags) => {
            for t in tlv_tags {
                match find_first_tag(tag_name, &t) {
                    Some(found) => return Some(found),
                    None => continue
                }
            }
        },
        Value::Primitive(_) => {
            return None
        }
    }

    return None
}

fn parse_tag_value(tag_name : &str, tlv_data : &Tlv) -> Option<Vec<u8>> {
    let tlv_tag = find_first_tag(tag_name, tlv_data).unwrap();
    if let Value::Primitive(value) = tlv_tag.value() {
        return Some(value.to_vec());
    }

    None
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
//n  = 00 00 00 01 23 45
fn ascii_to_bcd_cn(ascii_data : &[u8], size : usize) -> Result<Vec<u8>, ()> {
    let mut bcd_output : Vec<u8> = Vec::with_capacity(size);

    assert!(ascii_data.len() <= size);

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


fn run() -> Result<Option<String>, String> {
    initialize_logging();

    let matches = App::new("Minimum Viable Payment Terminal")
        .version("0.1")
        .about("EMV transaction simulation")
        .arg(Arg::with_name("pin")
            .short("p")
            .long("pin")
            .value_name("PIN CODE")
            .help("Card PIN code")
            .takes_value(true))
        .get_matches();

/*
    let today = Utc::today().naive_utc();
    let dt = NaiveDate::parse_from_str("010721", "%d%m%y").unwrap();
    let duration = today.signed_duration_since(dt).num_days();
    println!("date: {} {}", dt.to_string(), duration.to_string());
*/
    //return Ok(None);

    let mut connection = EmvConnection::new().unwrap();

    let applications = connection.handle_select_payment_system_environment().unwrap();

    let application = &applications[0];
    connection.handle_select_payment_application(application).unwrap();

    let data_authentication = connection.handle_get_processing_options().unwrap();

    let (issuer_pk_modulus, issuer_pk_exponent) = connection.get_issuer_public_key(application).unwrap();

    let (icc_pk_modulus, icc_pk_exponent) = connection.get_icc_public_key(&issuer_pk_modulus[..], &issuer_pk_exponent[..], &data_authentication[..]).unwrap();

    connection.handle_dynamic_data_authentication(&icc_pk_modulus[..], &icc_pk_exponent[..]).unwrap();

    let ascii_pin = matches.value_of("pin");
    if ascii_pin.is_some() {
        connection.handle_verify(ascii_pin.unwrap().as_bytes()).unwrap();
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
