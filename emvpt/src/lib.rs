use chrono::{Datelike, NaiveDate, Timelike, Utc};
use hex;
use hexplay::HexViewBuilder;
use iso7816_tlv::ber::{Tag, Tlv, Value};
use log::{debug, info, trace, warn};
use num_bigint::BigUint;
use rand::rngs::SysRng;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::error;
use std::fmt;
use std::fs::{self};
use std::panic::{self, AssertUnwindSafe};
use std::str;
use std::time::Instant;

pub mod bcdutil;

macro_rules! get_bit {
    ($byte:expr, $bit:expr) => {
        if $byte & (1 << $bit) != 0 {
            true
        } else {
            false
        }
    };
}

macro_rules! set_bit {
    ($byte:expr, $bit:expr, $bit_value:expr) => {
        if $bit_value == true {
            $byte |= 1 << $bit;
        } else {
            $byte &= !(1 << $bit);
        }
    };
}

// Configuration files bundled in the library, used when a configuration is not given
const DEFAULT_SETTINGS: &str = include_str!("config/settings.yaml");
const DEFAULT_EMV_TAGS: &str = include_str!("config/emv_tags.yaml");
const DEFAULT_CONSTANTS: &str = include_str!("config/constants.yaml");
const DEFAULT_SCHEME_CA_PUBLIC_KEYS: &str = include_str!("config/scheme_ca_public_keys_test.yaml");

fn parse_yaml<T: serde::de::DeserializeOwned>(name: &str, yaml: &str) -> Result<T, EmvError> {
    serde_yaml::from_str(yaml)
        .map_err(|err| EmvError::Configuration(format!("Invalid {}: {}", name, err)))
}

/// Why a transaction step could not be completed
#[derive(Debug, Clone, PartialEq)]
pub enum EmvError {
    /// The card answered a command with a status word other than '9000'
    CardStatus { command: String, sw: [u8; 2] },
    /// A card response or card data object is not in the expected format
    InvalidCardData(String),
    /// A data object needed by the step is missing, e.g. the step is done before the step that provides it
    MissingData(String),
    /// Offline data authentication (certificate, signature or cryptogram verification) failed
    Authentication(String),
    /// Exchanging the APDU with the card failed or there is no card interface
    Interface(String),
    /// The terminal configuration is not valid
    Configuration(String),
    /// A callback, e.g. PIN entry or application selection, failed or was cancelled
    Callback(String),
    /// The step panicked, see EmvConnection::guarded
    Internal(String),
}

impl fmt::Display for EmvError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            EmvError::CardStatus { command, sw } => {
                write!(
                    f,
                    "{} failed with status {:02X}{:02X}",
                    command, sw[0], sw[1]
                )
            }
            EmvError::InvalidCardData(msg) => write!(f, "Invalid card data: {}", msg),
            EmvError::MissingData(msg) => write!(f, "Missing data: {}", msg),
            EmvError::Authentication(msg) => write!(f, "Authentication failed: {}", msg),
            EmvError::Interface(msg) => write!(f, "Card interface error: {}", msg),
            EmvError::Configuration(msg) => write!(f, "Configuration error: {}", msg),
            EmvError::Callback(msg) => write!(f, "Callback failed: {}", msg),
            EmvError::Internal(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl error::Error for EmvError {}

impl EmvError {
    fn invalid(msg: impl Into<String>) -> EmvError {
        EmvError::InvalidCardData(msg.into())
    }

    fn missing(msg: impl Into<String>) -> EmvError {
        EmvError::MissingData(msg.into())
    }

    fn authentication(msg: impl Into<String>) -> EmvError {
        EmvError::Authentication(msg.into())
    }
}

/// Logs the error as a warning, the transaction log shows why a step failed
fn warned(err: EmvError) -> EmvError {
    warn!("{}", err);
    err
}

/// Bytes as bits, e.g. "00000000 10000000"
fn format_bits(value: &[u8]) -> String {
    value
        .iter()
        .map(|b| format!("{:08b}", b))
        .collect::<Vec<String>>()
        .join(" ")
}

/// Three digit numeric code (n3) of a two byte BCD value, e.g. a country code '0246' is 246
fn numeric_code(value: &[u8]) -> String {
    let code = hex::encode_upper(value);
    if code.len() == 4 && code.starts_with('0') {
        code[1..].to_string()
    } else {
        code
    }
}

// PCI SSC PAN truncation rules ref. https://d30000001huxdea4.my.salesforce-sites.com/faq/articles/Frequently_Asked_Question/What-are-acceptable-formats-for-truncation-of-primary-account-numbers
pub fn get_truncated_pan(pan: &str) -> String {
    let uncensored_bin_prefix_length = if pan.len() > 15 { 8 } else { 6 };

    let truncated_pan: String = pan
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i >= uncensored_bin_prefix_length && i < pan.len() - 4 {
                '*'
            } else {
                c
            }
        })
        .collect();

    truncated_pan
}

#[derive(Debug, Clone)]
pub struct Track1 {
    pub primary_account_number: String,
    pub last_name: String,
    pub first_name: String,
    pub expiry_year: String,
    pub expiry_month: String,
    pub service_code: String,
    pub discretionary_data: String,
}

impl Track1 {
    pub fn new(track_data: &str) -> Track1 {
        Track1::parse(track_data).unwrap()
    }

    /// Track 1 data, None if it is not in the format
    pub fn parse(track_data: &str) -> Option<Track1> {
        // %B4321432143214321^Mc'Doe/JOHN^2609101123456789012345678901234?
        let re = Regex::new(r"^(%B)?(\d+)\^(.+)?/(.+)?\^(\d{2})(\d{2})(\d{3})(\d+)\??$").unwrap();
        let cap = re.captures(track_data)?;
        let group = |i: usize| cap.get(i).map_or("", |m| m.as_str()).to_string();

        Some(Track1 {
            primary_account_number: group(2),
            last_name: group(3),
            first_name: group(4),
            expiry_year: group(5),
            expiry_month: group(6),
            service_code: group(7),
            discretionary_data: group(8),
        })
    }

    pub fn censor(&mut self) {
        self.primary_account_number = get_truncated_pan(&self.primary_account_number);
        self.last_name = self.last_name.replace(|_c: char| true, "*");
        self.first_name = self.first_name.replace(|_c: char| true, "*");
        self.discretionary_data = self.discretionary_data.replace(|_c: char| true, "*");
    }
}

impl fmt::Display for Track1 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "%B{}^{}/{}^{}{}{}{}?",
            self.primary_account_number,
            self.last_name,
            self.first_name,
            self.expiry_year,
            self.expiry_month,
            self.service_code,
            self.discretionary_data
        )
    }
}

#[derive(Debug, Clone)]
pub struct Track2 {
    pub primary_account_number: String,
    pub expiry_year: String,
    pub expiry_month: String,
    pub service_code: String,
    pub discretionary_data: String,
}

impl Track2 {
    pub fn new(track_data: &str) -> Track2 {
        Track2::parse(track_data).unwrap()
    }

    /// Track 2 data, None if it is not in the format. The discretionary data may be empty (ISO/IEC 7813, EMV Book 3, Annex A
    /// Track 2 Equivalent Data).
    pub fn parse(track_data: &str) -> Option<Track2> {
        // Supports human readable and ICC formats
        // human readable: ;4321432143214321=2612101123456789123?
        // ICC: 4321432143214321D2612101123456789123F

        let re = Regex::new(r"^;?(\d+)(=|D)(\d{2})(\d{2})(\d{3})(\d*)F?\??$").unwrap();
        let cap = re.captures(track_data)?;

        Some(Track2 {
            primary_account_number: cap.get(1).unwrap().as_str().to_string(),
            expiry_year: cap.get(3).unwrap().as_str().to_string(),
            expiry_month: cap.get(4).unwrap().as_str().to_string(),
            service_code: cap.get(5).unwrap().as_str().to_string(),
            discretionary_data: cap.get(6).unwrap().as_str().to_string(),
        })
    }

    pub fn censor(&mut self) {
        self.primary_account_number = get_truncated_pan(&self.primary_account_number);
        self.discretionary_data = self.discretionary_data.replace(|_c: char| true, "*");
    }
}

impl fmt::Display for Track2 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            ";{}={}{}{}{}?",
            self.primary_account_number,
            self.expiry_year,
            self.expiry_month,
            self.service_code,
            self.discretionary_data
        )
    }
}

#[repr(u8)]
#[derive(Deserialize, Serialize, Debug, Copy, Clone, PartialEq, Eq)]
pub enum CryptogramType {
    // bits 6-7 are relevant
    ApplicationAuthenticationCryptogram = 0b0000_0000, // AAC, transaction declined
    AuthorisationRequestCryptogram = 0b1000_0000,      // ARQC, online authorisation requested
    TransactionCertificate = 0b0100_0000,              // TC, transaction approved
}

impl From<CryptogramType> for u8 {
    fn from(orig: CryptogramType) -> Self {
        match orig {
            CryptogramType::ApplicationAuthenticationCryptogram => 0b0000_0000,
            CryptogramType::AuthorisationRequestCryptogram => 0b1000_0000,
            CryptogramType::TransactionCertificate => 0b0100_0000,
        }
    }
}

impl CryptogramType {
    // EMV Book 3, 9.3: responses in hierarchical order, TC being the highest and AAC the lowest
    fn level(self) -> u8 {
        match self {
            CryptogramType::ApplicationAuthenticationCryptogram => 0,
            CryptogramType::AuthorisationRequestCryptogram => 1,
            CryptogramType::TransactionCertificate => 2,
        }
    }
}

impl TryFrom<u8> for CryptogramType {
    type Error = &'static str;

    fn try_from(orig: u8) -> Result<Self, Self::Error> {
        match orig >> 6 << 6 {
            0b0000_0000 => Ok(CryptogramType::ApplicationAuthenticationCryptogram),
            0b1000_0000 => Ok(CryptogramType::AuthorisationRequestCryptogram),
            0b0100_0000 => Ok(CryptogramType::TransactionCertificate),
            _ => Err("Unknown code!"),
        }
    }
}

#[repr(u8)]
#[derive(Debug, Copy, Clone)]
pub enum CvmCode {
    FailCvmProcessing = 0b0000_0000,
    PlaintextPin = 0b0000_0001,
    EncipheredPinOnline = 0b0000_0010,
    PlaintextPinAndSignature = 0b0000_0011,
    EncipheredPinOffline = 0b0000_0100,
    EncipheredPinOfflineAndSignature = 0b0000_0101,
    Signature = 0b0001_1110,
    NoCvm = 0b0001_1111,
}

impl From<CvmCode> for u8 {
    fn from(orig: CvmCode) -> Self {
        match orig {
            CvmCode::FailCvmProcessing => 0b0000_0000,
            CvmCode::PlaintextPin => 0b0000_0001,
            CvmCode::EncipheredPinOnline => 0b0000_0010,
            CvmCode::PlaintextPinAndSignature => 0b0000_0011,
            CvmCode::EncipheredPinOffline => 0b0000_0100,
            CvmCode::EncipheredPinOfflineAndSignature => 0b0000_0101,
            CvmCode::Signature => 0b0001_1110,
            CvmCode::NoCvm => 0b0001_1111,
        }
    }
}

impl TryFrom<u8> for CvmCode {
    type Error = &'static str;

    fn try_from(orig: u8) -> Result<Self, Self::Error> {
        match orig {
            0b0000_0000 => Ok(CvmCode::FailCvmProcessing),
            0b0000_0001 => Ok(CvmCode::PlaintextPin),
            0b0000_0010 => Ok(CvmCode::EncipheredPinOnline),
            0b0000_0011 => Ok(CvmCode::PlaintextPinAndSignature),
            0b0000_0100 => Ok(CvmCode::EncipheredPinOffline),
            0b0000_0101 => Ok(CvmCode::EncipheredPinOfflineAndSignature),
            0b0001_1110 => Ok(CvmCode::Signature),
            0b0001_1111 => Ok(CvmCode::NoCvm),
            _ => Err("Unknown code!"),
        }
    }
}

#[repr(u8)]
#[derive(Debug, Copy, Clone)]
pub enum CvmConditionCode {
    Always = 0x00,
    UnattendedCash = 0x01,
    NotCashNorPurchaseWithCashback = 0x02,
    CvmSupported = 0x03,
    ManualCash = 0x04,
    PurchaseWithCashback = 0x05,
    IccCurrencyUnderX = 0x06,
    IccCurrencyOverX = 0x07,
    IccCurrencyUnderY = 0x08,
    IccCurrencyOverY = 0x09,
}

impl From<CvmConditionCode> for u8 {
    fn from(orig: CvmConditionCode) -> Self {
        match orig {
            CvmConditionCode::Always => 0x00,
            CvmConditionCode::UnattendedCash => 0x01,
            CvmConditionCode::NotCashNorPurchaseWithCashback => 0x02,
            CvmConditionCode::CvmSupported => 0x03,
            CvmConditionCode::ManualCash => 0x04,
            CvmConditionCode::PurchaseWithCashback => 0x05,
            CvmConditionCode::IccCurrencyUnderX => 0x06,
            CvmConditionCode::IccCurrencyOverX => 0x07,
            CvmConditionCode::IccCurrencyUnderY => 0x08,
            CvmConditionCode::IccCurrencyOverY => 0x09,
        }
    }
}

impl TryFrom<u8> for CvmConditionCode {
    type Error = &'static str;

    fn try_from(orig: u8) -> Result<Self, Self::Error> {
        match orig {
            0x00 => Ok(CvmConditionCode::Always),
            0x01 => Ok(CvmConditionCode::UnattendedCash),
            0x02 => Ok(CvmConditionCode::NotCashNorPurchaseWithCashback),
            0x03 => Ok(CvmConditionCode::CvmSupported),
            0x04 => Ok(CvmConditionCode::ManualCash),
            0x05 => Ok(CvmConditionCode::PurchaseWithCashback),
            0x06 => Ok(CvmConditionCode::IccCurrencyUnderX),
            0x07 => Ok(CvmConditionCode::IccCurrencyOverX),
            0x08 => Ok(CvmConditionCode::IccCurrencyUnderY),
            0x09 => Ok(CvmConditionCode::IccCurrencyOverY),
            _ => Err("Unknown condition!"),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct CvmRule {
    pub amount_x: u32,
    pub amount_y: u32,
    pub fail_if_unsuccessful: bool,
    /// CVM code, the code (b6-b1) when the terminal does not recognise it
    pub code: Result<CvmCode, u8>,
    pub condition: CvmConditionCode,
}

impl CvmRule {
    pub fn into_9f34_value(rule: Result<CvmRule, CvmRule>) -> Vec<u8> {
        // EMV Book 4, A4 CVM Results

        let rule_unwrapped = match rule {
            Ok(rule) => rule,
            Err(rule) => rule,
        };

        let mut c: u8 = match rule_unwrapped.code {
            Ok(code) => code.into(),
            Err(code) => code,
        };
        if !rule_unwrapped.fail_if_unsuccessful {
            c += 0b0100_0000;
        }

        let mut value: Vec<u8> = Vec::new();
        value.push(c);
        value.push(rule_unwrapped.condition.into());

        let result: u8 = match rule {
            Ok(rule) => {
                match rule.code {
                    Ok(CvmCode::Signature) => 0x00, // unknown
                    _ => 0x02,                      // successful
                }
            }
            Err(_) => 0x01, // failed
        };

        value.push(result);

        debug!("9F34 {:02X?}: {:?}", value, rule_unwrapped);

        return value;
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Capabilities {
    pub sda: bool,
    pub dda: bool,
    pub cda: bool,
    pub plaintext_pin: bool,
    pub enciphered_pin: bool,
    pub terminal_risk_management: bool,
    pub issuer_authentication: bool,
}

#[derive(Debug)]
pub struct UsageControl {
    pub domestic_cash_transactions: bool,
    pub international_cash_transactions: bool,
    pub domestic_goods: bool,
    pub international_goods: bool,
    pub domestic_services: bool,
    pub international_services: bool,
    pub atms: bool,
    pub terminals_other_than_atms: bool,
    pub domestic_cashback: bool,
    pub international_cashback: bool,
}

impl From<Vec<u8>> for UsageControl {
    // Missing bytes of a short value are zeros
    fn from(data: Vec<u8>) -> Self {
        let b1: u8 = data.get(0).copied().unwrap_or(0);
        let b2: u8 = data.get(1).copied().unwrap_or(0);

        UsageControl {
            domestic_cash_transactions: get_bit!(b1, 7),
            international_cash_transactions: get_bit!(b1, 6),
            domestic_goods: get_bit!(b1, 5),
            international_goods: get_bit!(b1, 4),
            domestic_services: get_bit!(b1, 3),
            international_services: get_bit!(b1, 2),
            atms: get_bit!(b1, 1),
            terminals_other_than_atms: get_bit!(b1, 0),
            domestic_cashback: get_bit!(b2, 7),
            international_cashback: get_bit!(b2, 6),
        }
    }
}

#[derive(Debug)]
pub struct Icc {
    pub capabilities: Capabilities,
    pub usage: UsageControl,
    pub cvm_rules: Vec<CvmRule>,
    pub issuer_pk: Option<RsaPublicKey>,
    pub icc_pk: Option<RsaPublicKey>,
    pub icc_pin_pk: Option<RsaPublicKey>,
    pub data_authentication: Option<Vec<u8>>,
    // Terminal Relay Resistance Entropy || Device Relay Resistance Entropy || Min Time For Processing Relay Resistance APDU ||
    // Max Time For Processing Relay Resistance APDU || Device Estimated Transmission Time For Relay Resistance R-APDU
    pub relay_resistance_data: Option<Vec<u8>>,
}

impl Icc {
    fn new() -> Icc {
        let capabilities = Capabilities {
            sda: false,
            dda: false,
            cda: false,
            plaintext_pin: false,
            enciphered_pin: false,
            terminal_risk_management: false,
            issuer_authentication: false,
        };

        let usage = UsageControl {
            domestic_cash_transactions: false,
            international_cash_transactions: false,
            domestic_goods: false,
            international_goods: false,
            domestic_services: false,
            international_services: false,
            atms: false,
            terminals_other_than_atms: false,
            domestic_cashback: false,
            international_cashback: false,
        };

        Icc {
            capabilities: capabilities,
            usage: usage,
            cvm_rules: Vec::new(),
            issuer_pk: None,
            icc_pk: None,
            icc_pin_pk: None,
            data_authentication: None,
            relay_resistance_data: None,
        }
    }
}

// EMV Contactless Book A, Table 5-4: Terminal Transaction Qualifier (TTQ)
#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub struct TerminalTransactionQualifiers {
    //byte 1
    pub mag_stripe_mode_supported: bool,
    //7bit rfu
    pub emv_mode_supported: bool,
    pub emv_contact_chip_supported: bool,
    pub offline_only_reader: bool,
    pub online_pin_supported: bool,
    pub signature_supported: bool,
    pub offline_data_authentication_for_online_authorizations_supported: bool,

    //byte 2
    pub online_cryptogram_required: bool, // transient value
    pub cvm_required: bool,               // transient value
    pub contact_chip_offline_pin_supported: bool,
    //5-1 bits RFU

    //byte 3
    pub issuer_update_processing_supported: bool,
    pub consumer_device_cvm_supported: bool, //6-1 bits RFU

                                             //byte 4 RFU
}

impl From<TerminalTransactionQualifiers> for Vec<u8> {
    fn from(ttq: TerminalTransactionQualifiers) -> Self {
        // EMV Contactless Book A, Table 5-4: Terminal Transaction Qualifier (TTQ)
        let mut b1: u8 = 0b0000_0000;
        let mut b2: u8 = 0b0000_0000;
        let mut b3: u8 = 0b0000_0000;
        let b4: u8 = 0b0000_0000; //byte 4 RFU

        set_bit!(b1, 7, ttq.mag_stripe_mode_supported);
        //7 bit RFU
        set_bit!(b1, 5, ttq.emv_mode_supported);
        set_bit!(b1, 4, ttq.emv_contact_chip_supported);
        set_bit!(b1, 3, ttq.offline_only_reader);
        set_bit!(b1, 2, ttq.online_pin_supported);
        set_bit!(b1, 1, ttq.signature_supported);
        set_bit!(
            b1,
            0,
            ttq.offline_data_authentication_for_online_authorizations_supported
        );

        set_bit!(b2, 7, ttq.online_cryptogram_required);
        set_bit!(b2, 6, ttq.cvm_required);
        set_bit!(b2, 5, ttq.contact_chip_offline_pin_supported);
        //5-1 bits RFU

        set_bit!(b3, 7, ttq.issuer_update_processing_supported);
        set_bit!(b3, 6, ttq.consumer_device_cvm_supported);
        //6-1 bits RFU

        let mut value: Vec<u8> = Vec::new();
        value.push(b1);
        value.push(b2);
        value.push(b3);
        value.push(b4);

        value
    }
}

// EMV Contactless Book C-4 Kernel 4 Specification, Table 4-4: Enhanced Contactless Reader Capabilities (tag 9F6E)
#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub struct C4EnhancedContactlessReaderCapabilities {
    //byte 1 - Terminal Capabilities
    pub contact_mode_supported: bool,
    pub contactless_mag_stripe_mode_supported: bool,
    pub contactless_emv_full_online_mode_not_supported: bool, // full online mode is a legacy feature and is no longer supported
    pub contactless_emv_partial_online_mode_supported: bool,
    pub contactless_mode_supported: bool,
    pub try_another_interface_after_decline: bool,
    //2-1 bits RFU

    //byte 2 - Terminal CVM Capabilities
    pub mobile_cvm_supported: bool,
    pub online_pin_supported: bool,
    pub signature: bool,
    pub plaintext_offline_pin: bool,
    //4-1 bits RFU

    //byte 3 - Transaction Capabilities
    pub reader_is_offline_only: bool,
    pub cvm_required: bool,
    //6-1 bits RFU

    //byte 4 - Transaction Capabilities
    pub terminal_exempt_from_no_cvm_checks: bool,
    pub delayed_authorisation_terminal: bool,
    pub transit_terminal: bool,
    //5-4 bits RFU
    pub c4_kernel_version: u8, // bits 3-1
}

impl From<C4EnhancedContactlessReaderCapabilities> for Vec<u8> {
    fn from(tag_9f6e: C4EnhancedContactlessReaderCapabilities) -> Self {
        let mut b1: u8 = 0b0000_0000;
        let mut b2: u8 = 0b0000_0000;
        let mut b3: u8 = 0b0000_0000;
        let mut b4: u8;

        set_bit!(b1, 7, tag_9f6e.contact_mode_supported);
        set_bit!(b1, 6, tag_9f6e.contactless_mag_stripe_mode_supported);
        set_bit!(
            b1,
            5,
            tag_9f6e.contactless_emv_full_online_mode_not_supported
        );
        set_bit!(
            b1,
            4,
            tag_9f6e.contactless_emv_partial_online_mode_supported
        );
        set_bit!(b1, 3, tag_9f6e.contactless_mode_supported);
        set_bit!(b1, 2, tag_9f6e.try_another_interface_after_decline);
        // 1-0 RFU

        set_bit!(b2, 7, tag_9f6e.mobile_cvm_supported);
        set_bit!(b2, 6, tag_9f6e.online_pin_supported);
        set_bit!(b2, 5, tag_9f6e.signature);
        set_bit!(b2, 4, tag_9f6e.plaintext_offline_pin);
        // 3-0 RFU

        set_bit!(b3, 7, tag_9f6e.reader_is_offline_only);
        set_bit!(b3, 6, tag_9f6e.cvm_required);
        //5-0 RFU

        b4 = tag_9f6e.c4_kernel_version; // bits 2-0
        set_bit!(b4, 7, tag_9f6e.terminal_exempt_from_no_cvm_checks);
        set_bit!(b4, 6, tag_9f6e.delayed_authorisation_terminal);
        set_bit!(b4, 5, tag_9f6e.transit_terminal);
        set_bit!(b4, 4, false); // RFU
        set_bit!(b4, 3, false); // RFU

        let mut value: Vec<u8> = Vec::new();
        value.push(b1);
        value.push(b2);
        value.push(b3);
        value.push(b4);

        value
    }
}

// TODO: support EMV Book 4, A2 Terminal Capabilities (a.k.a. 9F33)
#[derive(Serialize, Deserialize)]
pub struct Terminal {
    pub use_random: bool,
    pub capabilities: Capabilities,
    pub tvr: TerminalVerificationResults,
    pub tsi: TransactionStatusInformation,
    pub cryptogram_type: CryptogramType,
    pub cryptogram_type_arqc: CryptogramType,
    // Authorisation Response Codes (tag '8A', an 2) of the authorisation response that approve the transaction online. EMV Book 4,
    // A6 does not define the value of 'Online approved', it is acquirer specific. Without the list the second GENERATE AC requests
    // cryptogram_type_arqc.
    #[serde(default)]
    pub online_approved_authorisation_response_codes: Option<Vec<String>>,
    // Terminal list of AIDs (hex) selected one by one when the card has no PSE / PPSE or it lists no applications, EMV Book 1,
    // 12.3.3 Using a List of AIDs. A card application whose DF name begins with a listed AID matches partially.
    #[serde(default)]
    pub application_identifiers: Vec<String>,
    pub terminal_transaction_qualifiers: TerminalTransactionQualifiers,
    pub c4_enhanced_contactless_reader_capabilities: C4EnhancedContactlessReaderCapabilities,
    #[serde(default)]
    pub protocol_deviations: ProtocolDeviations,
}

// Terminal behaviour that deviates from the specifications, for example to see what a card does with a non-compliant terminal.
// Deviations are disabled by default, except ignoring certificate expiry so that test cards with expired certificates can be used.
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct ProtocolDeviations {
    // Accept a GENERATE AC response with a higher cryptogram type than requested, EMV Book 3, 9.3 treats it as an ICC logic error
    #[serde(default)]
    pub accept_higher_cryptogram_type: bool,
    // Send EXTERNAL AUTHENTICATE although the AIP does not indicate issuer authentication support (EMV Book 3, 10.9)
    #[serde(default)]
    pub external_authenticate_without_aip_support: bool,
    // Offline PIN verification with VERIFY in a Kernel 2 transaction, EMV Contactless Book C-2 has no VERIFY command
    #[serde(default)]
    pub kernel_2_offline_pin: bool,
    // Accept an expired Issuer or ICC Public Key Certificate, EMV Book 2, 6.3 and 6.4 fail offline data authentication with it.
    // The expiry is logged. A certificate expiry date that is not a valid date still fails.
    #[serde(default = "default_ignore_certificate_expiry")]
    pub ignore_certificate_expiry: bool,
}

fn default_ignore_certificate_expiry() -> bool {
    true
}

impl Default for ProtocolDeviations {
    fn default() -> ProtocolDeviations {
        ProtocolDeviations {
            accept_higher_cryptogram_type: false,
            external_authenticate_without_aip_support: false,
            kernel_2_offline_pin: false,
            ignore_certificate_expiry: default_ignore_certificate_expiry(),
        }
    }
}

// EMV Contactless Book C-2, Terminal Verification Results (TVR) byte 5 bits 2-1: Relay resistance performed
#[derive(Serialize, Deserialize, Debug, Copy, Clone, Default, PartialEq)]
pub enum RelayResistancePerformed {
    #[default]
    NotSupported = 0b00,
    NotPerformed = 0b01,
    Performed = 0b10,
}

impl From<u8> for RelayResistancePerformed {
    fn from(bits: u8) -> Self {
        match bits & 0b11 {
            0b01 => RelayResistancePerformed::NotPerformed,
            0b10 => RelayResistancePerformed::Performed,
            _ => RelayResistancePerformed::NotSupported,
        }
    }
}

// EMV Book 3, C5 Terminal Verification Results (TVR)
#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub struct TerminalVerificationResults {
    //TVR byte 1
    pub offline_data_authentication_was_not_performed: bool,
    pub sda_failed: bool,
    pub icc_data_missing: bool,
    pub card_appears_on_terminal_exception_file: bool,
    pub dda_failed: bool,
    pub cda_failed: bool,
    //RFU
    //RFU

    // TVR byte 2
    pub icc_and_terminal_have_different_application_versions: bool,
    pub expired_application: bool,
    pub application_not_yet_effective: bool,
    pub requested_service_not_allowed_for_card_product: bool,
    pub new_card: bool,
    //RFU
    //RFU
    //RFU

    //TVR byte 3
    pub cardholder_verification_was_not_successful: bool,
    pub unrecognised_cvm: bool,
    pub pin_try_limit_exceeded: bool,
    pub pin_entry_required_and_pin_pad_not_present_or_not_working: bool,
    pub pin_entry_required_pin_pad_present_but_pin_was_not_entered: bool,
    pub online_pin_entered: bool,
    //RFU
    //RFU

    //TVR byte 4
    pub transaction_exceeds_floor_limit: bool,
    pub lower_consecutive_offline_limit_exceeded: bool,
    pub upper_consecutive_offline_limit_exceeded: bool,
    pub transaction_selected_randomly_for_online_processing: bool,
    pub merchant_forced_transaction_online: bool,
    //RFU
    //RFU
    //RFU

    //TVR byte 5
    pub default_tdol_used: bool,
    pub issuer_authentication_failed: bool,
    pub script_processing_failed_before_final_generate_ac: bool,
    pub script_processing_failed_after_final_generate_ac: bool,
    // EMV Contactless Book C-2 Kernel 2, RFU in EMV Book 3
    #[serde(default)]
    pub relay_resistance_threshold_exceeded: bool,
    #[serde(default)]
    pub relay_resistance_time_limits_exceeded: bool,
    #[serde(default)]
    pub relay_resistance_performed: RelayResistancePerformed,
}

impl TerminalVerificationResults {
    pub fn action_code_matches(
        tvr: &TerminalVerificationResults,
        iac: &TerminalVerificationResults,
        tac: &TerminalVerificationResults,
    ) -> bool {
        if tvr.offline_data_authentication_was_not_performed
            && (iac.offline_data_authentication_was_not_performed
                || tac.offline_data_authentication_was_not_performed)
        {
            return true;
        }
        if tvr.sda_failed && (iac.sda_failed || tac.sda_failed) {
            return true;
        }
        if tvr.icc_data_missing && (iac.icc_data_missing || tac.icc_data_missing) {
            return true;
        }
        if tvr.card_appears_on_terminal_exception_file
            && (iac.card_appears_on_terminal_exception_file
                || tac.card_appears_on_terminal_exception_file)
        {
            return true;
        }
        if tvr.dda_failed && (iac.dda_failed || tac.dda_failed) {
            return true;
        }
        if tvr.cda_failed && (iac.cda_failed || tac.cda_failed) {
            return true;
        }
        if tvr.icc_and_terminal_have_different_application_versions
            && (iac.icc_and_terminal_have_different_application_versions
                || tac.icc_and_terminal_have_different_application_versions)
        {
            return true;
        }
        if tvr.expired_application && (iac.expired_application || tac.expired_application) {
            return true;
        }
        if tvr.application_not_yet_effective
            && (iac.application_not_yet_effective || tac.application_not_yet_effective)
        {
            return true;
        }
        if tvr.requested_service_not_allowed_for_card_product
            && (iac.requested_service_not_allowed_for_card_product
                || tac.requested_service_not_allowed_for_card_product)
        {
            return true;
        }
        if tvr.new_card && (iac.new_card || tac.new_card) {
            return true;
        }
        if tvr.cardholder_verification_was_not_successful
            && (iac.cardholder_verification_was_not_successful
                || tac.cardholder_verification_was_not_successful)
        {
            return true;
        }
        if tvr.unrecognised_cvm && (iac.unrecognised_cvm || tac.unrecognised_cvm) {
            return true;
        }
        if tvr.pin_try_limit_exceeded && (iac.pin_try_limit_exceeded || tac.pin_try_limit_exceeded)
        {
            return true;
        }
        if tvr.pin_entry_required_and_pin_pad_not_present_or_not_working
            && (iac.pin_entry_required_and_pin_pad_not_present_or_not_working
                || tac.pin_entry_required_and_pin_pad_not_present_or_not_working)
        {
            return true;
        }
        if tvr.pin_entry_required_pin_pad_present_but_pin_was_not_entered
            && (iac.pin_entry_required_pin_pad_present_but_pin_was_not_entered
                || tac.pin_entry_required_pin_pad_present_but_pin_was_not_entered)
        {
            return true;
        }
        if tvr.online_pin_entered && (iac.online_pin_entered || tac.online_pin_entered) {
            return true;
        }
        if tvr.transaction_exceeds_floor_limit
            && (iac.transaction_exceeds_floor_limit || tac.transaction_exceeds_floor_limit)
        {
            return true;
        }
        if tvr.lower_consecutive_offline_limit_exceeded
            && (iac.lower_consecutive_offline_limit_exceeded
                || tac.lower_consecutive_offline_limit_exceeded)
        {
            return true;
        }
        if tvr.upper_consecutive_offline_limit_exceeded
            && (iac.upper_consecutive_offline_limit_exceeded
                || tac.upper_consecutive_offline_limit_exceeded)
        {
            return true;
        }
        if tvr.transaction_selected_randomly_for_online_processing
            && (iac.transaction_selected_randomly_for_online_processing
                || tac.transaction_selected_randomly_for_online_processing)
        {
            return true;
        }
        if tvr.merchant_forced_transaction_online
            && (iac.merchant_forced_transaction_online || tac.merchant_forced_transaction_online)
        {
            return true;
        }
        if tvr.default_tdol_used && (iac.default_tdol_used || tac.default_tdol_used) {
            return true;
        }
        if tvr.issuer_authentication_failed
            && (iac.issuer_authentication_failed || tac.issuer_authentication_failed)
        {
            return true;
        }
        if tvr.script_processing_failed_before_final_generate_ac
            && (iac.script_processing_failed_before_final_generate_ac
                || tac.script_processing_failed_before_final_generate_ac)
        {
            return true;
        }
        if tvr.script_processing_failed_after_final_generate_ac
            && (iac.script_processing_failed_after_final_generate_ac
                || tac.script_processing_failed_after_final_generate_ac)
        {
            return true;
        }
        if tvr.relay_resistance_threshold_exceeded
            && (iac.relay_resistance_threshold_exceeded || tac.relay_resistance_threshold_exceeded)
        {
            return true;
        }
        if tvr.relay_resistance_time_limits_exceeded
            && (iac.relay_resistance_time_limits_exceeded
                || tac.relay_resistance_time_limits_exceeded)
        {
            return true;
        }
        if tvr.relay_resistance_performed as u8
            & (iac.relay_resistance_performed as u8 | tac.relay_resistance_performed as u8)
            != 0
        {
            return true;
        }

        false
    }
}

impl From<Vec<u8>> for TerminalVerificationResults {
    // Missing bytes of a short value, e.g. an Issuer Action Code of the card, are zeros
    fn from(data: Vec<u8>) -> Self {
        let byte = |i: usize| data.get(i).copied().unwrap_or(0);
        let b1: u8 = byte(0);
        let b2: u8 = byte(1);
        let b3: u8 = byte(2);
        let b4: u8 = byte(3);
        let b5: u8 = byte(4);

        TerminalVerificationResults {
            offline_data_authentication_was_not_performed: get_bit!(b1, 7),
            sda_failed: get_bit!(b1, 6),
            icc_data_missing: get_bit!(b1, 5),
            card_appears_on_terminal_exception_file: get_bit!(b1, 4),
            dda_failed: get_bit!(b1, 3),
            cda_failed: get_bit!(b1, 2),
            icc_and_terminal_have_different_application_versions: get_bit!(b2, 7),
            expired_application: get_bit!(b2, 6),
            application_not_yet_effective: get_bit!(b2, 5),
            requested_service_not_allowed_for_card_product: get_bit!(b2, 4),
            new_card: get_bit!(b2, 3),
            cardholder_verification_was_not_successful: get_bit!(b3, 7),
            unrecognised_cvm: get_bit!(b3, 6),
            pin_try_limit_exceeded: get_bit!(b3, 5),
            pin_entry_required_and_pin_pad_not_present_or_not_working: get_bit!(b3, 4),
            pin_entry_required_pin_pad_present_but_pin_was_not_entered: get_bit!(b3, 3),
            online_pin_entered: get_bit!(b3, 2),
            transaction_exceeds_floor_limit: get_bit!(b4, 7),
            lower_consecutive_offline_limit_exceeded: get_bit!(b4, 6),
            upper_consecutive_offline_limit_exceeded: get_bit!(b4, 5),
            transaction_selected_randomly_for_online_processing: get_bit!(b4, 4),
            merchant_forced_transaction_online: get_bit!(b4, 3),
            default_tdol_used: get_bit!(b5, 7),
            issuer_authentication_failed: get_bit!(b5, 6),
            script_processing_failed_before_final_generate_ac: get_bit!(b5, 5),
            script_processing_failed_after_final_generate_ac: get_bit!(b5, 4),
            relay_resistance_threshold_exceeded: get_bit!(b5, 3),
            relay_resistance_time_limits_exceeded: get_bit!(b5, 2),
            relay_resistance_performed: RelayResistancePerformed::from(b5),
        }
    }
}

impl From<TerminalVerificationResults> for Vec<u8> {
    fn from(tvr: TerminalVerificationResults) -> Self {
        let mut b1: u8 = 0b0000_0000;
        let mut b2: u8 = 0b0000_0000;
        let mut b3: u8 = 0b0000_0000;
        let mut b4: u8 = 0b0000_0000;
        let mut b5: u8 = 0b0000_0000;

        set_bit!(b1, 7, tvr.offline_data_authentication_was_not_performed);
        set_bit!(b1, 6, tvr.sda_failed);
        set_bit!(b1, 5, tvr.icc_data_missing);
        set_bit!(b1, 4, tvr.card_appears_on_terminal_exception_file);
        set_bit!(b1, 3, tvr.dda_failed);
        set_bit!(b1, 2, tvr.cda_failed);

        set_bit!(
            b2,
            7,
            tvr.icc_and_terminal_have_different_application_versions
        );
        set_bit!(b2, 6, tvr.expired_application);
        set_bit!(b2, 5, tvr.application_not_yet_effective);
        set_bit!(b2, 4, tvr.requested_service_not_allowed_for_card_product);
        set_bit!(b2, 3, tvr.new_card);

        set_bit!(b3, 7, tvr.cardholder_verification_was_not_successful);
        set_bit!(b3, 6, tvr.unrecognised_cvm);
        set_bit!(b3, 5, tvr.pin_try_limit_exceeded);
        set_bit!(
            b3,
            4,
            tvr.pin_entry_required_and_pin_pad_not_present_or_not_working
        );
        set_bit!(
            b3,
            3,
            tvr.pin_entry_required_pin_pad_present_but_pin_was_not_entered
        );
        set_bit!(b3, 2, tvr.online_pin_entered);

        set_bit!(b4, 7, tvr.transaction_exceeds_floor_limit);
        set_bit!(b4, 6, tvr.lower_consecutive_offline_limit_exceeded);
        set_bit!(b4, 5, tvr.upper_consecutive_offline_limit_exceeded);
        set_bit!(
            b4,
            4,
            tvr.transaction_selected_randomly_for_online_processing
        );
        set_bit!(b4, 3, tvr.merchant_forced_transaction_online);

        set_bit!(b5, 7, tvr.default_tdol_used);
        set_bit!(b5, 6, tvr.issuer_authentication_failed);
        set_bit!(b5, 5, tvr.script_processing_failed_before_final_generate_ac);
        set_bit!(b5, 4, tvr.script_processing_failed_after_final_generate_ac);
        set_bit!(b5, 3, tvr.relay_resistance_threshold_exceeded);
        set_bit!(b5, 2, tvr.relay_resistance_time_limits_exceeded);
        b5 |= tvr.relay_resistance_performed as u8;

        let mut output: Vec<u8> = Vec::new();
        output.push(b1);
        output.push(b2);
        output.push(b3);
        output.push(b4);
        output.push(b5);

        output
    }
}

// EMV Book 3, C6 Transaction Status Information (TSI)
#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub struct TransactionStatusInformation {
    //TSI byte 1
    pub offline_data_authentication_was_performed: bool,
    pub cardholder_verification_was_performed: bool,
    pub card_risk_management_was_performed: bool,
    pub issuer_authentication_was_performed: bool,
    pub terminal_risk_management_was_performed: bool,
    pub script_processing_was_performed: bool, //RFU
                                               //RFU

                                               //TSI byte 2 - RFU
}

impl From<TransactionStatusInformation> for Vec<u8> {
    fn from(tsi: TransactionStatusInformation) -> Self {
        let mut b1: u8 = 0b0000_0000;
        let b2: u8 = 0b0000_0000;

        set_bit!(b1, 7, tsi.offline_data_authentication_was_performed);
        set_bit!(b1, 6, tsi.cardholder_verification_was_performed);
        set_bit!(b1, 5, tsi.card_risk_management_was_performed);
        set_bit!(b1, 4, tsi.issuer_authentication_was_performed);
        set_bit!(b1, 3, tsi.terminal_risk_management_was_performed);
        set_bit!(b1, 2, tsi.script_processing_was_performed);

        let mut output: Vec<u8> = Vec::new();
        output.push(b1);
        output.push(b2);

        output
    }
}

/// Configuration files read by EmvConnection::new, relative to the working directory. The bundled configuration is used when
/// a file is not found.
#[derive(Serialize, Deserialize)]
pub struct ConfigurationFiles {
    pub emv_tags: String,
    pub scheme_ca_public_keys: String,
    pub constants: String,
}

impl Default for ConfigurationFiles {
    fn default() -> ConfigurationFiles {
        ConfigurationFiles {
            emv_tags: "emv_tags.yaml".to_string(),
            scheme_ca_public_keys: "scheme_ca_public_keys_test.yaml".to_string(),
            constants: "constants.yaml".to_string(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Settings {
    pub censor_sensitive_fields: bool,
    #[serde(default)]
    pub configuration_files: ConfigurationFiles,
    /// Terminal configuration, its TVR and TSI are the initial values of a transaction (TransactionState)
    pub terminal: Terminal,
    /// Terminal data objects (tag hex => value hex) set by process_settings
    #[serde(default)]
    pub default_tags: HashMap<String, String>,
}

/// Configuration of EmvConnection::from_configuration as YAML documents, the bundled configuration is used for a None
#[derive(Default, Clone)]
pub struct ConfigurationData {
    pub settings: Option<String>,
    pub emv_tags: Option<String>,
    pub constants: Option<String>,
    pub scheme_ca_public_keys: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Constants {
    pub numeric_country_codes: HashMap<String, String>,
    pub numeric_currency_codes: HashMap<String, String>,
    pub apdu_status_codes: HashMap<String, String>,
}

/// Card reader that exchanges an APDU with the card, the response is the response data and the status word SW1 SW2
pub trait ApduInterface: Send {
    fn send_apdu(&self, apdu: &[u8]) -> Result<Vec<u8>, EmvError>;
}

/// Hook to every APDU exchanged with the card, also the GET RESPONSE and Le correction commands that the terminal sends by
/// itself. A hook can change what the terminal sends or what it processes, e.g. to test how a card handles a malformed command.
pub trait ApduHook: Send {
    /// Command to send instead of the command, None to send it as is
    fn on_command(&self, _command: &[u8]) -> Option<Vec<u8>> {
        None
    }

    /// Response (response data and SW1 SW2) to process instead of the response of the card, None to process it as is
    fn on_response(&self, _command: &[u8], _response: &[u8]) -> Option<Vec<u8>> {
        None
    }

    /// Command sent and response processed, after the changes of on_command and on_response
    fn on_exchange(&self, _command: &[u8], _response: &[u8]) {}
}

/// Response of a command, after GET RESPONSE and Le corrections
#[derive(Debug, Clone, PartialEq)]
pub struct ApduResponse {
    /// Status word SW1 SW2 of the last response
    pub sw: [u8; 2],
    pub data: Vec<u8>,
}

impl ApduResponse {
    pub fn is_success(&self) -> bool {
        self.sw == [0x90, 0x00]
    }
}

/// APDU exchanged with the card, the response is the response data and SW1 SW2
#[derive(Debug, Clone, PartialEq)]
pub struct ApduExchange {
    pub command: Vec<u8>,
    pub response: Vec<u8>,
}

/// Results of the transaction so far. The card data and terminal data objects of the transaction are EmvConnection::tags and
/// the card capabilities and keys EmvConnection::icc.
#[derive(Debug, Clone)]
pub struct TransactionState {
    pub tvr: TerminalVerificationResults,
    pub tsi: TransactionStatusInformation,
    /// APDUs exchanged with the card
    pub exchanges: Vec<ApduExchange>,
}

impl TransactionState {
    fn new(terminal: &Terminal) -> TransactionState {
        TransactionState {
            tvr: terminal.tvr,
            tsi: terminal.tsi,
            exchanges: Vec::new(),
        }
    }
}

/// Entry of the Application File Locator (AFL), EMV Book 3, 10.2
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AflEntry {
    pub short_file_identifier: u8,
    pub first_record: u8,
    pub last_record: u8,
    /// Number of records, from the first record, that are in offline data authentication
    pub data_authentication_records: u8,
}

pub struct DataObject {
    pub emv_tag: EmvTag,
    pub length: usize,
}

impl DataObject {
    pub fn new(emv_connection: &EmvConnection, tag_name: &str, length: usize) -> DataObject {
        DataObject {
            emv_tag: emv_connection
                .get_emv_tag(tag_name)
                .unwrap_or(&EmvTag::new(tag_name))
                .clone(),
            length: length,
        }
    }
}

pub struct DataObjectList {
    data_objects: Vec<DataObject>,
}

impl fmt::Display for DataObjectList {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for data_object in &self.data_objects {
            if let Err(e) = write!(
                f,
                "{} - {} ({}b); ",
                data_object.emv_tag.tag, data_object.emv_tag.name, data_object.length
            ) {
                return Err(e);
            }
        }

        Ok(())
    }
}

// EMV Book 3, 5.4 Rules for Using a Data Object List (DOL)
impl DataObjectList {
    // EMV has some tags that don't conform to ISO/IEC 7816
    fn is_non_conforming_one_byte_tag(tag: u8) -> bool {
        if tag == 0x95 {
            return true;
        }

        false
    }

    fn new() -> DataObjectList {
        DataObjectList {
            data_objects: Vec::new(),
        }
    }

    fn push(&mut self, data_object: DataObject) {
        self.data_objects.push(data_object);
    }

    pub fn has_tag(&self, tag_name: &str) -> bool {
        for data_object in &self.data_objects {
            if data_object.emv_tag.tag == tag_name {
                return true;
            }
        }

        false
    }

    pub fn process_data_object_list(
        emv_connection: &EmvConnection,
        tag_list: &[u8],
    ) -> Result<DataObjectList, EmvError> {
        let mut dol: DataObjectList = DataObjectList::new();

        // FIXME: This parsing is complete BS
        // - Check if "Tag List" and "Data Object List" are same or different types
        // - Parse TLV tags appropriately...
        if tag_list.len() < 2 {
            if let Some(tag) = tag_list.first() {
                let tag_name = hex::encode_upper([*tag]);
                dol.push(DataObject::new(emv_connection, &tag_name, 0));
            }
        } else {
            let truncated = || {
                warned(EmvError::invalid(format!(
                    "Truncated data object list {:02X?}",
                    tag_list
                )))
            };

            let mut i = 0;
            loop {
                let tag_value_length: usize;

                let mut tag_name = hex::encode_upper(&tag_list[i..i + 1]);

                if Tag::try_from(tag_name.as_str()).is_ok()
                    || DataObjectList::is_non_conforming_one_byte_tag(tag_list[i])
                {
                    tag_value_length = *tag_list.get(i + 1).ok_or_else(truncated)? as usize;
                    i += 2;
                } else {
                    tag_name = hex::encode_upper(tag_list.get(i..i + 2).ok_or_else(truncated)?);
                    if Tag::try_from(tag_name.as_str()).is_ok() {
                        tag_value_length = *tag_list.get(i + 2).ok_or_else(truncated)? as usize;
                        i += 3;
                    } else {
                        return Err(warned(EmvError::invalid(format!(
                            "Incorrect tag {:?} in data object list",
                            tag_name
                        ))));
                    }
                }

                dol.push(DataObject::new(emv_connection, &tag_name, tag_value_length));

                if i >= tag_list.len() {
                    break;
                }
            }
        }

        Ok(dol)
    }

    /// EMV Book 3, 5.4: a value longer than its DOL entry is truncated keeping the leftmost bytes, the rightmost bytes of numeric
    /// (n) data. A shorter value is padded, numeric (n) data with leading hexadecimal zeros, compressed numeric (cn) data with
    /// trailing hexadecimal 'F's and other data with trailing hexadecimal zeros.
    fn fit_value(value: &[u8], length: usize, format: Option<FieldFormat>) -> Vec<u8> {
        let numeric = matches!(
            format,
            Some(FieldFormat::Numeric)
                | Some(FieldFormat::NumericCountryCode)
                | Some(FieldFormat::NumericCurrencyCode)
                | Some(FieldFormat::Date)
                | Some(FieldFormat::Time)
                | Some(FieldFormat::ServiceCodeIso7813)
        );

        if value.len() >= length {
            if numeric {
                return value[value.len() - length..].to_vec();
            }
            return value[..length].to_vec();
        }

        let padding = length - value.len();
        if numeric {
            let mut result = vec![0x00; padding];
            result.extend_from_slice(value);
            return result;
        }

        let mut result = value.to_vec();
        let padding_byte = match format {
            Some(FieldFormat::CompressedNumeric) => 0xFF,
            _ => 0x00,
        };
        result.resize(length, padding_byte);
        result
    }

    pub fn get_tag_list_tag_values(&self, emv_connection: &EmvConnection) -> Vec<u8> {
        let mut output: Vec<u8> = Vec::new();
        for data_object in &self.data_objects {
            let default_value: Vec<u8> = vec![0; data_object.length];
            let value = match emv_connection.get_tag_value(&data_object.emv_tag.tag) {
                Some(value) => value,
                None => {
                    debug!(
                        "tag {:?} has no value, filling with zeros",
                        data_object.emv_tag.tag
                    );

                    &default_value
                }
            };

            if data_object.length > 0 && value.len() != data_object.length {
                debug!(
                    "tag {:?} value length {:02X} does not match tag list value length {:02X}",
                    data_object.emv_tag.tag,
                    value.len(),
                    data_object.length
                );
            }

            if data_object.length == 0 {
                // at least 9F4A does not provide length information
                output.extend_from_slice(&value[..]);
            } else {
                output.extend_from_slice(&DataObjectList::fit_value(
                    &value[..],
                    data_object.length,
                    data_object.emv_tag.format,
                ));
            }
        }

        output
    }
}

/// Terminal side of an EMV transaction. The transaction is done step by step with the handle_* and other public step methods,
/// in the order and with the parameters chosen by the caller, e.g. the purchase sequence of the terminalsimulator. Each step
/// works on the transaction state: the data objects (tags), the card capabilities and keys (icc) and the TVR and TSI (state).
pub struct EmvConnection {
    pub tags: HashMap<String, Vec<u8>>,
    pub interface: Option<Box<dyn ApduInterface>>,
    /// Hook to the APDUs exchanged with the card
    pub apdu_hook: Option<Box<dyn ApduHook>>,
    pub contactless: bool,
    // Kernel Identifier of the selected contactless application
    pub kernel_identifier: Option<Vec<u8>>,
    emv_tags: HashMap<String, EmvTag>,
    constants: Constants,
    scheme_ca_public_keys: HashMap<String, CertificateAuthority>,
    pub settings: Settings,
    pub icc: Icc,
    pub state: TransactionState,
    /// PIN entry of handle_card_verification_methods
    pub pin_callback: Option<PinCallback>,
    /// Application selection of select_payment_application, the first application without it
    pub pse_application_select_callback: Option<ApplicationSelectCallback>,
}

/// PIN entry, the PIN is ASCII digits
pub type PinCallback = Box<dyn Fn() -> Result<String, EmvError> + Send>;

/// Selection of an application of the candidate applications
pub type ApplicationSelectCallback =
    Box<dyn Fn(&[EmvApplication]) -> Result<EmvApplication, EmvError> + Send>;

impl EmvConnection {
    /// Terminal with the settings file and the configuration files it refers to. The bundled configuration is used for a file
    /// that is not found.
    pub fn new(settings_file: &str) -> Result<EmvConnection, EmvError> {
        let settings = fs::read_to_string(settings_file).ok();
        let configuration_files: ConfigurationFiles = match &settings {
            Some(settings) => parse_yaml::<Settings>(settings_file, settings)?.configuration_files,
            None => ConfigurationFiles::default(),
        };

        EmvConnection::from_configuration(ConfigurationData {
            settings: settings,
            emv_tags: fs::read_to_string(&configuration_files.emv_tags).ok(),
            constants: fs::read_to_string(&configuration_files.constants).ok(),
            scheme_ca_public_keys: fs::read_to_string(&configuration_files.scheme_ca_public_keys)
                .ok(),
        })
    }

    /// Terminal with the configuration given as YAML documents, e.g. from the resources of an application
    pub fn from_configuration(configuration: ConfigurationData) -> Result<EmvConnection, EmvError> {
        let settings: Settings = parse_yaml(
            "settings",
            configuration
                .settings
                .as_deref()
                .unwrap_or(DEFAULT_SETTINGS),
        )?;
        let emv_tags = parse_yaml(
            "EMV tags",
            configuration
                .emv_tags
                .as_deref()
                .unwrap_or(DEFAULT_EMV_TAGS),
        )?;
        let constants = parse_yaml(
            "constants",
            configuration
                .constants
                .as_deref()
                .unwrap_or(DEFAULT_CONSTANTS),
        )?;
        let scheme_ca_public_keys = parse_yaml(
            "scheme CA public keys",
            configuration
                .scheme_ca_public_keys
                .as_deref()
                .unwrap_or(DEFAULT_SCHEME_CA_PUBLIC_KEYS),
        )?;

        Ok(EmvConnection {
            tags: HashMap::new(),
            emv_tags: emv_tags,
            constants: constants,
            scheme_ca_public_keys: scheme_ca_public_keys,
            state: TransactionState::new(&settings.terminal),
            settings: settings,
            icc: Icc::new(),
            interface: None,
            apdu_hook: None,
            contactless: false,
            kernel_identifier: None,
            pin_callback: None,
            pse_application_select_callback: None,
        })
    }

    /// Starts a new transaction: clears the data objects, the card data and the APDUs, and sets the TVR and TSI to their initial
    /// values of the settings
    pub fn reset_transaction(&mut self) {
        self.tags.clear();
        self.icc = Icc::new();
        self.kernel_identifier = None;
        self.state = TransactionState::new(&self.settings.terminal);
    }

    /// Runs a step so that a panic of it is an error, e.g. in a step of a binding where a panic would abort the process
    pub fn guarded<T>(
        &mut self,
        step: impl FnOnce(&mut EmvConnection) -> Result<T, EmvError>,
    ) -> Result<T, EmvError> {
        match panic::catch_unwind(AssertUnwindSafe(|| step(self))) {
            Ok(result) => result,
            Err(cause) => {
                let message = cause
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| cause.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "panic".to_string());
                Err(warned(EmvError::Internal(message)))
            }
        }
    }

    pub fn print_tags(&self) {
        let mut i = 0;
        for (key, value) in &self.tags {
            i += 1;
            let emv_tag = self.emv_tags.get(key);
            info!(
                "{:02}. tag: {} - {}",
                i,
                key,
                emv_tag.unwrap_or(&EmvTag::new(&key.clone())).name
            );
            self.print_tag_value(&emv_tag, value, 0);
        }
    }

    pub fn get_emv_tag(&self, tag_name: &str) -> Option<&EmvTag> {
        self.emv_tags.get(tag_name)
    }

    pub fn get_tag_value(&self, tag_name: &str) -> Option<&Vec<u8>> {
        self.tags.get(tag_name)
    }

    fn require_tag(&self, tag_name: &str) -> Result<&Vec<u8>, EmvError> {
        self.get_tag_value(tag_name).ok_or_else(|| {
            warned(EmvError::missing(format!(
                "{} ({})",
                tag_name,
                self.get_emv_tag(tag_name)
                    .map_or("Unknown tag", |tag| tag.name.as_str())
            )))
        })
    }

    pub fn add_tag(&mut self, tag_name: &str, value: Vec<u8>) {
        let old_tag = self.tags.get(tag_name);
        if old_tag.is_some() {
            if self.settings.censor_sensitive_fields {
                trace!(
                    "Overriding tag {:?}. Old size: {}, new size: {}",
                    tag_name,
                    old_tag.unwrap().len(),
                    value.len()
                );
            } else {
                trace!(
                    "Overriding tag {:?} from {:02X?} to {:02X?}",
                    tag_name,
                    old_tag.unwrap(),
                    value
                );
            }
        }

        self.tags.insert(tag_name.to_string(), value);
    }

    /// Sets a data object of the transaction, e.g. terminal data of a step that the caller wants to vary. The tag is hex.
    pub fn set_tag(&mut self, tag_name: &str, value: Vec<u8>) -> Result<(), EmvError> {
        let tag_name = tag_name.to_uppercase();
        if Tag::try_from(tag_name.as_str()).is_err() {
            return Err(EmvError::Configuration(format!(
                "Invalid tag {:?}",
                tag_name
            )));
        }
        self.process_tag_as_tlv(&tag_name, value);
        Ok(())
    }

    /// Removes a data object of the transaction
    pub fn remove_tag(&mut self, tag_name: &str) -> Option<Vec<u8>> {
        self.tags.remove(&tag_name.to_uppercase())
    }

    pub fn process_tag_as_tlv(&mut self, tag_name: &str, value: Vec<u8>) {
        let Ok(tag) = hex::decode(tag_name) else {
            warn!("Invalid tag {:?}", tag_name);
            return;
        };

        let mut tlv: Vec<u8> = tag;
        // BER-TLV length, ISO/IEC 7816-4
        let length = value.len();
        if length >= 0x100 {
            tlv.push(0x82);
            tlv.push((length >> 8) as u8);
        } else if length >= 0x80 {
            tlv.push(0x81);
        }
        tlv.push(length as u8);
        tlv.extend_from_slice(&value[..]);

        self.process_tlv(&tlv[..], 1);
    }

    fn send_apdu_select(&mut self, aid: &[u8]) -> Result<ApduResponse, EmvError> {
        self.send_apdu_select_occurrence(aid, false)
    }

    fn send_apdu_select_occurrence(
        &mut self,
        aid: &[u8],
        next_occurrence: bool,
    ) -> Result<ApduResponse, EmvError> {
        //ref. EMV Book 1, 11.3.2 Command message
        self.tags.clear();

        let apdu_command_select = b"\x00\xA4";
        let p1_reference_control_parameter: u8 = 0b0000_0100; // "Select by name"
        let p2_selection_options: u8 = if next_occurrence {
            0b0000_0010 // "Next occurrence"
        } else {
            0b0000_0000 // "First or only occurrence"
        };

        let mut select_command = apdu_command_select.to_vec();
        select_command.push(p1_reference_control_parameter);
        select_command.push(p2_selection_options);
        select_command.push(aid.len() as u8); // lc
        select_command.extend_from_slice(aid); // data
        select_command.push(0x00); // le

        self.send_apdu(&select_command)
    }

    fn get_apdu_response_localization(&self, apdu_status: &[u8]) -> String {
        let response_status_code = hex::encode_upper(apdu_status);

        let response_localization: String;
        if let Some(response_description) =
            self.constants.apdu_status_codes.get(&response_status_code)
        {
            response_localization = format!("{} - {}", response_status_code, response_description);
        } else if let Some(response_description) = response_status_code
            .get(0..2)
            .and_then(|sw1| self.constants.apdu_status_codes.get(sw1))
        {
            response_localization = format!("{} - {}", response_status_code, response_description);
        } else {
            response_localization = format!("{}", response_status_code);
        }

        response_localization
    }

    /// Exchanges one APDU with the card through the APDU hook
    fn exchange_apdu(&mut self, apdu: &[u8]) -> Result<Vec<u8>, EmvError> {
        let command = match &self.apdu_hook {
            Some(hook) => hook.on_command(apdu).unwrap_or_else(|| apdu.to_vec()),
            None => apdu.to_vec(),
        };
        if command[..] != apdu[..] {
            debug!(
                "APDU hook changed the command to:\n{}",
                HexViewBuilder::new(&command).finish()
            );
        }

        let Some(interface) = &self.interface else {
            return Err(warned(EmvError::Interface("No card interface".to_string())));
        };
        let mut response = interface.send_apdu(&command).map_err(warned)?;

        if let Some(hook) = &self.apdu_hook {
            if let Some(hook_response) = hook.on_response(&command, &response) {
                debug!(
                    "APDU hook changed the response to:\n{}",
                    HexViewBuilder::new(&hook_response).finish()
                );
                response = hook_response;
            }
            hook.on_exchange(&command, &response);
        }

        self.state.exchanges.push(ApduExchange {
            command: command,
            response: response.clone(),
        });

        Ok(response)
    }

    /// Sends a command to the card, also the GET RESPONSE and Le corrected commands when the card asks for them, and processes
    /// the data objects of the response. The response is the response to the last command sent.
    pub fn send_apdu(&mut self, apdu: &[u8]) -> Result<ApduResponse, EmvError> {
        let mut response_data: Vec<u8> = Vec::new();
        let mut response_trailer: [u8; 2];

        let mut apdu_command = apdu.to_vec();

        // A card that keeps on asking for GET RESPONSE or another Le would otherwise be served forever
        const MAX_COMMANDS: usize = 32;
        let mut commands = 0;

        loop {
            commands += 1;
            if commands > MAX_COMMANDS {
                return Err(warned(EmvError::invalid(format!(
                    "Card asked for more than {} commands to respond",
                    MAX_COMMANDS
                ))));
            }

            // Send an APDU command.
            if self.settings.censor_sensitive_fields {
                debug!(
                    "Sending APDU: {:02X?}... ({} bytes)",
                    &apdu_command[0..apdu_command.len().min(5)],
                    apdu_command.len()
                );
            } else {
                debug!(
                    "Sending APDU:\n{}",
                    HexViewBuilder::new(&apdu_command).finish()
                );
            }

            let apdu_response = self.exchange_apdu(&apdu_command)?;
            if apdu_response.len() < 2 {
                return Err(warned(EmvError::invalid(format!(
                    "Response without a status word {:02X?}",
                    apdu_response
                ))));
            }

            response_data.extend_from_slice(&apdu_response[0..apdu_response.len() - 2]);

            // response codes: https://www.eftlab.com/knowledge-base/complete-list-of-apdu-responses/
            response_trailer = [
                apdu_response[apdu_response.len() - 2],
                apdu_response[apdu_response.len() - 1],
            ];

            debug!(
                "APDU response status: {}",
                self.get_apdu_response_localization(&response_trailer[..])
            );

            // Automatically query more data, if available from the ICC
            const SW1_BYTES_AVAILABLE: u8 = 0x61;
            const SW1_WRONG_LENGTH: u8 = 0x6C;

            if response_trailer[0] == SW1_BYTES_AVAILABLE {
                trace!(
                    "APDU response({} bytes):\n{}",
                    response_data.len(),
                    HexViewBuilder::new(&response_data).finish()
                );

                let mut available_data_length = response_trailer[1];

                // NOTE: EMV doesn't have a use case where ICC would pass bigger records than what is passable with a single ADPU response
                if available_data_length == 0x00 {
                    // there are more than 255 bytes available, query the maximum
                    available_data_length = 0xFF;
                }

                apdu_command = b"\x00\xC0\x00\x00".to_vec();
                apdu_command.push(available_data_length);
            } else if response_trailer[0] == SW1_WRONG_LENGTH {
                trace!(
                    "APDU response({} bytes):\n{}",
                    response_data.len(),
                    HexViewBuilder::new(&response_data).finish()
                );

                let available_data_length = response_trailer[1];
                if available_data_length == 0x00 || apdu.len() < 5 {
                    return Err(warned(EmvError::invalid(format!(
                        "Wrong length response {:02X?} to a command that can not be corrected",
                        response_trailer
                    ))));
                }

                // Le is the last byte of the command
                apdu_command = apdu.to_vec();
                let apdu_command_length = apdu_command.len();
                apdu_command[apdu_command_length - 1] = available_data_length;
            } else {
                break;
            }
        }

        if self.settings.censor_sensitive_fields {
            debug!("APDU response({} bytes)", response_data.len());
        } else {
            debug!(
                "APDU response({} bytes):\n{}",
                response_data.len(),
                HexViewBuilder::new(&response_data).finish()
            );
        }

        if !response_data.is_empty() {
            debug!("APDU TLV parse:");

            self.process_tlv(&response_data[..], 0);
        }

        Ok(ApduResponse {
            sw: response_trailer,
            data: response_data,
        })
    }

    /// Error of a command that the card did not complete successfully
    fn card_status_error(command: &str, response: &ApduResponse) -> EmvError {
        warned(EmvError::CardStatus {
            command: command.to_string(),
            sw: response.sw,
        })
    }

    fn print_tag(&self, emv_tag: &EmvTag, level: u8) {
        let mut padding = String::with_capacity(level as usize);
        for _ in 0..level {
            padding.push(' ');
        }
        debug!("{}-{}: {}", padding, emv_tag.tag, emv_tag.name);
    }
    fn print_tag_value(&self, emv_tag: &Option<&EmvTag>, v: &Vec<u8>, level: u8) {
        let mut padding = String::with_capacity(level as usize);
        for _ in 0..level {
            padding.push(' ');
        }

        let mut value: String = String::from_utf8_lossy(&v).replace(
            |c: char| !(c.is_ascii_alphanumeric() || c.is_ascii_punctuation()),
            ".",
        );
        if let Some(tag) = emv_tag {
            match tag.format {
                Some(FieldFormat::Numeric) | Some(FieldFormat::CompressedNumeric) => {
                    value = format!("{:02X?}", v)
                        .replace(|c: char| !(c.is_ascii_alphanumeric()), "")
                        .trim_start_matches('0')
                        .to_string();
                }
                Some(FieldFormat::Alphanumeric) | Some(FieldFormat::AlphanumericSpecial) => {
                    value = String::from_utf8_lossy(&v).to_string();
                }
                Some(FieldFormat::TerminalVerificationResults) => {
                    let tvr: TerminalVerificationResults = v.to_vec().into();
                    value = format!("{} => {:#?}", format_bits(v), tvr);
                }
                Some(FieldFormat::ApplicationUsageControl) => {
                    let auc: UsageControl = v.to_vec().into();
                    value = format!("{} => {:#?}", format_bits(v), auc);
                }
                Some(FieldFormat::KeyCertificate) => {
                    value = format!("{} bit key", v.len() * 8);
                }
                Some(FieldFormat::ServiceCodeIso7813) if v.len() >= 2 => {
                    let position_1_interchange: String = match v[0] {
                        1 => "International".to_string(),
                        2 => "International (prefer ICC)".to_string(),
                        5 => "National".to_string(),
                        6 => "National (prefer ICC)".to_string(),
                        7 => "Private".to_string(),
                        9 => "Test".to_string(),
                        _ => format!("N/A {}", v[0]),
                    };

                    let position_2: u8 = v[1] >> 4;
                    let position_2_authorization_processing: String = match position_2 {
                        0 => "Normal".to_string(),
                        2 => "By Issuer".to_string(),
                        4 => "By Issuer (unless bileteral agreement exists)".to_string(),
                        _ => format!("N/A {}", position_2),
                    };

                    let position_3: u8 = v[1] & 0b0000_1111;
                    let position_3_allowed_services: String = match position_3 {
                        0 => "No restrictions (PIN required)".to_string(),
                        1 => "No restrictions".to_string(),
                        2 => "Goods and services only".to_string(),
                        3 => "ATM only (PIN required)".to_string(),
                        4 => "Cash only".to_string(),
                        5 => "Goods and services only (PIN required)".to_string(),
                        6 => "No restrictions (PIN prompt if PED)".to_string(),
                        7 => "Goods and services only (PIN prompt if PED)".to_string(),
                        _ => format!("N/A {}", position_3),
                    };

                    value = format!(
                        "{}{:02X} - {}, {}, {}",
                        v[0],
                        v[1],
                        position_1_interchange,
                        position_2_authorization_processing,
                        position_3_allowed_services
                    );
                }
                Some(FieldFormat::NumericCountryCode) => {
                    let numeric_country_code = numeric_code(&v[..]);
                    value = format!(
                        "{} - {}",
                        numeric_country_code,
                        self.constants
                            .numeric_country_codes
                            .get(&numeric_country_code)
                            .map_or("Unknown", String::as_str)
                    );
                }
                Some(FieldFormat::NumericCurrencyCode) => {
                    let numeric_currency_code = numeric_code(&v[..]);
                    value = format!(
                        "{} - {}",
                        numeric_currency_code,
                        self.constants
                            .numeric_currency_codes
                            .get(&numeric_currency_code)
                            .map_or("Unknown", String::as_str)
                    );
                }
                Some(FieldFormat::DataObjectList) => {
                    if let Ok(dol) = DataObjectList::process_data_object_list(self, &v[..]) {
                        value = format!("{}", dol);
                    }
                }
                Some(FieldFormat::Track2) => {
                    let track2_raw: String = format!("{:02X?}", v)
                        .replace(|c: char| !(c.is_ascii_alphanumeric()), "")
                        .to_string();
                    value = match Track2::parse(&track2_raw) {
                        Some(track2) => format!("{}", track2),
                        None => track2_raw,
                    };
                }
                Some(FieldFormat::Date) if v.len() == 3 => {
                    value =
                        format!("{:02X?}", v).replace(|c: char| !(c.is_ascii_alphanumeric()), "");
                    let yy = &value[0..2];
                    let mm = &value[2..4];
                    let dd = &value[4..6];

                    // FIXME: date format does not take into consideration pre 2000s dates
                    value = format!("20{}-{}-{}", yy, mm, dd);
                }
                Some(FieldFormat::Time) if v.len() == 3 => {
                    value =
                        format!("{:02X?}", v).replace(|c: char| !(c.is_ascii_alphanumeric()), "");
                    let hh = &value[0..2];
                    let mm = &value[2..4];
                    let ss = &value[4..6];

                    value = format!("{}:{}:{}", hh, mm, ss);
                }
                _ => { /* NOP */ }
            }

            // Special rules here
            match tag.tag.as_str() {
                "9F27" => {
                    if let Some(Ok(icc_cryptogram_type)) =
                        v.first().map(|cid| CryptogramType::try_from(*cid))
                    {
                        value = format!("{:?}", icc_cryptogram_type);
                    }
                }
                _ => { /* NOP */ }
            }
        }

        if self.settings.censor_sensitive_fields {
            if let Some(tag) = emv_tag {
                match tag.sensitivity {
                    Some(FieldSensitivity::PrimaryAccountNumber) => {
                        let truncated_pan = get_truncated_pan(&value);
                        debug!("{}-data: {}", padding, truncated_pan);
                    }
                    Some(FieldSensitivity::Track2) => {
                        value = match Track2::parse(&String::from_utf8_lossy(&v).to_string()) {
                            Some(mut track2) => {
                                track2.censor();
                                format!("{}", track2)
                            }
                            None => value.replace(|_c: char| true, "*"),
                        };

                        debug!("{}-data: {}", padding, value);
                    }
                    Some(
                        FieldSensitivity::SensitiveAuthenticationData | FieldSensitivity::Sensitive,
                    ) => {
                        debug!("{}-data: censored {} bytes", padding, v.len());
                    }
                    Some(FieldSensitivity::PersonallyIdentifiableInformation) => {
                        // allowing punctuation is primarily to see cardholder name which is separated by '/'
                        debug!(
                            "{}-data: {}",
                            padding,
                            value.replace(
                                |c: char| !(c.is_ascii_whitespace() || c.is_ascii_punctuation()),
                                "*"
                            )
                        );
                    }
                    _ => {
                        debug!("{}-data: {:02X?} = {}", padding, v, value);
                    }
                }
            } else {
                debug!("{}-data: {:02X?} = {}", padding, v, value);
            }
        } else {
            debug!("{}-data: {:02X?} = {}", padding, v, value);
        }
    }

    pub fn process_tlv(&mut self, buf: &[u8], level: u8) {
        let mut read_buffer = buf;

        loop {
            let (tlv_data, leftover_buffer) = Tlv::parse(read_buffer);

            let tlv_data: Tlv = match tlv_data {
                Ok(tlv) => tlv,
                Err(err) => {
                    if leftover_buffer.len() > 0 {
                        trace!(
                            "Could not parse as TLV! error:{:?}, data: {:02X?}",
                            err,
                            read_buffer
                        );
                    }

                    break;
                }
            };

            read_buffer = leftover_buffer;

            let tag_name = hex::encode_upper(tlv_data.tag().to_bytes());

            let emv_tag: Option<&EmvTag> = match self.emv_tags.get(tag_name.as_str()) {
                Some(emv_tag) => {
                    self.print_tag(&emv_tag, level);
                    Some(emv_tag)
                }
                _ => {
                    let unknown_tag = EmvTag::new(&tag_name.clone());
                    self.print_tag(&unknown_tag, level);
                    None
                }
            };

            match tlv_data.value() {
                Value::Constructed(v) => {
                    for tlv_tag in v {
                        self.process_tlv(&tlv_tag.to_vec(), level + 1);
                    }
                }
                Value::Primitive(v) => {
                    self.print_tag_value(&emv_tag, v, level);
                    self.add_tag(&tag_name, v.to_vec());
                }
            };

            if leftover_buffer.len() == 0 {
                break;
            }
        }
    }

    /// Initiate Application Processing, EMV Book 3, 10.1: GET PROCESSING OPTIONS, the relay resistance protocol of a
    /// contactless transaction, reading the application data and processing the card capabilities of it
    pub fn handle_get_processing_options(&mut self) -> Result<(), EmvError> {
        self.get_processing_options()?;

        // ref. EMV Contactless Book C-2, 3.10 Relay Resistance Protocol is performed before reading the records
        if self.contactless {
            self.handle_relay_resistance_protocol()?;
        }

        self.read_application_data()?;
        self.process_application_data()?;

        Ok(())
    }

    /// PDOL Related Data, the values of the data objects of the PDOL (EMV Book 3, 5.4), empty without the PDOL
    pub fn pdol_data(&self) -> Result<Vec<u8>, EmvError> {
        match self.get_tag_value("9F38") {
            Some(tag_9f38_pdol) => Ok(DataObjectList::process_data_object_list(
                self,
                &tag_9f38_pdol[..],
            )?
            .get_tag_list_tag_values(self)),
            None => Ok(Vec::new()),
        }
    }

    /// GET PROCESSING OPTIONS with the PDOL Related Data of the terminal data objects
    pub fn get_processing_options(&mut self) -> Result<ApduResponse, EmvError> {
        let pdol_data = self.pdol_data()?;
        self.send_get_processing_options(&pdol_data)
    }

    /// GET PROCESSING OPTIONS with the given PDOL Related Data (EMV Book 3, 6.5.8). The AIP and the AFL of the response are
    /// stored as data objects '82' and '94'.
    pub fn send_get_processing_options(
        &mut self,
        pdol_data: &[u8],
    ) -> Result<ApduResponse, EmvError> {
        debug!("GET PROCESSING OPTIONS:");

        // Command Template '83' of the PDOL Related Data
        let mut command_data = vec![0x83];
        if pdol_data.len() >= 0x80 {
            command_data.push(0x81);
        }
        command_data.push(pdol_data.len() as u8);
        command_data.extend_from_slice(pdol_data);
        if command_data.len() > 0xFF {
            return Err(warned(EmvError::Configuration(format!(
                "PDOL Related Data is too long, {} bytes",
                pdol_data.len()
            ))));
        }

        let mut get_processing_options_command = b"\x80\xA8\x00\x00".to_vec();
        get_processing_options_command.push(command_data.len() as u8); // lc
        get_processing_options_command.extend_from_slice(&command_data[..]);
        get_processing_options_command.push(0x00); // le

        let response = self.send_apdu(&get_processing_options_command)?;
        if !response.is_success() {
            return Err(EmvConnection::card_status_error(
                "GET PROCESSING OPTIONS",
                &response,
            ));
        }

        // ref. EMV Book 3, 6.5.8.4: Format 1 is AIP || AFL in tag '80', Format 2 includes the AIP and the AFL in tag '77'. If any
        // mandatory data element is missing, the terminal shall terminate the transaction.
        let response_data = &response.data;
        match response_data.first() {
            Some(0x80) if response_data.len() >= 4 => {
                self.process_tag_as_tlv("82", response_data[2..4].to_vec());
                self.process_tag_as_tlv("94", response_data[4..].to_vec());
            }
            Some(0x77) => {}
            _ => {
                return Err(warned(EmvError::invalid(
                    "Unrecognized GET PROCESSING OPTIONS response",
                )));
            }
        }

        match self.get_tag_value("82") {
            Some(aip) if aip.len() == 2 => {}
            Some(_) => {
                return Err(warned(EmvError::invalid(
                    "Invalid Application Interchange Profile (AIP)",
                )));
            }
            None => {
                return Err(warned(EmvError::missing(
                    "Application Interchange Profile (AIP)",
                )));
            }
        }

        Ok(response)
    }

    /// Entries of the Application File Locator (AFL), none without the AFL
    pub fn afl_entries(&self) -> Result<Vec<AflEntry>, EmvError> {
        // AFL is not in a contactless GET PROCESSING OPTIONS response when the card has no records for the terminal to read
        let Some(tag_94_afl) = self.get_tag_value("94") else {
            debug!("No Application File Locator (AFL), no records to read");
            return Ok(Vec::new());
        };

        // AFL entries are 4 bytes each (EMV Book 3, 10.2)
        if tag_94_afl.len() % 4 != 0 {
            return Err(warned(EmvError::invalid(
                "Invalid Application File Locator (AFL)",
            )));
        }

        Ok(tag_94_afl
            .chunks(4)
            .map(|entry| AflEntry {
                short_file_identifier: entry[0] >> 3,
                first_record: entry[1],
                last_record: entry[2],
                data_authentication_records: entry[3],
            })
            .collect())
    }

    /// Read Application Data, EMV Book 3, 10.2: the records of all AFL entries
    pub fn read_application_data(&mut self) -> Result<(), EmvError> {
        debug!("Read card Application File Locator (AFL) information:");

        self.icc.data_authentication = Some(Vec::new());
        for entry in self.afl_entries()? {
            self.read_afl_entry(&entry)?;
        }

        if let Some(data_authentication) = &self.icc.data_authentication {
            if self.settings.censor_sensitive_fields {
                debug!(
                    "AFL data authentication: {} bytes",
                    data_authentication.len()
                );
            } else {
                debug!(
                    "AFL data authentication:\n{}",
                    HexViewBuilder::new(data_authentication).finish()
                );
            }
        }

        Ok(())
    }

    /// Reads the records of an AFL entry. The records in offline data authentication are added to the static data to be
    /// authenticated (EMV Book 3, 10.3).
    pub fn read_afl_entry(&mut self, entry: &AflEntry) -> Result<(), EmvError> {
        let short_file_identifier = entry.short_file_identifier;
        let mut data_authentication_records = entry.data_authentication_records;

        for record_index in entry.first_record..=entry.last_record {
            let Some(data) = self.read_record(short_file_identifier, record_index)? else {
                continue;
            };
            if data.first() != Some(&0x70) {
                return Err(warned(EmvError::invalid(format!(
                    "Record {} of SFI {} is not a record template '70'",
                    record_index, short_file_identifier
                ))));
            }

            // Add data authentication input
            // ref EMV Book 3, 10.3 Offline Data Authentication
            if data_authentication_records > 0 {
                data_authentication_records -= 1;

                let mut record_data_authentication: Vec<u8> = Vec::new();
                if short_file_identifier <= 10 {
                    match parse_tlv(&data[..]).map(|tlv| tlv.value().clone()) {
                        Some(Value::Constructed(tag_70_tags)) => {
                            for tag in tag_70_tags {
                                record_data_authentication.extend(tag.to_vec());
                            }
                        }
                        _ => {
                            return Err(warned(EmvError::invalid(format!(
                                "Could not parse record {} of SFI {}",
                                record_index, short_file_identifier
                            ))));
                        }
                    }
                } else {
                    record_data_authentication.extend_from_slice(&data[..]);
                }

                let data_authentication = self.icc.data_authentication.get_or_insert_with(Vec::new);
                data_authentication.extend(record_data_authentication);

                if self.settings.censor_sensitive_fields {
                    trace!("Data authentication building: short_file_identifier:{}, data_authentication_records:{}, record_index:{}/{}, data:{} bytes", short_file_identifier, data_authentication_records, record_index, entry.last_record, data_authentication.len());
                } else {
                    trace!("Data authentication building: short_file_identifier:{}, data_authentication_records:{}, record_index:{}/{}, data:{:02X?}", short_file_identifier, data_authentication_records, record_index, entry.last_record, data_authentication);
                }
            }
        }

        Ok(())
    }

    /// Card capabilities of the AIP, the CVM List and the Application Usage Control
    pub fn process_application_data(&mut self) -> Result<(), EmvError> {
        let tag_82_aip = self.require_tag("82")?.clone();
        let Some(&auc_b1) = tag_82_aip.first() else {
            return Err(warned(EmvError::invalid(
                "Invalid Application Interchange Profile (AIP)",
            )));
        };

        // bit 7 = RFU
        self.icc.capabilities.sda = get_bit!(auc_b1, 6);
        self.icc.capabilities.dda = get_bit!(auc_b1, 5);
        // Cardholder verification is supported. Without the CVM List the terminal terminates cardholder verification (EMV Book 3, 10.5).
        let tag_8e_cvm_list = match self.get_tag_value("8E") {
            Some(cvm_list) if get_bit!(auc_b1, 4) && cvm_list.len() >= 8 => Some(cvm_list.clone()),
            Some(_) if get_bit!(auc_b1, 4) => {
                warn!("Invalid CVM List");
                None
            }
            None if get_bit!(auc_b1, 4) => {
                warn!("Cardholder verification is supported but the CVM List is missing");
                None
            }
            _ => None,
        };
        self.icc.cvm_rules = match tag_8e_cvm_list {
            Some(tag_8e_cvm_list) => parse_cvm_list(&tag_8e_cvm_list)?,
            None => Vec::new(),
        };
        self.icc.capabilities.terminal_risk_management = get_bit!(auc_b1, 3);
        // Issuer Authentication using the EXTERNAL AUTHENTICATE command is supported
        self.icc.capabilities.issuer_authentication = get_bit!(auc_b1, 2);
        // bit 1 = RFU
        self.icc.capabilities.cda = get_bit!(auc_b1, 0);

        if let Some(tag_9f07_application_usage_control) = self.get_tag_value("9F07") {
            self.icc.usage = tag_9f07_application_usage_control.to_vec().into();
        }

        debug!("{:?}", self.icc);

        // 5 - 0 bits are RFU

        Ok(())
    }

    /// Relay Resistance Protocol (EMV Contactless Book C-2, 3.10 and 5.3) when the ICC supports it in AIP byte 2 bit 1.
    /// The Unpredictable Number is used as the Terminal Relay Resistance Entropy. 'Relay resistance time limits exceeded' is
    /// set in TVR when the measured processing time less the Device Estimated Transmission Time exceeds the Max Time.
    /// C-2 retries, grace periods and accuracy threshold checks are not implemented.
    pub fn handle_relay_resistance_protocol(&mut self) -> Result<(), EmvError> {
        self.icc.relay_resistance_data = None;

        let tag_82_aip = self.require_tag("82")?;
        if tag_82_aip.len() < 2 || !get_bit!(tag_82_aip[1], 0) {
            self.state.tvr.relay_resistance_performed = RelayResistancePerformed::NotPerformed;
            return Ok(());
        }

        self.exchange_relay_resistance_data()
    }

    /// EXCHANGE RELAY RESISTANCE DATA, also when the AIP does not indicate support for it
    pub fn exchange_relay_resistance_data(&mut self) -> Result<(), EmvError> {
        debug!("EXCHANGE RELAY RESISTANCE DATA:");

        let terminal_relay_resistance_entropy = self.require_tag("9F37")?.clone();

        let mut exchange_relay_resistance_data_command = b"\x80\xEA\x00\x00".to_vec();
        exchange_relay_resistance_data_command.push(terminal_relay_resistance_entropy.len() as u8);
        exchange_relay_resistance_data_command
            .extend_from_slice(&terminal_relay_resistance_entropy[..]);
        exchange_relay_resistance_data_command.push(0x00);

        let start = Instant::now();
        let response = self.send_apdu(&exchange_relay_resistance_data_command)?;
        let elapsed = start.elapsed();

        if !response.is_success() {
            return Err(EmvConnection::card_status_error(
                "EXCHANGE RELAY RESISTANCE DATA",
                &response,
            ));
        }

        // Response Message Template Format 1: Device Relay Resistance Entropy (4) || Min Time (2) || Max Time (2) ||
        // Device Estimated Transmission Time For Relay Resistance R-APDU (2)
        let response_data = &response.data;
        if response_data.len() != 12 || response_data[0] != 0x80 || response_data[1] != 0x0A {
            return Err(warned(EmvError::invalid(
                "Unrecognized relay resistance data response",
            )));
        }

        let max_time = u16::from_be_bytes([response_data[8], response_data[9]]) as u128;
        let device_estimated_transmission_time =
            u16::from_be_bytes([response_data[10], response_data[11]]) as u128;

        // Times are in units of hundreds of microseconds
        let measured_processing_time =
            (elapsed.as_micros() / 100).saturating_sub(device_estimated_transmission_time);
        if measured_processing_time > max_time {
            warn!(
                "Relay resistance time limits exceeded: {} > {} (x 100 us)",
                measured_processing_time, max_time
            );
            self.state.tvr.relay_resistance_time_limits_exceeded = true;
        } else {
            debug!(
                "Relay resistance processing time: {} <= {} (x 100 us)",
                measured_processing_time, max_time
            );
        }

        let mut relay_resistance_data = terminal_relay_resistance_entropy;
        relay_resistance_data.extend_from_slice(&response_data[2..]);
        self.icc.relay_resistance_data = Some(relay_resistance_data);
        self.state.tvr.relay_resistance_performed = RelayResistancePerformed::Performed;

        Ok(())
    }

    /// PIN block of a VERIFY command, EMV Book 3, 6.5.12: control field 2, PIN length, PIN and 'F' filler. A PIN is 4-12 digits,
    /// other lengths that fit in the PIN block are sent as is to see how the card handles them.
    fn pin_block(ascii_pin: &[u8]) -> Result<Vec<u8>, EmvError> {
        if ascii_pin.len() > 14 {
            return Err(EmvError::Callback(format!(
                "PIN length {} does not fit in the PIN block",
                ascii_pin.len()
            )));
        }
        let pin_bcd_cn = bcdutil::ascii_to_bcd_cn(ascii_pin, 7)
            .map_err(|_| EmvError::Callback("PIN is not digits".to_string()))?;

        let mut pin_block = vec![0b0010_0000 + ascii_pin.len() as u8]; // control + PIN length
        pin_block.extend_from_slice(&pin_bcd_cn[..]);
        Ok(pin_block)
    }

    pub fn handle_verify_plaintext_pin(&mut self, ascii_pin: &[u8]) -> Result<(), EmvError> {
        debug!("Verify plaintext PIN:");

        let pin_block = EmvConnection::pin_block(ascii_pin)?;

        let apdu_command_verify = b"\x00\x20\x00";
        let mut verify_command = apdu_command_verify.to_vec();
        let p2_pin_type_qualifier = 0b1000_0000;
        verify_command.push(p2_pin_type_qualifier);
        verify_command.push(pin_block.len() as u8); // data length
        verify_command.extend_from_slice(&pin_block[..]);

        let response = self.send_apdu(&verify_command)?;
        if !response.is_success() {
            //Incorrect PIN = 63, C4
            return Err(EmvConnection::card_status_error("VERIFY", &response));
        }

        info!("Pin OK");
        Ok(())
    }

    fn fill_random(&self, data: &mut [u8]) {
        if self.settings.terminal.use_random {
            let mut rng =
                ChaCha20Rng::try_from_rng(&mut SysRng).expect("system random number generator");
            rng.fill_bytes(data);
        }
    }

    pub fn handle_verify_enciphered_pin(&mut self, ascii_pin: &[u8]) -> Result<(), EmvError> {
        debug!("Verify enciphered PIN:");

        // EMV Book 2, 7.1: the ICC PIN Encipherment Public Key, or the ICC Public Key, must be retrieved to encipher the PIN.
        // Without it the CVM is unsuccessful.
        let Some(icc_pin_pk) = self.icc.icc_pin_pk.clone() else {
            return Err(warned(EmvError::missing(
                "ICC PIN Encipherment public key, can't encipher the PIN",
            )));
        };

        let pin_block = EmvConnection::pin_block(ascii_pin)?;

        // EMV Book 2, 7.1 Keys and Certificates, 7.2 PIN Encipherment and Verification: '7F' || PIN block (8) || ICC Unpredictable
        // Number (8) || random padding
        let key_byte_size = icc_pin_pk.get_key_byte_size();
        if key_byte_size < 17 {
            return Err(warned(EmvError::invalid(
                "ICC PIN Encipherment public key is too short",
            )));
        }
        let mut random_padding = vec![0u8; key_byte_size - 17];
        self.fill_random(&mut random_padding[..]);

        let icc_unpredictable_number = self.handle_get_challenge()?;
        if icc_unpredictable_number.len() != 8 {
            return Err(warned(EmvError::invalid(format!(
                "ICC Unpredictable Number of GET CHALLENGE is {} bytes",
                icc_unpredictable_number.len()
            ))));
        }

        let mut plaintext_data = Vec::new();
        plaintext_data.push(0x7F);
        plaintext_data.extend_from_slice(&pin_block[..]);
        plaintext_data.extend_from_slice(&icc_unpredictable_number[..]);
        plaintext_data.extend_from_slice(&random_padding[..]);

        let ciphered_pin_data = icc_pin_pk.public_encrypt(&plaintext_data[..])?;

        let apdu_command_verify = b"\x00\x20\x00";
        let mut verify_command = apdu_command_verify.to_vec();
        let p2_pin_type_qualifier = 0b1000_1000;
        verify_command.push(p2_pin_type_qualifier);
        verify_command.push(ciphered_pin_data.len() as u8);
        verify_command.extend_from_slice(&ciphered_pin_data[..]);

        let response = self.send_apdu(&verify_command)?;
        if !response.is_success() {
            //Incorrect PIN = 63, C4
            return Err(EmvConnection::card_status_error("VERIFY", &response));
        }

        info!("Pin OK");
        Ok(())
    }

    /// Values of the data objects of a DOL of the card
    fn dol_data(&self, dol_tag: &str) -> Result<Vec<u8>, EmvError> {
        let dol = self.require_tag(dol_tag)?;
        Ok(DataObjectList::process_data_object_list(self, &dol[..])?.get_tag_list_tag_values(self))
    }

    fn handle_application_cryptogram_card_authentication(
        &mut self,
        generate_ac_response: &[u8],
        cdol_tag: &str,
    ) -> Result<(), EmvError> {
        //ref. EMV Book 2, 6.6.2 Dynamic Signature Verification

        debug!("Perform Application Cryptogram Data Authentication (CDA):");

        let tag_9f37_unpredictable_number = self.require_tag("9F37")?.clone();

        let icc_dynamic_data =
            self.validate_signed_dynamic_application_data(&tag_9f37_unpredictable_number[..])?;
        let field = |start: usize, length: usize| {
            icc_dynamic_data.get(start..start + length).ok_or_else(|| {
                warned(EmvError::authentication(
                    "ICC Dynamic Data of CDA is too short",
                ))
            })
        };

        // ICC Dynamic Number length || ICC Dynamic Number || CID || Application Cryptogram || Transaction Data Hash Code, EMV Book
        // 2, Table 19
        let mut i = 0;
        let icc_dynamic_number_length = field(i, 1)?[0] as usize;
        i += 1;
        let _icc_dynamic_number = field(i, icc_dynamic_number_length)?;
        i += icc_dynamic_number_length;
        let cryptogram_information_data = field(i, 1)?.to_vec();
        i += 1;
        let tag_9f26_application_cryptogram = field(i, 8)?.to_vec();
        i += 8;
        let transaction_data_hash_code = field(i, 20)?.to_vec();
        i += 20;

        // ref. EMV Contactless Book C-2, Table 6.8 ICC Dynamic Data includes the relay resistance data when RRP was performed
        if let Some(relay_resistance_data) = &self.icc.relay_resistance_data {
            let icc_relay_resistance_data =
                icc_dynamic_data.get(i..i + relay_resistance_data.len());
            if icc_relay_resistance_data != Some(&relay_resistance_data[..]) {
                return Err(warned(EmvError::authentication(format!(
                    "Relay resistance data mismatch in CDA! Exchanged:{:02X?}, ICC Dynamic Data:{:02X?}",
                    relay_resistance_data, icc_relay_resistance_data
                ))));
            }
        }

        let tag_9f27_cryptogram_information_data = self.require_tag("9F27")?;

        if &tag_9f27_cryptogram_information_data[..] != &cryptogram_information_data[..] {
            return Err(warned(EmvError::authentication(format!(
                "Cryptogram information data mismatch in CDA! 9F27:{:02X?}, 9F4B.CID:{:02X?}",
                &tag_9f27_cryptogram_information_data[..],
                cryptogram_information_data
            ))));
        }

        let mut checksum_data: Vec<u8> = Vec::new();

        checksum_data.extend_from_slice(&self.pdol_data()?);
        checksum_data.extend_from_slice(&self.dol_data("8C")?);
        if cdol_tag == "8D" {
            checksum_data.extend_from_slice(&self.dol_data("8D")?);
        }

        // Response data objects in the order they are returned, except Signed Dynamic Application Data
        match parse_tlv(generate_ac_response).map(|tlv| tlv.value().clone()) {
            Some(Value::Constructed(response_tlvs)) => {
                for response_tlv in response_tlvs {
                    if hex::encode_upper(response_tlv.tag().to_bytes()) != "9F4B" {
                        checksum_data.extend_from_slice(&response_tlv.to_vec()[..]);
                    }
                }
            }
            _ => {
                return Err(warned(EmvError::invalid(
                    "Could not parse GENERATE AC response template",
                )));
            }
        }

        let transaction_data_hash_code_checksum = sha1(&checksum_data[..]);

        if &transaction_data_hash_code_checksum[..] != &transaction_data_hash_code[..] {
            warn!(
                "Calculated transaction data\n{}",
                HexViewBuilder::new(&checksum_data[..]).finish()
            );
            warn!(
                "Calculated transaction data hash code\n{}",
                HexViewBuilder::new(&transaction_data_hash_code_checksum[..]).finish()
            );
            warn!(
                "Transaction data hash code\n{}",
                HexViewBuilder::new(&transaction_data_hash_code[..]).finish()
            );

            return Err(warned(EmvError::authentication(
                "Transaction data hash code mismatch!",
            )));
        }

        self.process_tag_as_tlv("9F26", tag_9f26_application_cryptogram);

        Ok(())
    }

    // EMV Book 3, 9.3: the ICC responds with the requested cryptogram type or a lower one. A higher one is an ICC logic error,
    // the transaction is terminated after the first GENERATE AC and the cryptogram is treated as an AAC after the second one.
    fn validate_ac(
        &self,
        requested_cryptogram_type: CryptogramType,
        second_generate_ac: bool,
    ) -> Result<CryptogramType, EmvError> {
        let tag_9f27_cryptogram_information_data = self.require_tag("9F27")?;
        let Some(Ok(mut icc_cryptogram_type)) = tag_9f27_cryptogram_information_data
            .first()
            .map(|cid| CryptogramType::try_from(*cid))
        else {
            return Err(warned(EmvError::invalid(format!(
                "Unknown cryptogram type in Cryptogram Information Data {:02X?}",
                tag_9f27_cryptogram_information_data
            ))));
        };

        if icc_cryptogram_type.level() > requested_cryptogram_type.level() {
            if self
                .settings
                .terminal
                .protocol_deviations
                .accept_higher_cryptogram_type
            {
                warn!(
                    "ICC logic error: {:?} requested but {:?} returned, accepted as a protocol deviation",
                    requested_cryptogram_type, icc_cryptogram_type
                );
            } else if second_generate_ac {
                warn!(
                    "ICC logic error: {:?} requested but {:?} returned, treated as an AAC",
                    requested_cryptogram_type, icc_cryptogram_type
                );
                icc_cryptogram_type = CryptogramType::ApplicationAuthenticationCryptogram;
            } else {
                return Err(warned(EmvError::invalid(format!(
                    "ICC logic error: {:?} requested but {:?} returned, transaction terminated",
                    requested_cryptogram_type, icc_cryptogram_type
                ))));
            }
        }

        if let CryptogramType::ApplicationAuthenticationCryptogram = icc_cryptogram_type {
            info!("Transaction declined by ICC (AAC)");
        }

        // Application Transaction Counter is mandatory in the GENERATE AC response, EMV Book 3, 6.5.5.4
        self.require_tag("9F36")?;

        Ok(icc_cryptogram_type)
    }

    /// Whether the terminal requests CDA in GENERATE AC: both the terminal and the card support it
    pub fn cda_requested(&self) -> bool {
        self.icc.capabilities.cda && self.settings.terminal.capabilities.cda
    }

    /// GENERATE AC with CDOL1 ('8C') or CDOL2 ('8D') data, EMV Book 3, 6.5.5 and EMV Contactless Book C-2, 7.6. A failed CDA
    /// sets 'CDA failed' in TVR and the cryptogram is treated as an AAC (EMV Book 2, 6.6.2).
    pub fn send_generate_ac(
        &mut self,
        requested_cryptogram_type: CryptogramType,
        cdol_tag: &str,
        second_generate_ac: bool,
        cda: bool,
    ) -> Result<CryptogramType, EmvError> {
        let mut p1_reference_control_parameter: u8 = requested_cryptogram_type.into();
        set_bit!(p1_reference_control_parameter, 4, cda);

        // ICC Dynamic Number (9F4C) is known only after DDA, otherwise it is zero filled like any data object that the terminal
        // does not have (EMV Book 3, 5.4). GET CHALLENGE is for the offline PIN encipherment only (EMV Book 2, 7.2).
        let cdol_data = self.dol_data(cdol_tag)?;
        if cdol_data.len() > 0xFF {
            return Err(warned(EmvError::invalid(format!(
                "{} data is too long, {} bytes",
                cdol_tag,
                cdol_data.len()
            ))));
        }

        let apdu_command_generate_ac = b"\x80\xAE";
        let mut generate_ac_command = apdu_command_generate_ac.to_vec();
        generate_ac_command.push(p1_reference_control_parameter);
        generate_ac_command.push(0x00);
        generate_ac_command.push(cdol_data.len() as u8);
        generate_ac_command.extend_from_slice(&cdol_data);
        generate_ac_command.push(0x00);

        let response = self.send_apdu(&generate_ac_command)?;
        if !response.is_success() {
            // 67 00 = wrong length (i.e. CDOL data incorrect)
            return Err(EmvConnection::card_status_error("GENERATE AC", &response));
        }

        // Format 1: CID (1) || ATC (2) || Application Cryptogram (8) || Issuer Application Data (optional)
        let response_data = &response.data;
        match response_data.first() {
            Some(0x80) if response_data.len() >= 13 => {
                self.process_tag_as_tlv("9F27", response_data[2..3].to_vec());
                self.process_tag_as_tlv("9F36", response_data[3..5].to_vec());
                self.process_tag_as_tlv("9F26", response_data[5..13].to_vec());
                if response_data.len() > 13 {
                    self.process_tag_as_tlv("9F10", response_data[13..].to_vec());
                }
            }
            Some(0x77) => {}
            _ => {
                return Err(warned(EmvError::invalid(
                    "Unrecognized GENERATE AC response",
                )));
            }
        }

        let mut cda_failed = false;
        if cda {
            let icc_cryptogram_type = self
                .require_tag("9F27")?
                .first()
                .map(|cid| CryptogramType::try_from(*cid));

            match icc_cryptogram_type {
                Some(Ok(CryptogramType::TransactionCertificate))
                | Some(Ok(CryptogramType::AuthorisationRequestCryptogram)) => {
                    // EMV Book 2, 6.6.2: a failed dynamic signature verification is 'CDA failed' in TVR, the Application
                    // Cryptogram is not recovered and the transaction is declined
                    if self
                        .handle_application_cryptogram_card_authentication(
                            &response.data[..],
                            cdol_tag,
                        )
                        .is_err()
                    {
                        warn!("CDA failed, the cryptogram is treated as an AAC");
                        self.state.tvr.cda_failed = true;
                        cda_failed = true;
                    }
                }
                _ => {}
            }
        }

        let icc_cryptogram_type =
            self.validate_ac(requested_cryptogram_type, second_generate_ac)?;
        if cda_failed {
            return Ok(CryptogramType::ApplicationAuthenticationCryptogram);
        }
        Ok(icc_cryptogram_type)
    }

    /// First GENERATE AC requesting the cryptogram type of the settings
    pub fn handle_1st_generate_ac(&mut self) -> Result<CryptogramType, EmvError> {
        self.first_generate_ac(self.settings.terminal.cryptogram_type)
    }

    /// First GENERATE AC requesting the cryptogram type. The cryptogram of a contactless GET PROCESSING OPTIONS response is
    /// validated instead.
    pub fn first_generate_ac(
        &mut self,
        requested_cryptogram_type: CryptogramType,
    ) -> Result<CryptogramType, EmvError> {
        debug!("Generate Application Cryptogram (GENERATE AC) - first issuance:");

        if self.contactless && self.get_tag_value("9F26").is_some() {
            debug!("Application Cryptogram returned in GET PROCESSING OPTIONS");
            // ref. EMV Contactless Book C-3, A.2 Data Elements by Name - cryptogram returned in GET PROCESSING OPTIONS (Kernel 3, Visa)
            return self.validate_ac(requested_cryptogram_type, false);
        }

        // ARQC continues with online processing and handle_2nd_generate_ac
        let cda = self.cda_requested();
        self.send_generate_ac(requested_cryptogram_type, "8C", false, cda)
    }

    /// Terminal decision on an online authorised transaction from the Authorisation Response Code: TC to approve, AAC to decline
    pub fn online_authorisation_decision(&self) -> CryptogramType {
        // EMV Book 4, 6.3.8 and 12.2.1: the terminal decides from the Authorisation Response Code whether to accept or decline the
        // transaction and requests a TC or an AAC. 'Y3' and 'Z3' are 'Unable to go online, offline approved / declined' (Book 4, A6).
        match (
            self.get_tag_value("8A"),
            &self
                .settings
                .terminal
                .online_approved_authorisation_response_codes,
        ) {
            (Some(arc), _) if &arc[..] == b"Y3" => CryptogramType::TransactionCertificate,
            (Some(arc), _) if &arc[..] == b"Z3" => {
                CryptogramType::ApplicationAuthenticationCryptogram
            }
            (Some(arc), Some(approved)) => {
                if approved.iter().any(|code| code.as_bytes() == &arc[..]) {
                    CryptogramType::TransactionCertificate
                } else {
                    CryptogramType::ApplicationAuthenticationCryptogram
                }
            }
            _ => self.settings.terminal.cryptogram_type_arqc,
        }
    }

    /// In a contact transaction an ARQC is completed with the second GENERATE AC. A contactless transaction has only one
    /// GENERATE AC (or the cryptogram in the GET PROCESSING OPTIONS response), an ARQC is the Online Request outcome and the
    /// online authorisation is final (EMV Contactless Book A, Online Request Outcome). The returned type is then the terminal
    /// decision from the Authorisation Response Code, no cryptogram is requested from the card.
    pub fn handle_2nd_generate_ac(&mut self) -> Result<CryptogramType, EmvError> {
        let decision = self.online_authorisation_decision();
        if self.contactless {
            debug!(
                "No second GENERATE AC in a contactless transaction, online authorisation decides the outcome: {:?}",
                decision
            );
            return Ok(decision);
        }

        self.second_generate_ac(decision)
    }

    /// Second GENERATE AC with CDOL2 data requesting the cryptogram type, also in a contactless transaction
    pub fn second_generate_ac(
        &mut self,
        requested_cryptogram_type: CryptogramType,
    ) -> Result<CryptogramType, EmvError> {
        debug!("Generate Application Cryptogram (GENERATE AC) - second issuance:");

        // EMV Book 3, 9.3: the ICC responds to the second GENERATE AC with either a TC or an AAC
        let cda = self.cda_requested();
        let icc_cryptogram_type =
            self.send_generate_ac(requested_cryptogram_type, "8D", true, cda)?;
        if let CryptogramType::AuthorisationRequestCryptogram = icc_cryptogram_type {
            return Err(warned(EmvError::invalid(
                "ARQC returned to the second GENERATE AC",
            )));
        }

        Ok(icc_cryptogram_type)
    }

    /// READ RECORD, None when the card does not return the record (EMV Book 3, 6.5.11)
    pub fn read_record(
        &mut self,
        short_file_identifier: u8,
        record_index: u8,
    ) -> Result<Option<Vec<u8>>, EmvError> {
        let apdu_command_read = b"\x00\xB2";

        let mut read_record = apdu_command_read.to_vec();
        read_record.push(record_index);
        read_record.push((short_file_identifier << 3) | 0x04);

        const RECORD_LENGTH_DEFAULT: u8 = 0x00;
        read_record.push(RECORD_LENGTH_DEFAULT);

        let response = self.send_apdu(&read_record)?;

        if response.is_success() && !response.data.is_empty() {
            return Ok(Some(response.data));
        }

        Ok(None)
    }

    pub fn handle_select_payment_system_environment(
        &mut self,
    ) -> Result<Vec<EmvApplication>, EmvError> {
        // ref. EMV Book 1, Payment System Environment (PSE) and EMV Contactless Book B, Proximity Payment System
        // Environment (PPSE)
        let pse_name = if self.contactless {
            debug!("Selecting Proximity Payment System Environment (PPSE):");
            "2PAY.SYS.DDF01"
        } else {
            debug!("Selecting Payment System Environment (PSE):");
            "1PAY.SYS.DDF01"
        };

        let response = self.send_apdu_select(&pse_name.as_bytes())?;
        if !response.is_success() {
            return Err(EmvConnection::card_status_error(
                &format!("SELECT {}", pse_name),
                &response,
            ));
        }
        let response_data = response.data;

        let mut all_applications: Vec<EmvApplication> = Vec::new();

        if self.contactless {
            //EMV Contactless Book B, Entry Point Specification v2.6, Table3-2: SELECT Response Message Data Field (FCI) of the PPSE
            match find_tlv_tag(&response_data, "BF0C") {
                Some(tag_bf0c) => {
                    if let Value::Constructed(application_templates) = tag_bf0c.value() {
                        for tag_61_application_template in application_templates {
                            if let Value::Constructed(application_template) =
                                tag_61_application_template.value()
                            {
                                self.tags.clear();

                                for application_template_child_tag in application_template {
                                    if let Value::Primitive(value) =
                                        application_template_child_tag.value()
                                    {
                                        let tag_name = hex::encode(
                                            application_template_child_tag.tag().to_bytes(),
                                        )
                                        .to_uppercase();
                                        self.add_tag(&tag_name, value.to_vec());
                                    }
                                }

                                let Some(tag_4f_aid) = self.get_tag_value("4F") else {
                                    warn!("Directory entry without an AID (4F)");
                                    continue;
                                };
                                let tag_50_label = match self.get_tag_value("50") {
                                    Some(v) => v,
                                    None => "UNKNOWN".as_bytes(),
                                };

                                //EMV Contactless Book B, Entry Point Specification v2.6, Table3-3: Format of Application Priority Indicator
                                let tag_87_priority = match self.get_tag_value("87") {
                                    Some(v) => v,
                                    None => "01".as_bytes(),
                                };

                                all_applications.push(EmvApplication {
                                    aid: tag_4f_aid.clone(),
                                    label: tag_50_label.to_vec(),
                                    priority: tag_87_priority.to_vec(),
                                    kernel_identifier: self.get_tag_value("9F2A").cloned(),
                                });

                                // TODO: Since in NFC we're interested only of a single application
                                //       However we should select the one with the best priority

                                break;
                            }
                        }
                    }
                }
                None => {
                    return Err(warned(EmvError::invalid(format!(
                        "Expected tag BF0C not found! pse:{}",
                        pse_name
                    ))));
                }
            }
        } else {
            let short_file_identifier = match &self.require_tag("88")?[..] {
                [short_file_identifier] => *short_file_identifier,
                sfi_data => {
                    return Err(warned(EmvError::invalid(format!(
                        "Invalid PSE Short File Identifier {:02X?}",
                        sfi_data
                    ))));
                }
            };

            debug!("Read available AIDs:");

            for record_index in 0x01..0xFF {
                match self.read_record(short_file_identifier, record_index)? {
                    Some(data) => {
                        if data[0] != 0x70 {
                            return Err(warned(EmvError::invalid(
                                "Expected PSE record template '70'",
                            )));
                        }

                        let Some(record_template) = parse_tlv(&data) else {
                            return Err(warned(EmvError::invalid("Could not parse PSE record")));
                        };
                        if let Value::Constructed(application_templates) = record_template.value() {
                            for tag_61_application_template in application_templates {
                                if let Value::Constructed(application_template) =
                                    tag_61_application_template.value()
                                {
                                    self.tags.clear();

                                    for application_template_child_tag in application_template {
                                        if let Value::Primitive(value) =
                                            application_template_child_tag.value()
                                        {
                                            let tag_name = hex::encode(
                                                application_template_child_tag.tag().to_bytes(),
                                            )
                                            .to_uppercase();
                                            self.add_tag(&tag_name, value.to_vec());
                                        }
                                    }

                                    let Some(tag_4f_aid) = self.get_tag_value("4F") else {
                                        warn!("Directory entry without an AID (4F)");
                                        continue;
                                    };
                                    let default_label = "UNKNOWN".as_bytes().to_vec();
                                    let tag_50_label =
                                        self.get_tag_value("50").unwrap_or(&default_label);

                                    if let Some(tag_87_priority) = self.get_tag_value("87") {
                                        all_applications.push(EmvApplication {
                                            aid: tag_4f_aid.clone(),
                                            label: tag_50_label.clone(),
                                            priority: tag_87_priority.clone(),
                                            kernel_identifier: None,
                                        });
                                    } else {
                                        debug!(
                                            "Skipping application. AID:{:02X?}, label:{:?}",
                                            tag_4f_aid,
                                            String::from_utf8_lossy(&tag_50_label)
                                        );
                                    }
                                }
                            }
                        }
                    }
                    None => break,
                };
            }
        }

        if all_applications.is_empty() {
            return Err(warned(EmvError::missing("No application records found!")));
        }

        Ok(all_applications)
    }

    /// Candidate applications from the terminal list of AIDs, ref. EMV Book 1, 12.3.3 Using a List of AIDs
    pub fn handle_select_list_of_aids(&mut self) -> Result<Vec<EmvApplication>, EmvError> {
        debug!("Selecting applications with the terminal list of AIDs:");

        let mut all_applications: Vec<EmvApplication> = Vec::new();

        for terminal_aid_hex in self.settings.terminal.application_identifiers.clone() {
            let terminal_aid = match hex::decode(&terminal_aid_hex) {
                Ok(aid) if !aid.is_empty() => aid,
                _ => {
                    warn!("Invalid terminal AID {:?}", terminal_aid_hex);
                    continue;
                }
            };

            // A card answering the same occurrence again would otherwise be selected endlessly
            let mut selected_df_names: Vec<Vec<u8>> = Vec::new();
            let mut next_occurrence = false;

            loop {
                let response = self.send_apdu_select_occurrence(&terminal_aid, next_occurrence)?;

                // '6A81': the card is blocked or does not support SELECT, the card is rejected
                if response.sw == [0x6A, 0x81] {
                    warn!("Card blocked or SELECT not supported");
                    return Err(EmvConnection::card_status_error("SELECT", &response));
                }

                // '6283': the application is blocked, it is not a candidate but further occurrences are still selected
                let application_blocked = response.sw == [0x62, 0x83];
                if !response.is_success() && !application_blocked {
                    break;
                }

                let df_name = match self.get_tag_value("84") {
                    Some(df_name) if df_name.starts_with(&terminal_aid) => df_name.clone(),
                    _ => {
                        warn!(
                            "DF name of the selected application does not match the terminal AID {:02X?}",
                            terminal_aid
                        );
                        break;
                    }
                };

                if selected_df_names.contains(&df_name) {
                    break;
                }
                selected_df_names.push(df_name.clone());

                if application_blocked {
                    debug!("Skipping blocked application. AID:{:02X?}", df_name);
                } else if !all_applications.iter().any(|a| a.aid == df_name) {
                    let default_label = "UNKNOWN".as_bytes().to_vec();
                    all_applications.push(EmvApplication {
                        aid: df_name.clone(),
                        label: self.get_tag_value("50").unwrap_or(&default_label).clone(),
                        priority: self.get_tag_value("87").cloned().unwrap_or_default(),
                        kernel_identifier: None,
                    });
                }

                // An exact match is the only occurrence, a partial match may have further occurrences
                if df_name == terminal_aid {
                    break;
                }
                next_occurrence = true;
            }
        }

        if all_applications.is_empty() {
            return Err(warned(EmvError::missing(
                "No applications of the terminal list of AIDs found!",
            )));
        }

        Ok(all_applications)
    }

    pub fn handle_select_payment_application(
        &mut self,
        application: &EmvApplication,
    ) -> Result<(), EmvError> {
        info!(
            "Selecting application. AID:{:02X?}, label:{:?}, priority:{:02X?}, kernel identifier:{:02X?}",
            application.aid,
            // Application Label is ans (EMV Book 3, Annex A), a card may still have other bytes in it
            String::from_utf8_lossy(&application.label),
            application.priority,
            application.kernel_identifier
        );
        let response = self.send_apdu_select(&application.aid)?;
        if !response.is_success() {
            warn!(
                "Could not select payment application! {:02X?}, {:?}",
                application.aid, application.label
            );
            return Err(EmvConnection::card_status_error("SELECT", &response));
        }
        self.kernel_identifier = application.kernel_identifier.clone();

        Ok(())
    }

    /// Candidate applications of the PSE / PPSE, or without them of the terminal list of AIDs (EMV Book 1, 12.3.2)
    pub fn candidate_applications(&mut self) -> Result<Vec<EmvApplication>, EmvError> {
        match self.handle_select_payment_system_environment() {
            Ok(applications) => Ok(applications),
            Err(EmvError::Interface(err)) => Err(EmvError::Interface(err)),
            Err(_) => self.handle_select_list_of_aids(),
        }
    }

    /// Selects an application of the candidate applications chosen with pse_application_select_callback, the first one without it
    pub fn select_payment_application(&mut self) -> Result<EmvApplication, EmvError> {
        let applications = self.candidate_applications()?;

        let application = match &self.pse_application_select_callback {
            Some(callback) => callback(&applications)?,
            None => applications[0].clone(),
        };
        self.handle_select_payment_application(&application)?;

        Ok(application)
    }

    /// Terminal data objects of the settings, and of the transaction date, time and Unpredictable Number when not set
    pub fn process_settings(&mut self) -> Result<(), EmvError> {
        let default_tags = self.settings.default_tags.clone();
        for (tag_name, tag_value) in default_tags.iter() {
            let value = hex::decode(tag_value).map_err(|_| {
                EmvError::Configuration(format!("Invalid value of default tag {}", tag_name))
            })?;
            self.set_tag(&tag_name, value)?;
        }

        let now = Utc::now().naive_utc();
        if !self.get_tag_value("9A").is_some() {
            let today = now.date();
            let transaction_date_ascii_yymmdd = format!(
                "{:02}{:02}{:02}",
                today.year() - 2000,
                today.month(),
                today.day()
            );
            self.process_tag_as_tlv("9A", hex::decode(transaction_date_ascii_yymmdd).unwrap());
        }

        if !self.get_tag_value("9F21").is_some() {
            let time = now.time();
            let transaction_time_ascii_hhmmss =
                format!("{:02}{:02}{:02}", time.hour(), time.minute(), time.second());
            self.process_tag_as_tlv("9F21", hex::decode(transaction_time_ascii_hhmmss).unwrap());
        }

        if !self.get_tag_value("9F37").is_some() {
            let mut tag_9f37_unpredictable_number = [0u8; 4];
            self.fill_random(&mut tag_9f37_unpredictable_number[..]);

            self.process_tag_as_tlv("9F37", tag_9f37_unpredictable_number.to_vec());
        }

        if !self.get_tag_value("8A").is_some() {
            // ref. EMV Book 4, A6 Authorisation Response Code
            self.process_tag_as_tlv("8A", b"\x59\x33".to_vec()); //Y3 = Unable to go online, offline approved
        }

        if !self.get_tag_value("9F66").is_some() {
            let tag_9f66_ttq: Vec<u8> = self
                .settings
                .terminal
                .terminal_transaction_qualifiers
                .into();
            self.process_tag_as_tlv("9F66", tag_9f66_ttq);
        }

        if !self.get_tag_value("9F6E").is_some() {
            let tag_9f6e: Vec<u8> = self
                .settings
                .terminal
                .c4_enhanced_contactless_reader_capabilities
                .into();
            self.process_tag_as_tlv("9F6E", tag_9f6e);
        }

        Ok(())
    }

    /// GET DATA of a one or two byte tag (P1 P2), EMV Book 3, 6.5.7: e.g. 9F36, 9F13, 9F17 or 9F4F
    pub fn handle_get_data(&mut self, tag: &[u8]) -> Result<Vec<u8>, EmvError> {
        debug!("GET DATA:");

        let p1_p2: [u8; 2] = match tag {
            [tag] => [0x00, *tag],
            [p1, p2] => [*p1, *p2],
            _ => {
                return Err(EmvError::Configuration(format!(
                    "GET DATA tag {:02X?} is not one or two bytes",
                    tag
                )));
            }
        };

        let apdu_command_get_data = b"\x80\xCA";

        let mut get_data_command = apdu_command_get_data.to_vec();
        get_data_command.extend_from_slice(&p1_p2);
        get_data_command.push(0x00); // le

        let response = self.send_apdu(&get_data_command[..])?;
        if !response.is_success() {
            return Err(EmvConnection::card_status_error("GET DATA", &response));
        }

        Ok(response.data)
    }

    pub fn handle_get_challenge(&mut self) -> Result<Vec<u8>, EmvError> {
        debug!("GET CHALLENGE:");

        let apdu_command_get_challenge = b"\x00\x84\x00\x00\x00";

        let response = self.send_apdu(&apdu_command_get_challenge[..])?;
        if !response.is_success() {
            return Err(EmvConnection::card_status_error("GET CHALLENGE", &response));
        }

        Ok(response.data)
    }

    /// Retrieves the Issuer, ICC and ICC PIN Encipherment public keys (EMV Book 2, 6.3, 6.4 and 7.1). A key that can not be
    /// retrieved is left unset, offline data authentication then fails and the terminal sets the failure in TVR (EMV Book 3,
    /// 10.3).
    pub fn handle_public_keys(&mut self, application: &EmvApplication) -> Result<(), EmvError> {
        if self.get_tag_value("8F").is_none() {
            debug!("Card does not support offline data authentication");
            return Ok(());
        }

        // A key that can not be retrieved is left unset, offline data authentication then fails and the terminal sets the
        // failure in TVR (EMV Book 3, 10.3)
        let (issuer_pk_modulus, issuer_pk_exponent) = match self.get_issuer_public_key(application)
        {
            Ok(key) => key,
            Err(_) => {
                warn!("Issuer public key could not be retrieved");
                return Ok(());
            }
        };
        self.icc.issuer_pk = Some(RsaPublicKey::new(
            &issuer_pk_modulus[..],
            &issuer_pk_exponent[..],
            self.settings.censor_sensitive_fields,
        ));

        let data_authentication = self.icc.data_authentication.as_deref().unwrap_or_default();

        let tag_9f46_icc_pk_certificate = self.get_tag_value("9F46");
        let tag_9f47_icc_pk_exponent = self.get_tag_value("9F47");
        if tag_9f46_icc_pk_certificate.is_some() && tag_9f47_icc_pk_exponent.is_some() {
            let tag_9f48_icc_pk_remainder = self.get_tag_value("9F48");
            match self.get_icc_public_key(
                tag_9f46_icc_pk_certificate.unwrap(),
                tag_9f47_icc_pk_exponent.unwrap(),
                tag_9f48_icc_pk_remainder,
                Some(data_authentication),
            ) {
                Ok((icc_pk_modulus, icc_pk_exponent)) => {
                    self.icc.icc_pk = Some(RsaPublicKey::new(
                        &icc_pk_modulus[..],
                        &icc_pk_exponent[..],
                        self.settings.censor_sensitive_fields,
                    ));
                    self.icc.icc_pin_pk = self.icc.icc_pk.clone();
                }
                Err(_) => warn!("ICC public key could not be retrieved"),
            }
        }

        let tag_9f2d_icc_pin_pk_certificate = self.get_tag_value("9F2D");
        let tag_9f2e_icc_pin_pk_exponent = self.get_tag_value("9F2E");
        if tag_9f2d_icc_pin_pk_certificate.is_some() && tag_9f2e_icc_pin_pk_exponent.is_some() {
            let tag_9f2f_icc_pin_pk_remainder = self.get_tag_value("9F2F");

            // ICC has a separate ICC PIN Encipherment public key, its certificate has no static data (EMV Book 2, 7.1)
            match self.get_icc_public_key(
                tag_9f2d_icc_pin_pk_certificate.unwrap(),
                tag_9f2e_icc_pin_pk_exponent.unwrap(),
                tag_9f2f_icc_pin_pk_remainder,
                None,
            ) {
                Ok((icc_pin_pk_modulus, icc_pin_pk_exponent)) => {
                    self.icc.icc_pin_pk = Some(RsaPublicKey::new(
                        &icc_pin_pk_modulus[..],
                        &icc_pin_pk_exponent[..],
                        self.settings.censor_sensitive_fields,
                    ));
                }
                Err(_) => warn!("ICC PIN Encipherment public key could not be retrieved"),
            }
        }

        Ok(())
    }

    /// Certificate Expiration Date of the Issuer or ICC Public Key Certificate (EMV Book 2, 6.3 and 6.4). An expired certificate
    /// fails offline data authentication unless the ignore_certificate_expiry protocol deviation is enabled, the expiry is logged.
    fn check_public_key_certificate_expiry(
        &self,
        certificate: &str,
        date_bcd: &[u8],
    ) -> Result<(), EmvError> {
        match check_certificate_expiry(date_bcd) {
            CertificateExpiry::Valid => Ok(()),
            CertificateExpiry::Expired
                if self
                    .settings
                    .terminal
                    .protocol_deviations
                    .ignore_certificate_expiry =>
            {
                warn!("{} expired, accepted as a protocol deviation", certificate);
                Ok(())
            }
            CertificateExpiry::Expired => Err(warned(EmvError::authentication(format!(
                "{} expired",
                certificate
            )))),
            CertificateExpiry::InvalidDate => Err(warned(EmvError::authentication(format!(
                "{} expiry date is invalid",
                certificate
            )))),
        }
    }

    pub fn get_issuer_public_key(
        &self,
        application: &EmvApplication,
    ) -> Result<(Vec<u8>, Vec<u8>), EmvError> {
        // ref. https://www.emvco.com/wp-content/uploads/2017/05/EMV_v4.3_Book_2_Security_and_Key_Management_20120607061923900.pdf - 6.3 Retrieval of Issuer Public Key
        let tag_92_issuer_pk_remainder = self.get_tag_value("92");
        let (
            Some(tag_9f32_issuer_pk_exponent),
            Some(tag_90_issuer_public_key_certificate),
            Some(tag_8f_ca_pk_index),
        ) = (
            self.get_tag_value("9F32"),
            self.get_tag_value("90"),
            self.get_tag_value("8F"),
        )
        else {
            return Err(warned(EmvError::missing(
                "Issuer Public Key Certificate, Issuer Public Key Exponent or CA Public Key Index",
            )));
        };

        // Registered Application Provider Identifier (RID) of the AID
        let Some(rid) = application.aid.get(0..5) else {
            return Err(warned(EmvError::invalid(format!(
                "AID {:02X?} is shorter than a RID",
                application.aid
            ))));
        };

        let ca_pk = match get_ca_public_key(
            &self.scheme_ca_public_keys,
            &rid[..],
            &tag_8f_ca_pk_index[..],
        ) {
            Some(ca_pk) => ca_pk,
            None => {
                return Err(warned(EmvError::authentication(format!(
                    "CA public key not found, rid:{:02X?}, index:{:02X?}",
                    rid, tag_8f_ca_pk_index
                ))));
            }
        };

        // EMV Book 2, 6.3: the certificate length is the CA public key modulus length
        if tag_90_issuer_public_key_certificate.len() != ca_pk.get_key_byte_size()
            || ca_pk.get_key_byte_size() < 36
        {
            return Err(warned(EmvError::authentication(
                "Issuer Public Key Certificate and CA public key length mismatch",
            )));
        }

        let issuer_certificate = ca_pk.public_decrypt(&tag_90_issuer_public_key_certificate[..])?;
        let issuer_certificate_length = issuer_certificate.len();

        if issuer_certificate[1] != 0x02 {
            return Err(warned(EmvError::authentication(format!(
                "Incorrect issuer certificate type {:02X?}",
                issuer_certificate[1]
            ))));
        }

        let checksum_position = 15 + issuer_certificate_length - 36;

        let issuer_certificate_iin = &issuer_certificate[2..6];
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
        debug!(
            "Issuer hash algo:{:02X?}",
            issuer_certificate_hash_algorithm
        );
        debug!("Issuer pk algo:{:02X?}", issuer_pk_algorithm);
        debug!("Issuer pk length:{:02X?}", issuer_pk_length);
        debug!("Issuer pk exp length:{:02X?}", issuer_pk_exponent_length);
        debug!(
            "Issuer pk leftmost digits:{:02X?}",
            issuer_pk_leftmost_digits
        );

        // SHA-1 and RSA as defined in EMV Book 2, B2.1 RSA Algorithm
        if issuer_certificate_hash_algorithm[0] != 0x01 || issuer_pk_algorithm[0] != 0x01 {
            return Err(warned(EmvError::authentication(format!(
                "Unsupported issuer certificate hash algorithm {:02X?} or public key algorithm {:02X?}",
                issuer_certificate_hash_algorithm, issuer_pk_algorithm
            ))));
        }

        let issuer_certificate_checksum =
            &issuer_certificate[checksum_position..checksum_position + 20];

        let mut checksum_data: Vec<u8> = Vec::new();
        checksum_data.extend_from_slice(&issuer_certificate[1..checksum_position]);
        if tag_92_issuer_pk_remainder.is_some() {
            checksum_data.extend_from_slice(&tag_92_issuer_pk_remainder.unwrap()[..]);
        }
        checksum_data.extend_from_slice(&tag_9f32_issuer_pk_exponent[..]);

        let cert_checksum = sha1(&checksum_data[..]);

        if &cert_checksum[..] != &issuer_certificate_checksum[..] {
            warn!(
                "Calculated checksum\n{}",
                HexViewBuilder::new(&cert_checksum[..]).finish()
            );
            warn!(
                "Issuer provided checksum\n{}",
                HexViewBuilder::new(&issuer_certificate_checksum[..]).finish()
            );

            return Err(warned(EmvError::authentication(
                "Issuer cert checksum mismatch!",
            )));
        }

        let tag_5a_pan = self.require_tag("5A")?;
        let ascii_pan = bcdutil::bcd_to_ascii(&tag_5a_pan[..])
            .map_err(|_| warned(EmvError::invalid("PAN is not BCD")))?;
        let ascii_iin = bcdutil::bcd_to_ascii(&issuer_certificate_iin)
            .map_err(|_| warned(EmvError::authentication("Certificate IIN is not BCD")))?;
        if ascii_pan.len() < ascii_iin.len() || ascii_iin != &ascii_pan[0..ascii_iin.len()] {
            return Err(warned(EmvError::authentication(format!(
                "IIN mismatch! Cert IIN: {:02X?}, PAN: {:02X?}",
                ascii_iin, ascii_pan
            ))));
        }

        self.check_public_key_certificate_expiry(
            "Issuer Public Key Certificate",
            &issuer_certificate_expiry[..],
        )?;

        let issuer_pk_leftmost_digits_length = issuer_pk_leftmost_digits
            .iter()
            .rev()
            .position(|c| -> bool { *c != 0xBB })
            .map_or(0, |i| issuer_pk_leftmost_digits.len() - i);

        let mut issuer_pk_modulus: Vec<u8> = Vec::new();
        issuer_pk_modulus
            .extend_from_slice(&issuer_pk_leftmost_digits[..issuer_pk_leftmost_digits_length]);
        if tag_92_issuer_pk_remainder.is_some() {
            issuer_pk_modulus.extend_from_slice(&tag_92_issuer_pk_remainder.unwrap()[..]);
        }
        trace!(
            "Issuer PK modulus:\n{}",
            HexViewBuilder::new(&issuer_pk_modulus[..]).finish()
        );

        Ok((issuer_pk_modulus, tag_9f32_issuer_pk_exponent.to_vec()))
    }

    /// ICC Public Key (EMV Book 2, 6.4) with the static data to be authenticated, or the ICC PIN Encipherment Public Key
    /// (EMV Book 2, 7.1) when static_data_authentication is None: its certificate hash has no static data to be authenticated
    /// and no Static Data Authentication Tag List values.
    pub fn get_icc_public_key(
        &self,
        icc_pk_certificate: &Vec<u8>,
        icc_pk_exponent: &Vec<u8>,
        icc_pk_remainder: Option<&Vec<u8>>,
        static_data_authentication: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Vec<u8>), EmvError> {
        // ICC public key retrieval: EMV Book 2, 6.4 Retrieval of ICC Public Key
        debug!(
            "Retrieving ICC public key {:02X?}",
            &icc_pk_certificate[..icc_pk_certificate.len().min(2)]
        );

        let tag_9f46_icc_pk_certificate = icc_pk_certificate;

        let Some(issuer_pk) = self.icc.issuer_pk.as_ref() else {
            return Err(warned(EmvError::missing(
                "Issuer public key, can't retrieve ICC public key",
            )));
        };

        // EMV Book 2, 6.4: the certificate length is the issuer public key modulus length
        if tag_9f46_icc_pk_certificate.len() != issuer_pk.get_key_byte_size()
            || issuer_pk.get_key_byte_size() < 42
        {
            return Err(warned(EmvError::authentication(
                "ICC Public Key Certificate and issuer public key length mismatch",
            )));
        }

        let icc_certificate = issuer_pk.public_decrypt(&tag_9f46_icc_pk_certificate[..])?;
        let icc_certificate_length = icc_certificate.len();
        if icc_certificate[1] != 0x04 {
            return Err(warned(EmvError::authentication(format!(
                "Incorrect ICC certificate type {:02X?}",
                icc_certificate[1]
            ))));
        }

        let checksum_position = 21 + icc_certificate_length - 42;

        let icc_certificate_pan = &icc_certificate[2..12];
        let icc_certificate_expiry = &icc_certificate[12..14];
        let icc_certificate_serial = &icc_certificate[14..17];
        let icc_certificate_hash_algo = &icc_certificate[17..18];
        let icc_certificate_pk_algo = &icc_certificate[18..19];
        let icc_certificate_pk_length = &icc_certificate[19..20];
        let icc_certificate_pk_exp_length = &icc_certificate[20..21];
        let icc_certificate_pk_leftmost_digits = &icc_certificate[21..checksum_position];

        if self.settings.censor_sensitive_fields {
            let pan: String = String::from_utf8_lossy(
                &bcdutil::bcd_to_ascii(&icc_certificate_pan).unwrap_or_default(),
            )
            .to_string();
            let truncated_pan = get_truncated_pan(&pan);
            debug!("ICC PAN:{}", truncated_pan);
        } else {
            debug!("ICC PAN:{:02X?}", icc_certificate_pan);
        }
        debug!("ICC expiry:{:02X?}", icc_certificate_expiry);
        debug!("ICC serial:{:02X?}", icc_certificate_serial);
        debug!("ICC hash algo:{:02X?}", icc_certificate_hash_algo);
        debug!("ICC pk algo:{:02X?}", icc_certificate_pk_algo);
        debug!("ICC pk length:{:02X?}", icc_certificate_pk_length);
        debug!("ICC pk exp length:{:02X?}", icc_certificate_pk_exp_length);
        debug!(
            "ICC pk leftmost digits:{:02X?}",
            icc_certificate_pk_leftmost_digits
        );

        // SHA-1 and RSA as defined in EMV Book 2, B2.1 RSA Algorithm
        if icc_certificate_hash_algo[0] != 0x01 || icc_certificate_pk_algo[0] != 0x01 {
            return Err(warned(EmvError::authentication(format!(
                "Unsupported ICC certificate hash algorithm {:02X?} or public key algorithm {:02X?}",
                icc_certificate_hash_algo, icc_certificate_pk_algo
            ))));
        }

        let tag_9f47_icc_pk_exponent = icc_pk_exponent;

        let mut checksum_data: Vec<u8> = Vec::new();
        checksum_data.extend_from_slice(&icc_certificate[1..checksum_position]);

        let tag_9f48_icc_pk_remainder = icc_pk_remainder;
        if let Some(tag_9f48_icc_pk_remainder) = tag_9f48_icc_pk_remainder {
            checksum_data.extend_from_slice(&tag_9f48_icc_pk_remainder[..]);
        }

        checksum_data.extend_from_slice(&tag_9f47_icc_pk_exponent[..]);

        if let Some(data_authentication) = static_data_authentication {
            checksum_data.extend_from_slice(data_authentication);
            checksum_data.extend_from_slice(&self.static_data_authentication_tag_list_values()?);
        }

        let cert_checksum = sha1(&checksum_data[..]);

        let icc_certificate_checksum = &icc_certificate[checksum_position..checksum_position + 20];

        if !self.settings.censor_sensitive_fields {
            trace!("Checksum data: {:02X?}", &checksum_data[..]);
        }
        trace!("Calculated checksum: {:02X?}", cert_checksum);
        trace!("Stored ICC checksum: {:02X?}", icc_certificate_checksum);
        if &cert_checksum[..] != icc_certificate_checksum {
            return Err(warned(EmvError::authentication(
                "ICC cert checksum mismatch!",
            )));
        }

        let tag_5a_pan = self.require_tag("5A")?;
        let ascii_pan = bcdutil::bcd_to_ascii(&tag_5a_pan[..])
            .map_err(|_| warned(EmvError::invalid("PAN is not BCD")))?;
        let icc_ascii_pan = bcdutil::bcd_to_ascii(&icc_certificate_pan)
            .map_err(|_| warned(EmvError::authentication("Certificate PAN is not BCD")))?;
        if icc_ascii_pan != ascii_pan {
            return Err(warned(EmvError::authentication(format!(
                "PAN mismatch! Cert PAN: {:02X?}, PAN: {:02X?}",
                icc_ascii_pan, ascii_pan
            ))));
        }

        self.check_public_key_certificate_expiry(
            "ICC Public Key Certificate",
            &icc_certificate_expiry[..],
        )?;

        let mut icc_pk_modulus: Vec<u8> = Vec::new();

        let icc_certificate_pk_leftmost_digits_length = icc_certificate_pk_leftmost_digits
            .iter()
            .rev()
            .position(|c| -> bool { *c != 0xBB })
            .map_or(0, |i| icc_certificate_pk_leftmost_digits.len() - i);

        icc_pk_modulus.extend_from_slice(
            &icc_certificate_pk_leftmost_digits[..icc_certificate_pk_leftmost_digits_length],
        );

        if let Some(tag_9f48_icc_pk_remainder) = tag_9f48_icc_pk_remainder {
            icc_pk_modulus.extend_from_slice(&tag_9f48_icc_pk_remainder[..]);
        }

        trace!(
            "ICC PK modulus ({} bytes):\n{}",
            icc_pk_modulus.len(),
            HexViewBuilder::new(&icc_pk_modulus[..]).finish()
        );

        Ok((icc_pk_modulus, tag_9f47_icc_pk_exponent.to_vec()))
    }

    /// Values of the data objects in the Static Data Authentication Tag List (9F4A), empty when the card has no tag list.
    /// EMV Book 3, 10.3: the list may contain only the AIP.
    fn static_data_authentication_tag_list_values(&self) -> Result<Vec<u8>, EmvError> {
        match self.get_tag_value("9F4A") {
            Some(tag_list) => Ok(
                DataObjectList::process_data_object_list(self, &tag_list[..])?
                    .get_tag_list_tag_values(self),
            ),
            None => Ok(Vec::new()),
        }
    }

    pub fn validate_signed_dynamic_application_data(
        &self,
        auth_data: &[u8],
    ) -> Result<Vec<u8>, EmvError> {
        let tag_9f4b_signed_data = self.require_tag("9F4B")?;
        trace!(
            "9F4B signed data result moduluslength: ({} bytes):\n{}",
            tag_9f4b_signed_data.len(),
            HexViewBuilder::new(&tag_9f4b_signed_data[..]).finish()
        );

        let Some(icc_pk) = self.icc.icc_pk.as_ref() else {
            return Err(warned(EmvError::missing("ICC public key, can't validate")));
        };

        // EMV Book 2, 6.5.2: the signed data length is the ICC public key modulus length
        if tag_9f4b_signed_data.len() != icc_pk.get_key_byte_size()
            || tag_9f4b_signed_data.len() < 25
        {
            return Err(warned(EmvError::authentication(
                "Signed Dynamic Application Data and ICC public key length mismatch",
            )));
        }

        let tag_9f4b_signed_data_decrypted = icc_pk.public_decrypt(&tag_9f4b_signed_data[..])?;
        let tag_9f4b_signed_data_decrypted_length = tag_9f4b_signed_data_decrypted.len();
        if tag_9f4b_signed_data_decrypted[1] != 0x05 {
            return Err(warned(EmvError::authentication(
                "Unrecognized Signed Dynamic Application Data format",
            )));
        }

        let tag_9f4b_signed_data_decrypted_hash_algo = tag_9f4b_signed_data_decrypted[2];
        if tag_9f4b_signed_data_decrypted_hash_algo != 0x01 {
            return Err(warned(EmvError::authentication(format!(
                "Unsupported hash algorithm {:02X?}",
                tag_9f4b_signed_data_decrypted_hash_algo
            ))));
        }

        let tag_9f4b_signed_data_decrypted_dynamic_data_length =
            tag_9f4b_signed_data_decrypted[3] as usize;
        if 4 + tag_9f4b_signed_data_decrypted_dynamic_data_length + 21
            > tag_9f4b_signed_data_decrypted_length
        {
            return Err(warned(EmvError::authentication(
                "ICC Dynamic Data length exceeds the signed data",
            )));
        }

        let tag_9f4b_signed_data_decrypted_dynamic_data = &tag_9f4b_signed_data_decrypted
            [4..4 + tag_9f4b_signed_data_decrypted_dynamic_data_length];

        let checksum_position = tag_9f4b_signed_data_decrypted_length - 21;
        let mut checksum_data: Vec<u8> = Vec::new();
        checksum_data.extend_from_slice(&tag_9f4b_signed_data_decrypted[1..checksum_position]);
        checksum_data.extend_from_slice(&auth_data[..]);

        let signed_data_checksum = sha1(&checksum_data[..]);

        let tag_9f4b_signed_data_decrypted_checksum =
            &tag_9f4b_signed_data_decrypted[checksum_position..checksum_position + 20];

        if &signed_data_checksum[..] != &tag_9f4b_signed_data_decrypted_checksum[..] {
            warn!(
                "Calculated checksum\n{}",
                HexViewBuilder::new(&signed_data_checksum[..]).finish()
            );
            warn!(
                "Signed data checksum\n{}",
                HexViewBuilder::new(&tag_9f4b_signed_data_decrypted_checksum[..]).finish()
            );

            return Err(warned(EmvError::authentication(
                "Signed data checksum mismatch!",
            )));
        }

        Ok(tag_9f4b_signed_data_decrypted_dynamic_data.to_vec())
    }

    pub fn handle_signed_static_application_data(
        &mut self,
        data_authentication: &[u8],
    ) -> Result<(), EmvError> {
        debug!("Validate Signed Static Application Data (SDA):");

        let Some(issuer_pk) = self.icc.issuer_pk.as_ref() else {
            return Err(warned(EmvError::missing(
                "Issuer public key, can't perform SDA",
            )));
        };

        let tag_93_ssad = self.require_tag("93")?;

        // Header, format, hash algorithm, Data Authentication Code (2), padding, hash (20) and trailer, EMV Book 2, Table 7
        if tag_93_ssad.len() != issuer_pk.get_key_byte_size() || tag_93_ssad.len() < 26 {
            return Err(warned(EmvError::authentication(
                "SDA and issuer key mismatch",
            )));
        }

        let tag_93_ssad_decrypted = issuer_pk.public_decrypt(&tag_93_ssad[..])?;

        if tag_93_ssad_decrypted[1] != 0x03 {
            return Err(warned(EmvError::authentication(
                "Unrecognized Signed Static Application Data format",
            )));
        }

        let mut checksum_data: Vec<u8> = Vec::new();
        checksum_data
            .extend_from_slice(&tag_93_ssad_decrypted[1..tag_93_ssad_decrypted.len() - 22]);
        checksum_data.extend_from_slice(data_authentication);
        checksum_data.extend_from_slice(&self.static_data_authentication_tag_list_values()?);

        let ssad_checksum_calculated = sha1(&checksum_data[..]);

        let ssad_checksum = &tag_93_ssad_decrypted
            [tag_93_ssad_decrypted.len() - 22..tag_93_ssad_decrypted.len() - 1];

        if &ssad_checksum_calculated[..] != ssad_checksum {
            warn!(
                "Checksum input\n{}",
                HexViewBuilder::new(&checksum_data[..]).finish()
            );
            warn!(
                "Calculated checksum\n{}",
                HexViewBuilder::new(&ssad_checksum_calculated[..]).finish()
            );
            warn!(
                "Stored checksum\n{}",
                HexViewBuilder::new(&ssad_checksum[..]).finish()
            );

            return Err(warned(EmvError::authentication(
                "SDA verification mismatch!",
            )));
        }

        self.process_tag_as_tlv("9F45", tag_93_ssad_decrypted[3..5].to_vec());

        Ok(())
    }

    pub fn handle_dynamic_data_authentication(&mut self) -> Result<(), EmvError> {
        let mut auth_data: Vec<u8> = Vec::new();

        // fDDA is a contactless transaction, a contact transaction does DDA also when the card has Card Authentication Related Data
        let tag_9f69 = if self.contactless {
            self.get_tag_value("9F69")
        } else {
            None
        };
        if let Some(tag_9f69_card_authentication_related_data) = tag_9f69 {
            // ref. EMV Contactless Book C-3, Annex C Fast Dynamic Data Authentication (fDDA)
            // ref. EMV Contactless Book C-7, Annex B Fast Dynamic Data Authentication (fDDA)

            debug!("Perform Fast Dynamic Data Authentication (fDDA):");

            if tag_9f69_card_authentication_related_data.first() != Some(&0x01) {
                return Err(warned(EmvError::authentication(format!(
                    "fDDA version not recognized:{:02X?}",
                    tag_9f69_card_authentication_related_data.first()
                ))));
            }

            auth_data.extend_from_slice(&self.require_tag("9F37")?[..]);
            auth_data.extend_from_slice(&self.require_tag("9F02")?[..]);
            auth_data.extend_from_slice(&self.require_tag("5F2A")?[..]);
            auth_data.extend_from_slice(&tag_9f69_card_authentication_related_data[..]);
        } else {
            debug!("Perform Dynamic Data Authentication (DDA):");

            let ddol_default_value = b"\x9f\x37\x04".to_vec();
            let tag_9f49_ddol = match self.get_tag_value("9F49") {
                Some(ddol) => ddol,
                // fall-back to a default DDOL
                None => &ddol_default_value,
            };

            let ddol_data = DataObjectList::process_data_object_list(self, &tag_9f49_ddol[..])?
                .get_tag_list_tag_values(self);

            auth_data.extend_from_slice(&ddol_data[..]);

            self.internal_authenticate(&auth_data)?;
        }

        let tag_9f4b_signed_data_decrypted_dynamic_data =
            self.validate_signed_dynamic_application_data(&auth_data[..])?;

        // ICC Dynamic Data = ICC Dynamic Number length || ICC Dynamic Number, ref. EMV Book 2, 6.5.2
        let icc_dynamic_number_length = tag_9f4b_signed_data_decrypted_dynamic_data
            .first()
            .copied()
            .unwrap_or(0) as usize;
        if !(2..=8).contains(&icc_dynamic_number_length)
            || tag_9f4b_signed_data_decrypted_dynamic_data.len() < 1 + icc_dynamic_number_length
        {
            return Err(warned(EmvError::authentication(format!(
                "Invalid ICC Dynamic Number length: {}",
                icc_dynamic_number_length
            ))));
        }
        let tag_9f4c_icc_dynamic_number =
            &tag_9f4b_signed_data_decrypted_dynamic_data[1..1 + icc_dynamic_number_length];
        self.process_tag_as_tlv("9F4C", tag_9f4c_icc_dynamic_number.to_vec());

        Ok(())
    }

    /// INTERNAL AUTHENTICATE with the authentication-related data, EMV Book 3, 6.5.9. The Signed Dynamic Application Data of
    /// the response is data object '9F4B'.
    pub fn internal_authenticate(&mut self, auth_data: &[u8]) -> Result<ApduResponse, EmvError> {
        let apdu_command_internal_authenticate = b"\x00\x88\x00\x00";
        let mut internal_authenticate_command = apdu_command_internal_authenticate.to_vec();
        internal_authenticate_command.push(auth_data.len() as u8);
        internal_authenticate_command.extend_from_slice(&auth_data[..]);
        internal_authenticate_command.push(0x00);

        let response = self.send_apdu(&internal_authenticate_command)?;
        if !response.is_success() {
            return Err(EmvConnection::card_status_error(
                "INTERNAL AUTHENTICATE",
                &response,
            ));
        }

        // Format 1: Signed Dynamic Application Data in tag '80'
        match response.data.first() {
            Some(0x80) if response.data.len() > 3 => {
                self.process_tag_as_tlv("9F4B", response.data[3..].to_vec());
            }
            Some(0x77) => {}
            _ => {
                return Err(warned(EmvError::invalid(
                    "Unrecognized INTERNAL AUTHENTICATE response",
                )));
            }
        }

        Ok(response)
    }

    /// Terminal data objects of the settings, GET PROCESSING OPTIONS and the reading of the application data, and the public
    /// keys of the application
    pub fn start_transaction(&mut self, application: &EmvApplication) -> Result<(), EmvError> {
        self.process_settings()?;

        self.handle_get_processing_options()?;

        self.handle_public_keys(application)?;

        Ok(())
    }

    fn pin_entry(&self) -> Result<String, EmvError> {
        match &self.pin_callback {
            Some(pin_callback) => pin_callback(),
            None => Err(warned(EmvError::Callback("No PIN entry".to_string()))),
        }
    }

    /// Amount, Authorised (Numeric) of the transaction
    fn amount_authorised(&self) -> Result<u64, EmvError> {
        let tag_9f02 = self.require_tag("9F02")?;
        bcdutil::bcd_to_ascii(&tag_9f02[..])
            .ok()
            .and_then(|ascii| str::from_utf8(&ascii).ok()?.parse::<u64>().ok())
            .ok_or_else(|| {
                warned(EmvError::invalid(format!(
                    "Invalid amount {:02X?}",
                    tag_9f02
                )))
            })
    }

    /// Cardholder Verification, EMV Book 3, 10.5: the CV Rules of the CVM List are processed in order with the PIN of
    /// pin_callback. The CVM Results are data object '9F34'.
    pub fn handle_card_verification_methods(&mut self) -> Result<(), EmvError> {
        let purchase_amount = self.amount_authorised()?;

        // EMV Contactless Book C-2, 5: Kernel 2 has no VERIFY command, so offline PIN is not supported in a Kernel 2 transaction.
        // Kernel 2 is identified by Kernel Identifier '02' of the PPSE directory entry.
        let kernel_2 = self.contactless && self.kernel_identifier.as_deref() == Some(&[0x02][..]);
        let offline_pin_supported = !kernel_2
            || self
                .settings
                .terminal
                .protocol_deviations
                .kernel_2_offline_pin;
        if kernel_2 && offline_pin_supported {
            warn!("Offline PIN in a Kernel 2 transaction, a protocol deviation");
        }

        let cvm_rules = self.icc.cvm_rules.clone();
        for rule in cvm_rules {
            let mut skip_if_not_supported = false;
            let mut success = false;

            match rule.condition {
                CvmConditionCode::UnattendedCash
                | CvmConditionCode::ManualCash
                | CvmConditionCode::PurchaseWithCashback => {
                    // TODO: conditions currently never supported, maybe should implement it more flexible
                    continue;
                }
                CvmConditionCode::CvmSupported => {
                    skip_if_not_supported = true;
                }
                // TODO: verify that ICC and terminal currencies are the same or provide conversion
                CvmConditionCode::IccCurrencyUnderX => {
                    if purchase_amount >= rule.amount_x as u64 {
                        continue;
                    }
                }
                CvmConditionCode::IccCurrencyOverX => {
                    if purchase_amount <= rule.amount_x as u64 {
                        continue;
                    }
                }
                CvmConditionCode::IccCurrencyUnderY => {
                    if purchase_amount >= rule.amount_y as u64 {
                        continue;
                    }
                }
                CvmConditionCode::IccCurrencyOverY => {
                    if purchase_amount <= rule.amount_y as u64 {
                        continue;
                    }
                }
                _ => (),
            }

            match rule.code {
                Err(code) => {
                    debug!("CVM {:02X} not recognised", code);
                    self.state.tvr.unrecognised_cvm = true;
                    success = false;
                }
                Ok(CvmCode::FailCvmProcessing) => success = false,
                Ok(CvmCode::EncipheredPinOnline) => {
                    debug!("Enciphered PIN online is not supported");

                    if skip_if_not_supported {
                        continue;
                    }

                    success = false;
                }
                Ok(CvmCode::PlaintextPin)
                | Ok(CvmCode::PlaintextPinAndSignature)
                | Ok(CvmCode::EncipheredPinOffline)
                | Ok(CvmCode::EncipheredPinOfflineAndSignature) => {
                    let enciphered_pin = match rule.code {
                        Ok(CvmCode::EncipheredPinOffline)
                        | Ok(CvmCode::EncipheredPinOfflineAndSignature) => true,
                        _ => false,
                    };

                    if !offline_pin_supported {
                        debug!("Offline PIN is not supported in a Kernel 2 transaction");

                        if skip_if_not_supported {
                            continue;
                        }

                        success = false;
                    } else if enciphered_pin
                        && self.settings.terminal.capabilities.enciphered_pin
                        && self.icc.icc_pin_pk.is_none()
                    {
                        // The PIN can not be enciphered, the cardholder is not asked for it (EMV Book 2, 7.1)
                        warn!("ICC PIN Encipherment public key missing, offline enciphered PIN is unsuccessful");
                        success = false;
                    } else if enciphered_pin && self.settings.terminal.capabilities.enciphered_pin {
                        let ascii_pin = self.pin_entry()?;
                        success = match self.handle_verify_enciphered_pin(ascii_pin.as_bytes()) {
                            Ok(_) => true,
                            Err(_) => false,
                        };
                    } else if self.settings.terminal.capabilities.plaintext_pin {
                        let ascii_pin = self.pin_entry()?;
                        success = match self.handle_verify_plaintext_pin(ascii_pin.as_bytes()) {
                            Ok(_) => true,
                            Err(_) => false,
                        };
                    } else if skip_if_not_supported {
                        continue;
                    }
                }
                Ok(CvmCode::Signature) | Ok(CvmCode::NoCvm) => {
                    success = true;
                }
            }

            if success {
                self.state.tvr.cardholder_verification_was_not_successful = false;
                self.process_tag_as_tlv("9F34", CvmRule::into_9f34_value(Ok(rule)));
                break;
            } else {
                self.state.tvr.cardholder_verification_was_not_successful = true;
                self.process_tag_as_tlv("9F34", CvmRule::into_9f34_value(Err(rule)));

                // EMV Book 3, 10.5: b7 of the CVM Code, apply the succeeding CV Rule if this CVM is unsuccessful. A CVM that the
                // terminal does not support with condition 'if terminal supports the CVM' is skipped before this.
                if rule.fail_if_unsuccessful {
                    break;
                }
            }
        }

        self.state.tsi.cardholder_verification_was_performed = true;

        if !self.get_tag_value("9F34").is_some() {
            self.state.tvr.cardholder_verification_was_not_successful = true;

            // "no CVM performed"
            self.process_tag_as_tlv("9F34", b"\x3F\x00\x01".to_vec());
        }

        Ok(())
    }

    pub fn handle_terminal_risk_management(&mut self) -> Result<(), EmvError> {
        //ref. EMV 4.3 Book 3 - 10.6 Terminal Risk Management
        //risk management for online transaction:
        //- check terminal floor limit
        //- random transaction selection; select a transaction randomly for online authorization
        //- velocity checking; check offline transaction counter / limits from the card

        Ok(())
    }

    pub fn handle_offline_data_authentication(&mut self) -> Result<(), EmvError> {
        //ref. EMV 4.3 Book 3 - 10.3 Offline Data Authentication

        if self.settings.terminal.capabilities.cda && self.icc.capabilities.cda {
            // CDA is completed in GENERATE AC, the ICC Public Key retrieval of it is done here (EMV Book 2, 6.6.1). Without the
            // key CDA fails.
            if self.icc.icc_pk.is_none() {
                warn!("ICC public key could not be retrieved for CDA");
                self.state.tvr.cda_failed = true;
            }
        } else {
            if self.settings.terminal.capabilities.dda && self.icc.capabilities.dda {
                if let Err(_) = self.handle_dynamic_data_authentication() {
                    self.state.tvr.dda_failed = true;
                }
            } else if self.settings.terminal.capabilities.sda && self.icc.capabilities.sda {
                let data_authentication = self.icc.data_authentication.clone().unwrap_or_default();
                if let Err(_) = self.handle_signed_static_application_data(&data_authentication[..])
                {
                    self.state.tvr.sda_failed = true;
                }
            }
        }

        self.state.tsi.offline_data_authentication_was_performed = true;

        Ok(())
    }

    /// Terminal Action Analysis, EMV Book 3, 10.7: the TVR is data object '95' and the result is the cryptogram type that the
    /// Action Codes call for
    pub fn handle_terminal_action_analysis(&mut self) -> Result<CryptogramType, EmvError> {
        // ref. EMV 4.3 Book 3 - 10.7 Terminal Action Analysis
        // Terminal & Issuer Action Code - Denial => default bits 0
        // For each bit in the TVR that has a value of 1, the terminal shall check the corresponding bits in
        // the Issuer Action Code - Denial and the Terminal Action Code - Denial. If the corresponding bit in either of the action codes
        // is set to 1, it indicates that the issuer or the acquirer wishes the transaction to be rejected offlin
        //  In this case, the terminal shall issue a GENERATE AC command to request an AAC from the ICC

        // If the Issuer Action Code - Online is not present, a default value with all bits set to 1 shall be used in its place.
        // Together, the Issuer Action Code - Online and the Terminal Action Code - Online specify the conditions that cause
        // a transaction to be completed online.

        // If the Issuer Action Code - Default is not present, a default value with all bits set to 1
        //Action Code - Default are used only if the Issuer Action Code -Online and the Terminal Action Code - Online were not
        //used (for example, in case of an offline-only terminal) or indicated a desire on the part of the issuer or the acquirer
        //to process the transaction online but the terminal was unable to go online.

        let tag_95_tvr: Vec<u8> = self.state.tvr.into();
        let tvr_len = tag_95_tvr.len();
        self.process_tag_as_tlv("95", tag_95_tvr);
        debug!("{:?}", self.state.tvr);

        let action_zero: TerminalVerificationResults = vec![0x00; tvr_len].into();
        let action_one: TerminalVerificationResults = vec![0xFF; tvr_len].into();

        let tag_9f0e_issuer_action_code_denial: TerminalVerificationResults =
            match self.get_tag_value("9F0E") {
                Some(iac) => {
                    let ac: TerminalVerificationResults = iac.to_vec().into();
                    debug!("Action Code - Denial: {:?}", ac);
                    ac
                }
                None => action_zero.clone(),
            };
        let tag_9f0f_issuer_action_code_online: TerminalVerificationResults =
            match self.get_tag_value("9F0F") {
                Some(iac) => {
                    let ac: TerminalVerificationResults = iac.to_vec().into();
                    debug!("Action Code - Online: {:?}", ac);
                    ac
                }
                None => action_one.clone(),
            };
        let tag_9f0d_issuer_action_code_default = match self.get_tag_value("9F0D") {
            Some(iac) => {
                let ac: TerminalVerificationResults = iac.to_vec().into();
                debug!("Action Code - Default: {:?}", ac);
                ac
            }
            None => action_one.clone(),
        };

        let terminal_action_code_denial: TerminalVerificationResults = action_zero.clone();
        let terminal_action_code_online: TerminalVerificationResults = action_zero.clone();
        let terminal_action_code_default: TerminalVerificationResults = action_zero.clone();

        // The result is a recommendation, the cryptogram type of the first GENERATE AC is chosen by the caller (first_generate_ac)
        // or the settings (handle_1st_generate_ac)
        let cryptogram_type = if TerminalVerificationResults::action_code_matches(
            &self.state.tvr,
            &tag_9f0e_issuer_action_code_denial,
            &terminal_action_code_denial,
        ) {
            debug!("Action Code - Denial matches => GENERATE AC AAC needed");
            CryptogramType::ApplicationAuthenticationCryptogram
        } else if TerminalVerificationResults::action_code_matches(
            &self.state.tvr,
            &tag_9f0f_issuer_action_code_online,
            &terminal_action_code_online,
        ) {
            // online action codes for online capable terminals
            debug!("Action Code - Online matches => GENERATE AC ARQC needed");
            CryptogramType::AuthorisationRequestCryptogram
        } else if TerminalVerificationResults::action_code_matches(
            &self.state.tvr,
            &tag_9f0d_issuer_action_code_default,
            &terminal_action_code_default,
        ) {
            // TODO: offline-only terminals or if online authorization is not possible this is to be done
            debug!("Action Code - Default matches => GENERATE AC AAC needed");
            CryptogramType::ApplicationAuthenticationCryptogram
        } else {
            debug!("Action Codes vs. TVR are OK => GENERATE AC TC needed");
            CryptogramType::TransactionCertificate
        };

        Ok(cryptogram_type)
    }

    pub fn handle_issuer_authentication_data(&mut self) -> Result<(), EmvError> {
        // ref. EMV 4.3 Book 3 - 10.9 Online Processing
        // ref. EMV 4.3 Book 3 - 6.5.4 EXTERNAL AUTHENTICATE Command-Response APDUs

        let tag_91_issuer_authentication_data = match self.get_tag_value("91") {
            Some(data) => data.clone(),
            None => return Ok(()),
        };

        // Without issuer authentication in the AIP the ICC has combined issuer authentication with the GENERATE AC command,
        // and the terminal shall not execute the EXTERNAL AUTHENTICATE command
        if !self.icc.capabilities.issuer_authentication {
            if !self
                .settings
                .terminal
                .protocol_deviations
                .external_authenticate_without_aip_support
            {
                return Ok(());
            }
            warn!("EXTERNAL AUTHENTICATE without issuer authentication in the AIP, a protocol deviation");
        }

        debug!("Validating issuer authentication data");
        let apdu_command_external_authenticate = b"\x00\x82\x00\x00"; // EXTERNAL AUTHENTICATE
        let mut external_authenticate_command = apdu_command_external_authenticate.to_vec();
        external_authenticate_command.push(tag_91_issuer_authentication_data.len() as u8);
        external_authenticate_command.extend_from_slice(&tag_91_issuer_authentication_data[..]);

        let response = self.send_apdu(&external_authenticate_command)?;
        if !response.is_success() {
            self.state.tvr.issuer_authentication_failed = true;
        }
        self.state.tsi.issuer_authentication_was_performed = true;

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct EmvApplication {
    pub aid: Vec<u8>,
    pub label: Vec<u8>,
    pub priority: Vec<u8>,
    // Kernel Identifier (tag '9F2A') of the PPSE directory entry, EMV Contactless Book B
    pub kernel_identifier: Option<Vec<u8>>,
}

#[derive(Deserialize, Serialize, Debug, Copy, Clone)]
pub enum FieldSensitivity {
    Public,
    SensitiveAuthenticationData,
    Sensitive,
    Track2,
    PrimaryAccountNumber,
    PersonallyIdentifiableInformation,
}

#[derive(Deserialize, Serialize, Debug, Copy, Clone)]
pub enum FieldFormat {
    // Numeric (n) and compressed numeric (cn) data, EMV Book 3, 4.3
    Numeric,
    CompressedNumeric,
    Binary,
    Alphanumeric,
    AlphanumericSpecial,
    TerminalVerificationResults,
    ApplicationUsageControl,
    KeyCertificate,
    ServiceCodeIso7813,
    NumericCountryCode,
    NumericCurrencyCode,
    DataObjectList,
    Track2,
    Date,
    Time,
}

#[derive(Deserialize, Serialize, Debug, Copy, Clone)]
pub enum FieldSource {
    Icc,
    Terminal,
    Issuer,
    IssuerOrTerminal,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EmvTag {
    pub tag: String,
    pub name: String,
    pub sensitivity: Option<FieldSensitivity>,
    pub format: Option<FieldFormat>,
    pub min: Option<u8>,
    pub max: Option<u8>,
    pub source: Option<FieldSource>,
}

impl EmvTag {
    pub fn new(tag_name: &str) -> EmvTag {
        EmvTag {
            tag: tag_name.to_string(),
            name: "Unknown tag".to_string(),
            sensitivity: None,
            format: None,
            min: None,
            max: None,
            source: None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RsaPublicKey {
    pub modulus: String,
    pub exponent: String,
    sensitive: Option<bool>,
}

impl RsaPublicKey {
    pub fn new(modulus: &[u8], exponent: &[u8], sensitive: bool) -> RsaPublicKey {
        RsaPublicKey {
            modulus: hex::encode_upper(modulus),
            exponent: hex::encode_upper(exponent),
            sensitive: Some(sensitive),
        }
    }

    pub fn get_key_byte_size(&self) -> usize {
        return self.modulus.len() / 2;
    }

    /// RSA public key operation without padding, EMV Book 2, B2.1: the data is as long as the modulus and less than it, the
    /// result is as long as the modulus
    fn public_key_operation(&self, data: &[u8]) -> Result<Vec<u8>, EmvError> {
        let invalid_key = || {
            warned(EmvError::Authentication(
                "Invalid RSA public key".to_string(),
            ))
        };
        let pk_modulus_raw = hex::decode(&self.modulus).map_err(|_| invalid_key())?;
        let pk_exponent_raw = hex::decode(&self.exponent).map_err(|_| invalid_key())?;
        let pk_modulus = BigUint::from_bytes_be(&pk_modulus_raw[..]);
        let pk_exponent = BigUint::from_bytes_be(&pk_exponent_raw[..]);
        if pk_modulus.bits() == 0 || pk_exponent.bits() == 0 {
            return Err(invalid_key());
        }

        let input = BigUint::from_bytes_be(data);
        if data.len() != pk_modulus_raw.len() || input >= pk_modulus {
            return Err(warned(EmvError::authentication(format!(
                "RSA data of {} bytes does not fit the {} byte modulus",
                data.len(),
                pk_modulus_raw.len()
            ))));
        }

        let output = input.modpow(&pk_exponent, &pk_modulus).to_bytes_be();
        let mut result = vec![0u8; pk_modulus_raw.len() - output.len()];
        result.extend_from_slice(&output[..]);
        Ok(result)
    }

    pub fn public_encrypt(&self, plaintext_data: &[u8]) -> Result<Vec<u8>, EmvError> {
        let data = self.public_key_operation(plaintext_data)?;

        if let Some(true) = self.sensitive {
            trace!("Encrypt result ({} bytes)", data.len());
        } else {
            trace!(
                "Encrypt result ({} bytes):\n{}",
                data.len(),
                HexViewBuilder::new(&data[..]).finish()
            );
        }

        Ok(data)
    }

    /// Recovers the data of a certificate or signature, EMV Book 2, Annex A2: the recovered data has header '6A' and trailer 'BC'
    pub fn public_decrypt(&self, cipher_data: &[u8]) -> Result<Vec<u8>, EmvError> {
        let data = self.public_key_operation(cipher_data)?;

        if let Some(true) = self.sensitive {
            trace!("Decrypt result ({} bytes)", data.len());
        } else {
            trace!(
                "Decrypt result ({} bytes):\n{}",
                data.len(),
                HexViewBuilder::new(&data[..]).finish()
            );
        }

        if data.len() < 3 || data[0] != 0x6A {
            return Err(warned(EmvError::authentication("Data header incorrect")));
        }
        if data[data.len() - 1] != 0xBC {
            return Err(warned(EmvError::authentication("Data trailer incorrect")));
        }

        Ok(data)
    }
}

/// SHA-1 hash, EMV Book 2, B3.1
fn sha1(data: &[u8]) -> [u8; 20] {
    Sha1::digest(data).into()
}

#[derive(Serialize, Deserialize)]
pub struct CertificateAuthority {
    issuer: String,
    certificates: HashMap<String, RsaPublicKey>,
}

/// CV Rules of the CVM List (tag '8E'), EMV Book 3, 10.5
fn parse_cvm_list(tag_8e_cvm_list: &[u8]) -> Result<Vec<CvmRule>, EmvError> {
    let amount = |bcd: &[u8]| -> Result<u32, EmvError> {
        bcdutil::bcd_to_ascii(bcd)
            .ok()
            .and_then(|ascii| str::from_utf8(&ascii).ok()?.parse::<u32>().ok())
            .ok_or_else(|| {
                warned(EmvError::invalid(format!(
                    "Invalid CVM List amount {:02X?}",
                    bcd
                )))
            })
    };

    if tag_8e_cvm_list.len() < 8 || tag_8e_cvm_list.len() % 2 != 0 {
        return Err(warned(EmvError::invalid("Invalid CVM List length")));
    }

    let amount_x = amount(&tag_8e_cvm_list[0..4])?;
    let amount_y = amount(&tag_8e_cvm_list[4..8])?;

    let mut cvm_rules: Vec<CvmRule> = Vec::new();
    for cvm_rule in tag_8e_cvm_list[8..].chunks(2) {
        let cvm_code = cvm_rule[0];
        let cvm_condition_code = cvm_rule[1];

        // bit 7 = RFU
        let fail_if_unsuccessful = !get_bit!(cvm_code, 6);
        let cvm_code = (cvm_code << 2) >> 2;
        // EMV Book 3, 10.5: a CVM the terminal does not recognise is unsuccessful ('Unrecognised CVM' in TVR), a
        // CV Rule with a condition code the terminal does not understand is bypassed
        let code: Result<CvmCode, u8> = cvm_code.try_into().map_err(|_| cvm_code);
        let condition: CvmConditionCode = match cvm_condition_code.try_into() {
            Ok(condition) => condition,
            Err(_) => {
                debug!(
                    "CVM condition code {:02X} not understood, CV Rule bypassed",
                    cvm_condition_code
                );
                continue;
            }
        };

        cvm_rules.push(CvmRule {
            amount_x: amount_x,
            amount_y: amount_y,
            fail_if_unsuccessful: fail_if_unsuccessful,
            code: code,
            condition: condition,
        });
    }

    Ok(cvm_rules)
}

pub fn is_success_response(response_trailer: &Vec<u8>) -> bool {
    let mut success = false;

    if response_trailer.len() >= 2 && response_trailer[0] == 0x90 && response_trailer[1] == 0x00 {
        success = true;
    }

    success
}

fn parse_tlv(raw_data: &[u8]) -> Option<Tlv> {
    let (tlv_data, leftover_buffer) = Tlv::parse(raw_data);
    if leftover_buffer.len() > 0 {
        trace!("Could not parse as TLV: {:02X?}", leftover_buffer);
    }

    let tlv_data: Option<Tlv> = match tlv_data {
        Ok(tlv) => Some(tlv),
        Err(_) => None,
    };

    return tlv_data;
}

fn find_tlv_tag(buf: &[u8], tag: &str) -> Option<Tlv> {
    let mut read_buffer = buf;

    loop {
        let (tlv_data, leftover_buffer) = Tlv::parse(read_buffer);

        let tlv_data: Tlv = match tlv_data {
            Ok(tlv) => tlv,
            Err(err) => {
                if leftover_buffer.len() > 0 {
                    trace!(
                        "Could not parse as TLV! error:{:?}, data: {:02X?}",
                        err,
                        read_buffer
                    );
                }

                break;
            }
        };

        read_buffer = leftover_buffer;

        let tag_name = hex::encode_upper(tlv_data.tag().to_bytes());

        if tag_name.eq(tag) {
            return Some(tlv_data);
        }

        if let Value::Constructed(v) = tlv_data.value() {
            for tlv_tag in v {
                let child_tlv: Option<Tlv> = find_tlv_tag(&tlv_tag.to_vec(), tag);
                if child_tlv.is_some() {
                    return child_tlv;
                }
            }
        }

        if leftover_buffer.len() == 0 {
            break;
        }
    }

    None
}

pub fn get_ca_public_key<'a>(
    ca_data: &'a HashMap<String, CertificateAuthority>,
    rid: &[u8],
    index: &[u8],
) -> Option<&'a RsaPublicKey> {
    match ca_data.get(&hex::encode_upper(&rid)) {
        Some(ca) => match ca.certificates.get(&hex::encode_upper(&index)) {
            Some(pk) => Some(pk),
            _ => {
                warn!("No CA key defined! rid:{:02X?}, index:{:02X?}", rid, index);
                return None;
            }
        },
        _ => None,
    }
}

/// Certificate Expiration Date check result, EMV Book 2, 6.3 and 6.4
#[derive(Debug, PartialEq)]
pub enum CertificateExpiry {
    Valid,
    Expired,
    InvalidDate,
}

/// EMV Book 2, 6.3 and 6.4: a certificate is valid until the last day of the month of its Certificate Expiration Date (MMYY).
/// An invalid date is treated as expired.
pub fn is_certificate_expired(date_bcd: &[u8]) -> bool {
    check_certificate_expiry(date_bcd) != CertificateExpiry::Valid
}

/// EMV Book 2, 6.3 and 6.4: a certificate is valid until the last day of the month of its Certificate Expiration Date (MMYY)
pub fn check_certificate_expiry(date_bcd: &[u8]) -> CertificateExpiry {
    let date = hex::encode(date_bcd);
    let (Some(Ok(month)), Some(Ok(year))) = (
        date.get(0..2).map(|m| m.parse::<u32>()),
        date.get(2..4).map(|y| y.parse::<i32>()),
    ) else {
        warn!("Invalid certificate expiry date (MMYY) {:02X?}", date_bcd);
        return CertificateExpiry::InvalidDate;
    };

    // Two digit year as chrono %y: 00-68 is 2000-2068, 69-99 is 1969-1999
    let year = if year < 69 { 2000 + year } else { 1900 + year };
    let (next_month_year, next_month) = if month == 12 {
        (year + 1, 1)
    } else {
        (year, month + 1)
    };
    let first_day_after_expiry = match NaiveDate::from_ymd_opt(next_month_year, next_month, 1) {
        Some(date) if month >= 1 => date,
        _ => {
            warn!("Invalid certificate expiry date (MMYY) {:02X?}", date_bcd);
            return CertificateExpiry::InvalidDate;
        }
    };

    let today = Utc::now().date_naive();
    if today >= first_day_after_expiry {
        warn!(
            "Certificate expiry date (MMYY) {:02X?} is in the past",
            date_bcd
        );

        return CertificateExpiry::Expired;
    }

    CertificateExpiry::Valid
}

#[cfg(test)]
mod tests {
    use super::bcdutil::*;
    use super::*;
    use hex;
    use hexplay::HexViewBuilder;
    use log::{debug, LevelFilter};
    use log4rs;
    use log4rs::{
        append::console::ConsoleAppender,
        config::{Appender, Root},
    };
    use openssl::rsa::{Padding, Rsa};
    use serde::{Deserialize, Serialize};
    use std::fs::{self};
    use std::str;
    use std::sync::Once;

    static LOGGING: Once = Once::new();

    static SETTINGS_FILE: &str = "config/settings.yaml";

    #[derive(Serialize, Deserialize, Clone)]
    struct ApduRequestResponse {
        req: String,
        res: String,
    }

    impl ApduRequestResponse {
        fn to_raw_vec(s: &String) -> Vec<u8> {
            hex::decode(s.replace(" ", "")).unwrap()
        }
    }

    struct DummySmartCardConnection {
        test_data_file: String,
    }

    impl DummySmartCardConnection {
        fn find_dummy_apdu<'a>(
            test_data: &'a Vec<ApduRequestResponse>,
            apdu: &[u8],
        ) -> Option<&'a ApduRequestResponse> {
            for data in test_data {
                if &apdu[..] == &ApduRequestResponse::to_raw_vec(&data.req)[..] {
                    return Some(data);
                }
            }

            None
        }
    }

    impl ApduInterface for DummySmartCardConnection {
        fn send_apdu(&self, apdu: &[u8]) -> Result<Vec<u8>, EmvError> {
            let mut output: Vec<u8> = Vec::new();

            let mut response = b"\x6A\x82".to_vec(); // file not found error

            let test_data: Vec<ApduRequestResponse> =
                serde_yaml::from_str(&fs::read_to_string(&self.test_data_file).unwrap()).unwrap();

            if let Some(req) = DummySmartCardConnection::find_dummy_apdu(&test_data, &apdu[..]) {
                response = ApduRequestResponse::to_raw_vec(&req.res);
            }

            output.extend_from_slice(&response[..]);
            Ok(output)
        }
    }

    fn init_logging() {
        LOGGING.call_once(|| {
            let stdout: ConsoleAppender = ConsoleAppender::builder().build();
            let config = log4rs::config::Config::builder()
                .appender(Appender::builder().build("stdout", Box::new(stdout)))
                .build(Root::builder().appender("stdout").build(LevelFilter::Trace))
                .unwrap();
            log4rs::init_config(config).unwrap();
        });
    }

    #[test]
    fn test_rsa_key() -> Result<(), String> {
        init_logging();

        const KEY_SIZE: u32 = 1408;
        const KEY_BYTE_SIZE: usize = KEY_SIZE as usize / 8;

        // openssl key generation:
        // openssl genrsa -out icc_1234560012345608_e_3_private_key.pem -3 1024
        // openssl genrsa -out iin_313233343536_e_3_private_key.pem -3 1408
        // openssl genrsa -out AFFFFFFFFF_92_ca_private_key.pem -3 1408
        // openssl rsa -in AFFFFFFFFF_92_ca_private_key.pem -outform PEM -pubout -out AFFFFFFFFF_92_ca_key.pem

        let rsa = Rsa::private_key_from_pem(
            &fs::read_to_string("config/AFFFFFFFFF_92_ca_private_key.pem")
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        //let rsa = Rsa::private_key_from_pem(&fs::read_to_string("config/iin_313233343536_e_3_private_key.pem").unwrap().as_bytes()).unwrap();
        //let rsa = Rsa::private_key_from_pem(&fs::read_to_string("config/icc_1234560012345608_e_3_private_key.pem").unwrap().as_bytes()).unwrap();

        let public_key_modulus = &rsa.n().to_vec()[..];
        let public_key_exponent = &rsa.e().to_vec()[..];
        let private_key_exponent = &rsa.d().to_vec()[..];

        let pk = RsaPublicKey::new(public_key_modulus, public_key_exponent, false);
        debug!(
            "modulus: {:02X?}, exponent: {:02X?}, private_exponent: {:02X?}",
            public_key_modulus, public_key_exponent, private_key_exponent
        );

        let mut encrypt_output = [0u8; KEY_BYTE_SIZE];
        let mut plaintext_data = [0u8; KEY_BYTE_SIZE];
        plaintext_data[0] = 0x6A;
        plaintext_data[1] = 0xFF;
        plaintext_data[KEY_BYTE_SIZE - 1] = 0xBC;

        let encrypt_size = rsa
            .private_encrypt(&plaintext_data[..], &mut encrypt_output[..], Padding::NONE)
            .unwrap();

        debug!(
            "Encrypt result ({} bytes):\n{}",
            encrypt_output.len(),
            HexViewBuilder::new(&encrypt_output[..]).finish()
        );

        let decrypted_data = pk.public_decrypt(&encrypt_output[0..encrypt_size]).unwrap();

        assert_eq!(&plaintext_data[..], &decrypted_data[..]);

        Ok(())
    }

    fn pse_application_select(applications: &[EmvApplication]) -> Result<EmvApplication, EmvError> {
        Ok(applications[0].clone())
    }

    fn pin_entry() -> Result<String, EmvError> {
        Ok("1234".to_string())
    }

    fn amount_entry() -> Result<u64, EmvError> {
        Ok(1)
    }

    /// Terminal data of the test card transaction, set after the application selection that clears the data objects
    fn set_test_terminal_data(connection: &mut EmvConnection) {
        // force transaction date as 24.07.2020
        connection.process_tag_as_tlv("9A", b"\x20\x07\x24".to_vec());

        // force unpreditable number
        connection.process_tag_as_tlv("9F37", b"\x01\x23\x45\x67".to_vec());
        connection.settings.terminal.use_random = false;

        // force issuer authentication data
        connection.process_tag_as_tlv("91", b"\x12\x34\x56\x78\x12\x34\x56\x78".to_vec());
    }

    fn start_transaction(
        connection: &mut EmvConnection,
        application: &EmvApplication,
    ) -> Result<(), EmvError> {
        set_test_terminal_data(connection);
        connection.start_transaction(application)
    }

    fn setup_connection(connection: &mut EmvConnection) -> Result<(), EmvError> {
        connection.contactless = false;
        connection.pse_application_select_callback = Some(Box::new(pse_application_select));
        connection.pin_callback = Some(Box::new(pin_entry));

        Ok(())
    }

    fn test_card() -> Box<DummySmartCardConnection> {
        Box::new(DummySmartCardConnection {
            test_data_file: "test_data.yaml".to_string(),
        })
    }

    #[test]
    fn test_get_data() -> Result<(), EmvError> {
        init_logging();

        let mut connection = EmvConnection::new(SETTINGS_FILE).unwrap();
        connection.interface = Some(test_card());
        setup_connection(&mut connection)?;

        connection.select_payment_application()?;

        let search_tag = b"\x9f\x36";
        connection.handle_get_data(&search_tag[..])?;

        Ok(())
    }

    #[test]
    fn test_pin_verification_methods() -> Result<(), EmvError> {
        init_logging();

        let mut connection = EmvConnection::new(SETTINGS_FILE).unwrap();
        connection.interface = Some(test_card());
        setup_connection(&mut connection)?;

        let application = connection.select_payment_application()?;

        start_transaction(&mut connection, &application).unwrap();

        let ascii_pin = pin_entry()?;

        connection.handle_verify_plaintext_pin(ascii_pin.as_bytes())?;
        connection.handle_verify_enciphered_pin(ascii_pin.as_bytes())?;

        Ok(())
    }

    #[test]
    fn test_purchase_transaction() -> Result<(), EmvError> {
        init_logging();

        let mut connection = EmvConnection::new(SETTINGS_FILE).unwrap();
        connection.interface = Some(test_card());
        setup_connection(&mut connection)?;

        let amount = amount_entry()?;

        let application = connection.select_payment_application()?;

        start_transaction(&mut connection, &application)?;

        connection.process_tag_as_tlv(
            "9F02",
            ascii_to_bcd_n(format!("{}", amount).as_bytes(), 6).unwrap(),
        );

        connection.handle_card_verification_methods()?;

        connection.handle_terminal_risk_management()?;

        connection.handle_offline_data_authentication()?;

        connection.handle_terminal_action_analysis()?;

        match connection.handle_1st_generate_ac()? {
            CryptogramType::AuthorisationRequestCryptogram => {
                connection.handle_issuer_authentication_data()?;
                assert!(!connection.state.tvr.issuer_authentication_failed);

                match connection.handle_2nd_generate_ac()? {
                    CryptogramType::AuthorisationRequestCryptogram => {
                        panic!("Unexpected cryptogram type");
                    }
                    CryptogramType::TransactionCertificate => { /* Expected */ }
                    CryptogramType::ApplicationAuthenticationCryptogram => {
                        panic!("Unexpected cryptogram type");
                    }
                }
            }
            CryptogramType::TransactionCertificate => {
                panic!("For test case 2ND GEN AC TC is expected");
            }
            CryptogramType::ApplicationAuthenticationCryptogram => {
                panic!("Unexpected AAC");
            }
        }

        Ok(())
    }

    #[test]
    fn test_data_object_list_processing() -> Result<(), EmvError> {
        let mut connection = EmvConnection::new(SETTINGS_FILE).unwrap();

        let cdol1: [u8; 39] = [
            //tag       length
            0x9F, 0x02, 0x06, 0x9F, 0x03, 0x06, 0x9F, 0x1A, 0x02, 0x95, 0x05, 0x5F, 0x2A, 0x02,
            0x9A, 0x03, 0x9C, 0x01, 0x9F, 0x37, 0x04, 0x9F, 0x35, 0x01, 0x9F, 0x45, 0x02, 0x9F,
            0x4C, 0x08, 0x9F, 0x34, 0x03, 0x9F, 0x21, 0x03, 0x9F, 0x7C, 0x14,
        ];

        let dol1: DataObjectList =
            DataObjectList::process_data_object_list(&connection, &cdol1).unwrap();

        // Check zero padded DOL
        let dol1_output: Vec<u8> = dol1.get_tag_list_tag_values(&connection);
        assert_eq!(&dol1_output[..], [0; 66]);

        // Fill couple of tags with information
        connection.process_tag_as_tlv(
            "9F02",
            ascii_to_bcd_n(format!("{}", 123456).as_bytes(), 6).unwrap(),
        );
        connection.process_tag_as_tlv("9C", [0xFF].to_vec());

        let tag_82_data: [u8; 2] = [0x39, 0x00];

        connection.process_tag_as_tlv("82", tag_82_data.to_vec());

        let dol1_output2: Vec<u8> = dol1.get_tag_list_tag_values(&connection);
        assert_eq!(
            &dol1_output2[..],
            [
                0, 0, 0, 18, 52, 86, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );

        // Curious case of static data authentication list (9F4A) which slightly differs from regular DOL by not providing tag length
        let static_data_authentication_list: [u8; 1] = [0x82];
        let static_dol1: DataObjectList =
            DataObjectList::process_data_object_list(&connection, &static_data_authentication_list)
                .unwrap();
        let static_data_authentication_list_output: Vec<u8> =
            static_dol1.get_tag_list_tag_values(&connection);
        assert_eq!(&static_data_authentication_list_output[..], tag_82_data);

        Ok(())
    }

    #[test]
    fn test_track2_without_discretionary_data() {
        // Track 2 Equivalent Data: PAN, separator, expiry date and service code, the discretionary data may be empty
        let track2 = Track2::parse("6263600221180611D2212206").unwrap();
        assert_eq!(track2.primary_account_number, "6263600221180611");
        assert_eq!(track2.service_code, "206");
        assert_eq!(track2.discretionary_data, "");
        assert!(Track2::parse("not track 2").is_none());
    }

    #[test]
    fn test_cvm_results_of_unrecognised_cvm() {
        // EMV Book 4, A4: CVM Results of a failed CVM that the terminal does not recognise, b7 'apply succeeding CV Rule'
        let rule = CvmRule {
            amount_x: 0,
            amount_y: 0,
            fail_if_unsuccessful: false,
            code: Err(0x20),
            condition: CvmConditionCode::Always,
        };
        assert_eq!(CvmRule::into_9f34_value(Err(rule)), vec![0x60, 0x00, 0x01]);
    }

    #[test]
    fn test_cvm_processing_continues_after_unsuccessful_cvm() -> Result<(), EmvError> {
        init_logging();

        let mut connection = EmvConnection::new(SETTINGS_FILE).unwrap();
        connection.process_tag_as_tlv("9F02", b"\x00\x00\x00\x00\x01\x00".to_vec());
        connection.settings.terminal.capabilities.enciphered_pin = true;
        // Enciphered PIN by ICC, apply succeeding CV Rule if unsuccessful (b7), without an ICC PIN Encipherment key, then a
        // CVM that the terminal does not recognise and Signature
        let rule = |code: Result<CvmCode, u8>, fail_if_unsuccessful: bool| CvmRule {
            amount_x: 0,
            amount_y: 0,
            fail_if_unsuccessful: fail_if_unsuccessful,
            code: code,
            condition: CvmConditionCode::Always,
        };
        connection.icc.cvm_rules = vec![
            rule(Ok(CvmCode::EncipheredPinOffline), false),
            rule(Err(0x20), false),
            rule(Ok(CvmCode::Signature), true),
        ];

        connection.handle_card_verification_methods()?;

        assert_eq!(
            connection.get_tag_value("9F34").unwrap(),
            &vec![0x1E, 0x00, 0x00]
        );
        assert!(connection.state.tvr.unrecognised_cvm);
        assert!(
            !connection
                .state
                .tvr
                .cardholder_verification_was_not_successful
        );

        Ok(())
    }

    #[test]
    fn test_tvr_relay_resistance() {
        let tvr = TerminalVerificationResults::from(b"\x00\x00\x00\x00\x06".to_vec());
        assert!(!tvr.relay_resistance_threshold_exceeded);
        assert!(tvr.relay_resistance_time_limits_exceeded);
        assert_eq!(
            tvr.relay_resistance_performed,
            RelayResistancePerformed::Performed
        );
        assert_eq!(Vec::<u8>::from(tvr), b"\x00\x00\x00\x00\x06".to_vec());

        let tvr = TerminalVerificationResults::from(b"\x00\x00\x00\x00\x09".to_vec());
        assert!(tvr.relay_resistance_threshold_exceeded);
        assert_eq!(
            tvr.relay_resistance_performed,
            RelayResistancePerformed::NotPerformed
        );
        assert_eq!(Vec::<u8>::from(tvr), b"\x00\x00\x00\x00\x09".to_vec());
    }

    #[test]
    fn test_track2_human_readable() -> Result<(), EmvError> {
        let track2_data = ";4321432143214321=2612101123456789123?";
        let track2_data_censored = ";43214321****4321=2612101************?";

        let mut track2: Track2 = Track2::new(track2_data);
        assert_eq!(format!("{}", track2), track2_data);

        assert_eq!(track2.primary_account_number, "4321432143214321");
        assert_eq!(track2.expiry_year, "26");
        assert_eq!(track2.expiry_month, "12");
        assert_eq!(track2.service_code, "101");
        assert_eq!(track2.discretionary_data, "123456789123");

        track2.censor();
        assert_eq!(format!("{}", track2), track2_data_censored);
        assert_eq!(track2.primary_account_number, "43214321****4321");
        assert_eq!(track2.discretionary_data, "************");

        Ok(())
    }

    #[test]
    fn test_track2_icc() -> Result<(), EmvError> {
        let track2_data = "4321432143214321D2612101123456789123F";
        let track2_data_formatted = ";4321432143214321=2612101123456789123?";
        let track2_data_censored = ";43214321****4321=2612101************?";

        let mut track2: Track2 = Track2::new(track2_data);
        assert_eq!(format!("{}", track2), track2_data_formatted);

        assert_eq!(track2.primary_account_number, "4321432143214321");
        assert_eq!(track2.expiry_year, "26");
        assert_eq!(track2.expiry_month, "12");
        assert_eq!(track2.service_code, "101");
        assert_eq!(track2.discretionary_data, "123456789123");

        track2.censor();
        assert_eq!(format!("{}", track2), track2_data_censored);
        assert_eq!(track2.primary_account_number, "43214321****4321");
        assert_eq!(track2.discretionary_data, "************");

        Ok(())
    }

    #[test]
    fn test_track1() -> Result<(), EmvError> {
        let track1_data = "%B4321432143214321^Mc'Doe/JOHN^2609101123456789012345678901234?";
        let track1_data_censored =
            "%B43214321****4321^******/****^2609101************************?";

        let mut track1: Track1 = Track1::new(track1_data);
        assert_eq!(format!("{}", track1), track1_data);

        assert_eq!(track1.primary_account_number, "4321432143214321");
        assert_eq!(track1.last_name, "Mc'Doe");
        assert_eq!(track1.first_name, "JOHN");
        assert_eq!(track1.expiry_year, "26");
        assert_eq!(track1.expiry_month, "09");
        assert_eq!(track1.service_code, "101");
        assert_eq!(track1.discretionary_data, "123456789012345678901234");

        track1.censor();
        assert_eq!(format!("{}", track1), track1_data_censored);
        assert_eq!(track1.primary_account_number, "43214321****4321");
        assert_eq!(track1.last_name, "******");
        assert_eq!(track1.first_name, "****");
        assert_eq!(track1.discretionary_data, "************************");

        Ok(())
    }

    #[test]
    fn test_bcd_conversion() -> Result<(), EmvError> {
        let empty1: Vec<u8> = [].to_vec();
        assert_eq!(
            str::from_utf8(&bcdutil::bcd_to_ascii(&empty1[..]).unwrap()).unwrap(),
            ""
        );

        let empty2: Vec<u8> = [0xFF, 0xFF].to_vec();
        assert_eq!(
            str::from_utf8(&bcdutil::bcd_to_ascii(&empty2[..]).unwrap()).unwrap(),
            ""
        );

        let pan1: Vec<u8> = [0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x77, 0x77].to_vec();
        assert_eq!(
            str::from_utf8(&bcdutil::bcd_to_ascii(&pan1[..]).unwrap()).unwrap(),
            "4444555566667777"
        );

        let pan2: Vec<u8> = [0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x77, 0x78, 0xFF].to_vec();
        assert_eq!(
            str::from_utf8(&bcdutil::bcd_to_ascii(&pan2[..]).unwrap()).unwrap(),
            "4444555566667778"
        );

        let pan3: Vec<u8> = [0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x77, 0x7F].to_vec();
        assert_eq!(
            str::from_utf8(&bcdutil::bcd_to_ascii(&pan3[..]).unwrap()).unwrap(),
            "444455556666777"
        );

        let pan4: Vec<u8> = [0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x77, 0x77, 0x88, 0x8F].to_vec();
        assert_eq!(
            str::from_utf8(&bcdutil::bcd_to_ascii(&pan4[..]).unwrap()).unwrap(),
            "4444555566667777888"
        );

        let not_bcd1: Vec<u8> = [0x44, 0x44, 0xAB, 0x55].to_vec();
        assert_eq!(bcdutil::bcd_to_ascii(&not_bcd1[..]).is_ok(), false);

        let not_bcd2: Vec<u8> = [0x44, 0x44, 0xF4].to_vec();
        assert_eq!(bcdutil::bcd_to_ascii(&not_bcd2[..]).is_ok(), false);

        Ok(())
    }

    /// Test card of test_data.yaml with some responses replaced
    struct ModifiedSmartCardConnection {
        card: DummySmartCardConnection,
        responses: Vec<(Vec<u8>, Vec<u8>)>,
    }

    impl ApduInterface for ModifiedSmartCardConnection {
        fn send_apdu(&self, apdu: &[u8]) -> Result<Vec<u8>, EmvError> {
            for (request, response) in &self.responses {
                if &apdu[..] == &request[..] {
                    return Ok(response.clone());
                }
            }
            self.card.send_apdu(apdu)
        }
    }

    fn modified_card(responses: Vec<(&str, &str)>) -> ModifiedSmartCardConnection {
        ModifiedSmartCardConnection {
            card: DummySmartCardConnection {
                test_data_file: "test_data.yaml".to_string(),
            },
            responses: responses
                .iter()
                .map(|(req, res)| {
                    (
                        ApduRequestResponse::to_raw_vec(&req.to_string()),
                        ApduRequestResponse::to_raw_vec(&res.to_string()),
                    )
                })
                .collect(),
        }
    }

    /// Response of a request in test_data.yaml
    fn test_data_response(request: &str) -> Vec<u8> {
        let test_data: Vec<ApduRequestResponse> =
            serde_yaml::from_str(&fs::read_to_string("test_data.yaml").unwrap()).unwrap();
        let request = ApduRequestResponse::to_raw_vec(&request.to_string());
        let data = DummySmartCardConnection::find_dummy_apdu(&test_data, &request).unwrap();
        ApduRequestResponse::to_raw_vec(&data.res)
    }

    #[test]
    fn test_data_object_list_padding() {
        let mut connection = EmvConnection::new(SETTINGS_FILE).unwrap();
        // Numeric (n) Amount, Authorised, compressed numeric (cn) PAN, binary Issuer Authentication Data and TTQ
        connection.process_tag_as_tlv("9F02", b"\x12\x34".to_vec());
        connection.process_tag_as_tlv("5A", b"\x12\x34\x56\x78\x90\x12\x34\x56".to_vec());
        connection.process_tag_as_tlv("91", b"\x11\x22\x33\x44\x55\x66\x77\x88".to_vec());
        connection.process_tag_as_tlv("9F66", b"\x36\x00\x40\x00".to_vec());

        // EMV Book 3, 5.4: shorter numeric data is padded with leading zeros, compressed numeric with trailing 'F's, others
        // with trailing zeros
        let dol = DataObjectList::process_data_object_list(
            &connection,
            b"\x9F\x02\x06\x5A\x0A\x91\x10\x9F\x66\x04",
        )
        .unwrap();
        assert_eq!(
            hex::encode_upper(dol.get_tag_list_tag_values(&connection)),
            "000000001234".to_string()
                + "1234567890123456FFFF"
                + "11223344556677880000000000000000"
                + "36004000"
        );

        // Longer numeric data is truncated keeping the rightmost bytes, others keeping the leftmost bytes
        let dol = DataObjectList::process_data_object_list(
            &connection,
            b"\x9F\x02\x01\x91\x04\x9F\x66\x02",
        )
        .unwrap();
        assert_eq!(
            hex::encode_upper(dol.get_tag_list_tag_values(&connection)),
            "34112233443600"
        );
    }

    #[test]
    fn test_certificate_expiry() {
        assert!(is_certificate_expired(b"\x12\x20"));
        assert!(!is_certificate_expired(b"\x12\x68"));

        // Valid until the last day of the expiry month
        let today = Utc::now().date_naive();
        let this_month = hex::decode(today.format("%m%y").to_string()).unwrap();
        assert!(!is_certificate_expired(&this_month));

        assert!(is_certificate_expired(b"\x13\x30"));
        assert!(is_certificate_expired(b"\x00\x30"));
        assert!(is_certificate_expired(b"\xFF\x12"));
    }

    #[test]
    fn test_ignore_certificate_expiry() {
        init_logging();

        // Enabled by default, also without the setting or the protocol_deviations section
        assert!(ProtocolDeviations::default().ignore_certificate_expiry);
        let deviations: ProtocolDeviations =
            serde_yaml::from_str("accept_higher_cryptogram_type: false").unwrap();
        assert!(deviations.ignore_certificate_expiry);

        let mut connection = EmvConnection::new(SETTINGS_FILE).unwrap();
        connection
            .settings
            .terminal
            .protocol_deviations
            .ignore_certificate_expiry = true;
        assert!(connection
            .check_public_key_certificate_expiry("Issuer Public Key Certificate", b"\x12\x20")
            .is_ok());
        assert!(connection
            .check_public_key_certificate_expiry("Issuer Public Key Certificate", b"\x12\x68")
            .is_ok());
        // Only an expired certificate is accepted, not an invalid date
        assert!(connection
            .check_public_key_certificate_expiry("Issuer Public Key Certificate", b"\x13\x30")
            .is_err());

        connection
            .settings
            .terminal
            .protocol_deviations
            .ignore_certificate_expiry = false;
        assert!(connection
            .check_public_key_certificate_expiry("ICC Public Key Certificate", b"\x12\x20")
            .is_err());
        assert!(connection
            .check_public_key_certificate_expiry("ICC Public Key Certificate", b"\x12\x68")
            .is_ok());
    }

    #[test]
    fn test_unknown_country_code() {
        init_logging();

        let mut connection = EmvConnection::new(SETTINGS_FILE).unwrap();
        // Issuer Country Code that is not in the constants is logged as unknown
        connection.process_tag_as_tlv("5F28", b"\x09\x00".to_vec());
        connection.process_tag_as_tlv("9F42", b"\x09\x99".to_vec());
        assert_eq!(
            connection.get_tag_value("5F28").unwrap(),
            &b"\x09\x00".to_vec()
        );
    }

    #[test]
    fn test_contactless_arqc_has_no_second_generate_ac() -> Result<(), EmvError> {
        init_logging();

        // Without a card interface any APDU would panic, a contactless transaction has no second GENERATE AC (no CDOL2)
        let mut connection = EmvConnection::new(SETTINGS_FILE).unwrap();
        connection.contactless = true;

        connection.process_tag_as_tlv("8A", b"Y3".to_vec());
        assert!(matches!(
            connection.handle_2nd_generate_ac()?,
            CryptogramType::TransactionCertificate
        ));

        connection.process_tag_as_tlv("8A", b"Z3".to_vec());
        assert!(matches!(
            connection.handle_2nd_generate_ac()?,
            CryptogramType::ApplicationAuthenticationCryptogram
        ));

        Ok(())
    }

    #[test]
    fn test_list_of_aids_without_pse() -> Result<(), EmvError> {
        init_logging();

        // The card has no PSE, the terminal AID 'AFFFFFFFFF' matches the card application 'AFFFFFFFFF1234' partially and
        // 'A0000000031010' is not found
        let card = modified_card(vec![
            (
                "00 A4 04 00 0E 31 50 41 59 2E 53 59 53 2E 44 44 46 30 31 00",
                "6A 82",
            ),
            (
                "00 A4 04 00 05 AF FF FF FF FF 00",
                "6F 39 84 07 AF FF FF FF FF 12 34 A5 2E 50 0D 56 45 53 41 20 45 4C 45 43 54 52 4F 4E 5F 2D 02 65 6E 87 01 01 9F 12 10 56 45 53 41 20 20 20 20 20 20 20 20 20 20 20 20 9F 11 01 01 90 00",
            ),
        ]);

        let mut connection = EmvConnection::new(SETTINGS_FILE).unwrap();
        connection.interface = Some(Box::new(card));
        setup_connection(&mut connection)?;
        connection.settings.terminal.application_identifiers =
            vec!["A0000000031010".to_string(), "AFFFFFFFFF".to_string()];

        let application = connection.select_payment_application()?;
        assert_eq!(application.aid, b"\xAF\xFF\xFF\xFF\xFF\x12\x34".to_vec());
        assert_eq!(application.label, b"VESA ELECTRON".to_vec());
        assert_eq!(application.priority, b"\x01".to_vec());

        Ok(())
    }

    #[test]
    fn test_get_processing_options_without_afl() -> Result<(), EmvError> {
        init_logging();

        let mut connection = EmvConnection::new(SETTINGS_FILE).unwrap();
        // GET PROCESSING OPTIONS response format 2 without AFL
        let card = modified_card(vec![("00 C0 00 00 10", "77 04 82 02 00 00 90 00")]);
        connection.interface = Some(Box::new(card));
        setup_connection(&mut connection)?;

        let application = connection.select_payment_application()?;
        start_transaction(&mut connection, &application)?;

        assert!(connection.get_tag_value("94").is_none());
        assert_eq!(connection.icc.data_authentication, Some(Vec::new()));

        Ok(())
    }

    #[test]
    fn test_get_processing_options_invalid_response() -> Result<(), EmvError> {
        init_logging();

        // EMV Book 3, 6.5.8.4 and 10.2: the transaction is terminated, not panicked, when the AIP is missing or invalid, the
        // Format 1 response is too short or an AFL entry is not 4 bytes
        for response in [
            "77 00 90 00",
            "77 04 94 04 08 01 01 00 90 00",
            "77 03 82 01 00 90 00",
            "80 01 00 90 00",
            "77 07 82 02 00 00 94 01 08 90 00",
            "90 00",
        ] {
            let mut connection = EmvConnection::new(SETTINGS_FILE).unwrap();
            let card = modified_card(vec![("00 C0 00 00 10", response)]);
            connection.interface = Some(Box::new(card));
            setup_connection(&mut connection)?;

            let application = connection.select_payment_application()?;
            assert!(
                start_transaction(&mut connection, &application).is_err(),
                "GET PROCESSING OPTIONS response {}",
                response
            );
        }

        Ok(())
    }

    #[test]
    fn test_contact_dda_with_card_authentication_related_data() -> Result<(), EmvError> {
        init_logging();

        let mut connection = EmvConnection::new(SETTINGS_FILE).unwrap();
        connection.interface = Some(test_card());
        setup_connection(&mut connection)?;

        let application = connection.select_payment_application()?;
        start_transaction(&mut connection, &application)?;

        // Card Authentication Related Data of fDDA does not change a contact transaction to fDDA
        connection.process_tag_as_tlv("9F69", b"\x01\x00\x00\x00\x00\x00\x00".to_vec());
        connection.handle_offline_data_authentication()?;

        assert!(!connection.state.tvr.dda_failed);
        assert!(connection.get_tag_value("9F4C").is_some());

        Ok(())
    }

    #[test]
    fn test_icc_certificate_mismatch() -> Result<(), EmvError> {
        init_logging();

        // ICC Public Key Certificate in SFI 2 record 1 with a modified byte
        let mut record = test_data_response("00 B2 01 14 C1");
        record[20] ^= 0x01;
        let record = hex::encode_upper(record);

        let mut connection = EmvConnection::new(SETTINGS_FILE).unwrap();
        let card = modified_card(vec![("00 B2 01 14 C1", &record)]);
        connection.interface = Some(Box::new(card));
        setup_connection(&mut connection)?;

        let application = connection.select_payment_application()?;
        start_transaction(&mut connection, &application)?;
        assert!(connection.icc.issuer_pk.is_some());
        assert!(connection.icc.icc_pk.is_none());

        // EMV Book 3, 10.3: DDA has failed
        connection.handle_offline_data_authentication()?;
        assert!(connection.state.tvr.dda_failed);

        Ok(())
    }

    #[test]
    fn test_missing_ca_public_key() -> Result<(), EmvError> {
        init_logging();

        // Certification Authority Public Key Index '93' is not in the CA public keys
        let record =
            hex::encode_upper(test_data_response("00 B2 02 14 E3")).replacen("8F0192", "8F0193", 1);

        let mut connection = EmvConnection::new(SETTINGS_FILE).unwrap();
        let card = modified_card(vec![("00 B2 02 14 E3", &record)]);
        connection.interface = Some(Box::new(card));
        setup_connection(&mut connection)?;

        let application = connection.select_payment_application()?;
        start_transaction(&mut connection, &application)?;
        assert!(connection.icc.issuer_pk.is_none());

        connection.handle_offline_data_authentication()?;
        assert!(connection.state.tvr.dda_failed);

        Ok(())
    }

    #[test]
    fn test_pan_truncation() {
        assert_eq!(get_truncated_pan("0000000000000000"), "00000000****0000");
        assert_eq!(get_truncated_pan("000000000000000"), "000000*****0000");
        assert_eq!(get_truncated_pan("00000000000000"), "000000****0000");
    }

    /// Purchase transaction of test_purchase_transaction with the default steps
    fn purchase(connection: &mut EmvConnection) -> Result<CryptogramType, EmvError> {
        let application = connection.select_payment_application()?;
        start_transaction(connection, &application)?;
        connection.process_tag_as_tlv("9F02", ascii_to_bcd_n(b"1", 6).unwrap());
        connection.handle_card_verification_methods()?;
        connection.handle_terminal_risk_management()?;
        connection.handle_offline_data_authentication()?;
        connection.handle_terminal_action_analysis()?;
        match connection.handle_1st_generate_ac()? {
            CryptogramType::AuthorisationRequestCryptogram => {
                connection.handle_issuer_authentication_data()?;
                connection.handle_2nd_generate_ac()
            }
            cryptogram_type => Ok(cryptogram_type),
        }
    }

    #[test]
    fn test_connection_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<EmvConnection>();
    }

    #[test]
    fn test_bundled_configuration() -> Result<(), EmvError> {
        let connection = EmvConnection::from_configuration(ConfigurationData::default())?;
        assert!(connection.get_emv_tag("9F02").is_some());

        let invalid = ConfigurationData {
            settings: Some("terminal: [".to_string()),
            ..Default::default()
        };
        assert!(matches!(
            EmvConnection::from_configuration(invalid),
            Err(EmvError::Configuration(_))
        ));

        Ok(())
    }

    #[test]
    fn test_step_by_step_transaction() -> Result<(), EmvError> {
        init_logging();

        let mut connection = EmvConnection::new(SETTINGS_FILE)?;
        connection.interface = Some(test_card());

        // Application selection without the selection callback: the first candidate
        let applications = connection.candidate_applications()?;
        assert_eq!(applications.len(), 1);
        connection.handle_select_payment_application(&applications[0])?;

        set_test_terminal_data(&mut connection);
        connection.process_settings()?;

        // GET PROCESSING OPTIONS and reading of the application data one AFL entry at a time
        connection.get_processing_options()?;
        let entries = connection.afl_entries()?;
        assert!(!entries.is_empty());
        for entry in entries.iter() {
            connection.read_afl_entry(entry)?;
        }
        connection.process_application_data()?;
        let data_authentication = connection.icc.data_authentication.clone();

        // Same static data to be authenticated as reading all the records
        connection.read_application_data()?;
        assert_eq!(connection.icc.data_authentication, data_authentication);

        connection.handle_public_keys(&applications[0])?;
        connection.process_tag_as_tlv("9F02", ascii_to_bcd_n(b"1", 6).unwrap());

        // The TVR of the transaction state is used in the terminal action analysis, an Issuer Action Code - Online of the card
        // calls for an online authorisation
        connection.state.tvr.merchant_forced_transaction_online = true;
        assert!(matches!(
            connection.handle_terminal_action_analysis()?,
            CryptogramType::AuthorisationRequestCryptogram
        ));
        assert_eq!(connection.get_tag_value("95").unwrap()[3], 0b0000_1000);

        // A TC requested in the first GENERATE AC is not in the test card, the error has the status word of the card
        let exchanges = connection.state.exchanges.len();
        assert_eq!(
            connection.first_generate_ac(CryptogramType::TransactionCertificate),
            Err(EmvError::CardStatus {
                command: "GENERATE AC".to_string(),
                sw: [0x6A, 0x82],
            })
        );
        assert_eq!(connection.state.exchanges.len(), exchanges + 1);
        assert_eq!(
            connection.state.exchanges[exchanges].command[0..4],
            [0x80, 0xAE, 0x40, 0x00]
        );

        // A new transaction starts with the TVR of the settings
        connection.reset_transaction();
        assert!(!connection.state.tvr.merchant_forced_transaction_online);
        assert!(connection.tags.is_empty());
        assert!(connection.state.exchanges.is_empty());

        Ok(())
    }

    struct TestHook {
        exchanges: std::sync::Arc<std::sync::Mutex<Vec<ApduExchange>>>,
    }

    impl ApduHook for TestHook {
        fn on_command(&self, command: &[u8]) -> Option<Vec<u8>> {
            // GET DATA of the PIN Try Counter instead of the Application Transaction Counter
            if command == b"\x80\xCA\x9F\x36\x00" {
                return Some(b"\x80\xCA\x9F\x17\x00".to_vec());
            }
            None
        }

        fn on_response(&self, command: &[u8], _response: &[u8]) -> Option<Vec<u8>> {
            if command == b"\x80\xCA\x9F\x17\x00" {
                return Some(b"\x9F\x17\x01\x03\x90\x00".to_vec());
            }
            None
        }

        fn on_exchange(&self, command: &[u8], response: &[u8]) {
            self.exchanges.lock().unwrap().push(ApduExchange {
                command: command.to_vec(),
                response: response.to_vec(),
            });
        }
    }

    #[test]
    fn test_apdu_hook() -> Result<(), EmvError> {
        init_logging();

        let exchanges = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut connection = EmvConnection::new(SETTINGS_FILE)?;
        connection.interface = Some(test_card());
        connection.apdu_hook = Some(Box::new(TestHook {
            exchanges: exchanges.clone(),
        }));

        connection.select_payment_application()?;
        assert_eq!(
            connection.handle_get_data(b"\x9F\x36")?,
            b"\x9F\x17\x01\x03".to_vec()
        );
        assert_eq!(connection.get_tag_value("9F17"), Some(&vec![0x03]));

        // The hook sees the exchanges as the terminal processes them, GET RESPONSE commands included
        let exchanges = exchanges.lock().unwrap();
        assert_eq!(&exchanges[..], &connection.state.exchanges[..]);
        assert!(exchanges
            .iter()
            .any(|exchange| exchange.command[0..2] == [0x00, 0xC0]));
        assert_eq!(
            exchanges.last().unwrap().command,
            b"\x80\xCA\x9F\x17\x00".to_vec()
        );

        Ok(())
    }

    #[test]
    fn test_guarded_step() {
        let mut connection = EmvConnection::new(SETTINGS_FILE).unwrap();
        let result: Result<(), EmvError> = connection.guarded(|_| panic!("step panicked"));
        assert_eq!(result, Err(EmvError::Internal("step panicked".to_string())));

        // Without a card interface a step fails, it does not panic
        assert!(matches!(
            connection.guarded(|connection| connection.select_payment_application()),
            Err(EmvError::Interface(_))
        ));
    }

    #[test]
    fn test_malformed_card_responses() {
        // Each response of the test card truncated or with a changed byte: the purchase transaction completes or fails with an
        // error, the terminal does not panic
        let test_data: Vec<ApduRequestResponse> =
            serde_yaml::from_str(&fs::read_to_string("test_data.yaml").unwrap()).unwrap();

        for data in &test_data {
            let response = ApduRequestResponse::to_raw_vec(&data.res);
            let (body, sw) = response.split_at(response.len() - 2);

            let mut variants: Vec<Vec<u8>> = Vec::new();
            for length in [
                0,
                1,
                2,
                3,
                4,
                5,
                8,
                13,
                body.len() / 2,
                body.len().saturating_sub(1),
            ] {
                if length < body.len() {
                    variants.push([&body[..length], sw].concat());
                }
            }
            for position in [0, 1, 2, 3, body.len() / 2, body.len().saturating_sub(1)] {
                if position < body.len() {
                    for value in [0x00, 0x81, 0xFF] {
                        let mut changed = body.to_vec();
                        changed[position] = value;
                        variants.push([&changed[..], sw].concat());
                    }
                }
            }
            variants.push(Vec::new());
            variants.push(sw.to_vec());

            for variant in variants {
                let mut connection = EmvConnection::new(SETTINGS_FILE).unwrap();
                connection.settings.censor_sensitive_fields = true;
                connection.interface = Some(Box::new(modified_card(vec![(
                    &data.req,
                    &hex::encode_upper(&variant),
                )])));
                setup_connection(&mut connection).unwrap();

                let _ = purchase(&mut connection);
            }
        }
    }
}
