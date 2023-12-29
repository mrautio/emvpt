use chrono::{Datelike, NaiveDate, Timelike, Utc};
use hex;
use hexplay::HexViewBuilder;
use iso7816_tlv::ber::{Tag, Tlv, Value};
use log::{debug, info, trace, warn};
use openssl::bn::BigNum;
use openssl::rsa::{Padding, Rsa};
use openssl::sha;
use rand::prelude::*;
use rand::Rng;
use rand_chacha::ChaCha20Rng;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::error;
use std::fmt;
use std::fs::{self};
use std::str;

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

macro_rules! serialize_yaml {
    ($file:expr, $static_resource:expr) => {
        serde_yaml::from_str(
            &fs::read_to_string($file)
                .unwrap_or(String::from_utf8_lossy(include_bytes!($static_resource)).to_string()),
        )
        .unwrap()
    };
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
        // %B4321432143214321^Mc'Doe/JOHN^2609101123456789012345678901234?
        println!("Track: {}", track_data);
        let re = Regex::new(r"^(%B)?(\d+)\^(.+)?/(.+)?\^(\d{2})(\d{2})(\d{3})(\d+)\??$").unwrap();
        let cap = re.captures(track_data).unwrap();

        Track1 {
            primary_account_number: cap.get(2).unwrap().as_str().to_string(),
            last_name: cap.get(3).unwrap().as_str().to_string(),
            first_name: cap.get(4).unwrap().as_str().to_string(),
            expiry_year: cap.get(5).unwrap().as_str().to_string(),
            expiry_month: cap.get(6).unwrap().as_str().to_string(),
            service_code: cap.get(7).unwrap().as_str().to_string(),
            discretionary_data: cap.get(8).unwrap().as_str().to_string(),
        }
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
        // Supports human readable and ICC formats
        // human readable: ;4321432143214321=2612101123456789123?
        // ICC: 4321432143214321D2612101123456789123F

        let re = Regex::new(r"^;?(\d+)(=|D)(\d{2})(\d{2})(\d{3})(\d+)F?\??$").unwrap();
        let cap = re.captures(track_data).unwrap();

        Track2 {
            primary_account_number: cap.get(1).unwrap().as_str().to_string(),
            expiry_year: cap.get(3).unwrap().as_str().to_string(),
            expiry_month: cap.get(4).unwrap().as_str().to_string(),
            service_code: cap.get(5).unwrap().as_str().to_string(),
            discretionary_data: cap.get(6).unwrap().as_str().to_string(),
        }
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
#[derive(Deserialize, Serialize, Debug, Copy, Clone)]
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
    pub code: CvmCode,
    pub condition: CvmConditionCode,
}

impl CvmRule {
    pub fn into_9f34_value(rule: Result<CvmRule, CvmRule>) -> Vec<u8> {
        // EMV Book 4, A4 CVM Results

        let rule_unwrapped = match rule {
            Ok(rule) => rule,
            Err(rule) => rule,
        };

        let mut c: u8 = rule_unwrapped.code.try_into().unwrap();
        if !rule_unwrapped.fail_if_unsuccessful {
            c += 0b0100_0000;
        }

        let mut value: Vec<u8> = Vec::new();
        value.push(c);
        value.push(rule_unwrapped.condition.try_into().unwrap());

        let result: u8 = match rule {
            Ok(rule) => {
                match rule.code {
                    CvmCode::Signature => 0x00, // unknown
                    _ => 0x02,                  // successful
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
    fn from(data: Vec<u8>) -> Self {
        let b1: u8 = data[0];
        let b2: u8 = data[1];

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
    pub terminal_transaction_qualifiers: TerminalTransactionQualifiers,
    pub c4_enhanced_contactless_reader_capabilities: C4EnhancedContactlessReaderCapabilities,
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
    pub script_processing_failed_after_final_generate_ac: bool, //RFU
                                                                //RFU
                                                                //RFU
                                                                //RFU
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

        false
    }
}

impl From<Vec<u8>> for TerminalVerificationResults {
    fn from(data: Vec<u8>) -> Self {
        let b1: u8 = data[0];
        let b2: u8 = data[1];
        let b3: u8 = data[2];
        let b4: u8 = data[3];
        let b5: u8 = data[4];

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

#[derive(Serialize, Deserialize)]
pub struct ConfigurationFiles {
    emv_tags: String,
    scheme_ca_public_keys: String,
    constants: String,
}

#[derive(Serialize, Deserialize)]
pub struct Settings {
    pub censor_sensitive_fields: bool,
    configuration_files: ConfigurationFiles,
    pub terminal: Terminal,
    default_tags: HashMap<String, String>,
}

#[derive(Serialize, Deserialize)]
pub struct Constants {
    pub numeric_country_codes: HashMap<String, String>,
    pub numeric_currency_codes: HashMap<String, String>,
    pub apdu_status_codes: HashMap<String, String>,
}

pub trait ApduInterface {
    fn send_apdu(&self, apdu: &[u8]) -> Result<Vec<u8>, ()>;
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
    ) -> Result<DataObjectList, ()> {
        let mut dol: DataObjectList = DataObjectList::new();

        // FIXME: This parsing is complete BS
        // - Check if "Tag List" and "Data Object List" are same or different types
        // - Parse TLV tags appropriately...
        if tag_list.len() < 2 {
            let tag_name = hex::encode(&tag_list[0..1]).to_uppercase();
            dol.push(DataObject::new(emv_connection, &tag_name, 0));
        } else {
            let mut i = 0;
            loop {
                let tag_value_length: usize;

                let mut tag_name = hex::encode(&tag_list[i..i + 1]).to_uppercase();

                if Tag::try_from(tag_name.as_str()).is_ok()
                    || DataObjectList::is_non_conforming_one_byte_tag(tag_list[i])
                {
                    tag_value_length = tag_list[i + 1] as usize;
                    i += 2;
                } else {
                    tag_name = hex::encode(&tag_list[i..i + 2]).to_uppercase();
                    if Tag::try_from(tag_name.as_str()).is_ok() {
                        tag_value_length = tag_list[i + 2] as usize;
                        i += 3;
                    } else {
                        warn!("Incorrect tag {:?}", tag_name);
                        return Err(());
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

            // TODO: we need to understand tag metadata (is tag "numeric" etc) in order to properly truncate/pad the tag
            if data_object.length > 0 && value.len() != data_object.length {
                warn!(
                    "tag {:?} value length {:02X} does not match tag list value length {:02X}",
                    data_object.emv_tag.tag,
                    value.len(),
                    data_object.length
                );
                //return Err(());
            }

            let mut len = data_object.length;
            if len == 0 {
                // at least 9F4A does not provide length information
                len = value.len();
            }

            output.extend_from_slice(&value[..len]);
        }

        output
    }
}

pub struct EmvConnection<'a> {
    pub tags: HashMap<String, Vec<u8>>,
    pub interface: Option<&'a dyn ApduInterface>,
    pub contactless: bool,
    emv_tags: HashMap<String, EmvTag>,
    constants: Constants,
    pub settings: Settings,
    pub icc: Icc,
    pub pin_callback: Option<&'a dyn Fn() -> Result<String, ()>>,
    pub amount_callback: Option<&'a dyn Fn() -> Result<u64, ()>>,
    pub pse_application_select_callback:
        Option<&'a dyn Fn(&Vec<EmvApplication>) -> Result<EmvApplication, ()>>,
    pub start_transaction_callback: Option<&'a dyn Fn(&mut EmvConnection) -> Result<(), ()>>,
}

impl EmvConnection<'_> {
    pub fn new(settings_file: &str) -> Result<EmvConnection<'static>, String> {
        let settings: Settings = serialize_yaml!(settings_file, "config/settings.yaml");
        let emv_tags = serialize_yaml!(
            settings.configuration_files.emv_tags.clone(),
            "config/emv_tags.yaml"
        );
        let constants = serialize_yaml!(
            settings.configuration_files.constants.clone(),
            "config/constants.yaml"
        );

        Ok(EmvConnection {
            tags: HashMap::new(),
            emv_tags: emv_tags,
            constants: constants,
            settings: settings,
            icc: Icc::new(),
            interface: None,
            contactless: false,
            pin_callback: None,
            amount_callback: None,
            pse_application_select_callback: None,
            start_transaction_callback: None,
        })
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

    pub fn process_tag_as_tlv(&mut self, tag_name: &str, value: Vec<u8>) {
        let mut tlv: Vec<u8> = Vec::new();
        tlv.extend_from_slice(&hex::decode(&tag_name).unwrap()[..]);
        if value.len() >= 0x80 {
            tlv.push(0x81 as u8);
        }
        tlv.push(value.len() as u8);
        tlv.extend_from_slice(&value[..]);

        self.process_tlv(&tlv[..], 1);
    }

    fn send_apdu_select(&mut self, aid: &[u8]) -> (Vec<u8>, Vec<u8>) {
        //ref. EMV Book 1, 11.3.2 Command message
        self.tags.clear();

        let apdu_command_select = b"\x00\xA4";
        let p1_reference_control_parameter: u8 = 0b0000_0100; // "Select by name"
        let p2_selection_options: u8 = 0b0000_0000; // "First or only occurrence"

        let mut select_command = apdu_command_select.to_vec();
        select_command.push(p1_reference_control_parameter);
        select_command.push(p2_selection_options);
        select_command.push(aid.len() as u8); // lc
        select_command.extend_from_slice(aid); // data
        select_command.push(0x00); // le

        self.send_apdu(&select_command)
    }

    fn get_apdu_response_localization(&self, apdu_status: &[u8]) -> String {
        assert_eq!(apdu_status.len(), 2);

        let response_status_code = hex::encode_upper(apdu_status);

        let response_localization: String;
        if let Some(response_description) =
            self.constants.apdu_status_codes.get(&response_status_code)
        {
            response_localization = format!("{} - {}", response_status_code, response_description);
        } else if let Some(response_description) = self
            .constants
            .apdu_status_codes
            .get(&response_status_code[0..2])
        {
            response_localization = format!("{} - {}", response_status_code, response_description);
        } else {
            response_localization = format!("{}", response_status_code);
        }

        response_localization
    }

    pub fn send_apdu<'apdu>(&mut self, apdu: &'apdu [u8]) -> (Vec<u8>, Vec<u8>) {
        let mut response_data: Vec<u8> = Vec::new();
        let mut response_trailer: Vec<u8>;

        let mut new_apdu_command;
        let mut apdu_command = apdu;

        loop {
            // Send an APDU command.
            if self.settings.censor_sensitive_fields {
                debug!(
                    "Sending APDU: {:02X?}... ({} bytes)",
                    &apdu_command[0..5],
                    apdu_command.len()
                );
            } else {
                debug!(
                    "Sending APDU:\n{}",
                    HexViewBuilder::new(&apdu_command).finish()
                );
            }

            let apdu_response = self.interface.unwrap().send_apdu(apdu_command).unwrap();

            response_data.extend_from_slice(&apdu_response[0..apdu_response.len() - 2]);

            // response codes: https://www.eftlab.com/knowledge-base/complete-list-of-apdu-responses/
            response_trailer = vec![
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

                let apdu_command_get_response = b"\x00\xC0\x00\x00";
                new_apdu_command = apdu_command_get_response.to_vec();
                new_apdu_command.push(available_data_length);

                apdu_command = &new_apdu_command[..];
            } else if response_trailer[0] == SW1_WRONG_LENGTH {
                trace!(
                    "APDU response({} bytes):\n{}",
                    response_data.len(),
                    HexViewBuilder::new(&response_data).finish()
                );

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

        (response_trailer, response_data)
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
                Some(FieldFormat::CompressedNumeric) => {
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
                    value = format!(
                        "{:08b} {:08b} {:08b} {:08b} {:08b} => {:#?}",
                        v[0], v[1], v[2], v[3], v[4], tvr
                    );
                }
                Some(FieldFormat::ApplicationUsageControl) => {
                    let auc: UsageControl = v.to_vec().into();
                    value = format!("{:08b} {:08b} => {:#?}", v[0], v[1], auc);
                }
                Some(FieldFormat::KeyCertificate) => {
                    value = format!("{} bit key", v.len() * 8);
                }
                Some(FieldFormat::ServiceCodeIso7813) => {
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
                    let numeric_country_code: String = format!("{:02X?}", v)
                        .replace(|c: char| !(c.is_ascii_alphanumeric()), "")[1..]
                        .to_string();
                    value = format!(
                        "{} - {}",
                        numeric_country_code,
                        self.constants.numeric_country_codes[&numeric_country_code]
                    );
                }
                Some(FieldFormat::NumericCurrencyCode) => {
                    let numeric_currency_code: String = format!("{:02X?}", v)
                        .replace(|c: char| !(c.is_ascii_alphanumeric()), "")[1..]
                        .to_string();
                    value = format!(
                        "{} - {}",
                        numeric_currency_code,
                        self.constants.numeric_currency_codes[&numeric_currency_code]
                    );
                }
                Some(FieldFormat::DataObjectList) => {
                    let dol: DataObjectList =
                        DataObjectList::process_data_object_list(self, &v[..]).unwrap();
                    value = format!("{}", dol);
                }
                Some(FieldFormat::Track2) => {
                    let track2_raw: String = format!("{:02X?}", v)
                        .replace(|c: char| !(c.is_ascii_alphanumeric()), "")
                        .to_string();
                    let track2: Track2 = Track2::new(&track2_raw);
                    value = format!("{}", track2);
                }
                Some(FieldFormat::Date) => {
                    value =
                        format!("{:02X?}", v).replace(|c: char| !(c.is_ascii_alphanumeric()), "");
                    let yy = &value[0..2];
                    let mm = &value[2..4];
                    let dd = &value[4..6];

                    // FIXME: date format does not take into consideration pre 2000s dates
                    value = format!("20{}-{}-{}", yy, mm, dd);
                }
                Some(FieldFormat::Time) => {
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
                    let icc_cryptogram_type = CryptogramType::try_from(v[0] as u8).unwrap();
                    value = format!("{:?}", icc_cryptogram_type);
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
                        let mut track2: Track2 =
                            Track2::new(&String::from_utf8_lossy(&v).to_string());
                        track2.censor();
                        value = format!("{}", track2);

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

    pub fn handle_get_processing_options(&mut self) -> Result<(), ()> {
        //ref. EMV Book 3, 6.5.8 GET PROCESSING OPTIONS Command-Response APDUs

        debug!("GET PROCESSING OPTIONS:");

        let apdu_command_get_processing_options = b"\x80\xA8\x00\x00";
        let mut get_processing_options_command = apdu_command_get_processing_options.to_vec();

        match self.get_tag_value("9F38") {
            Some(tag_9f38_pdol) => {
                let pdol_data = DataObjectList::process_data_object_list(self, &tag_9f38_pdol[..])
                    .unwrap()
                    .get_tag_list_tag_values(self);

                get_processing_options_command.push((pdol_data.len() + 2) as u8); // lc
                                                                                  // data
                get_processing_options_command.push(0x83); // tag 83
                get_processing_options_command.push(pdol_data.len() as u8); // tag 83 length
                get_processing_options_command.extend_from_slice(&pdol_data[..]); // pdol list
                get_processing_options_command.push(0x00); // le
            }
            None => {
                get_processing_options_command.push(0x02); // lc
                get_processing_options_command.push(0x83); // data
                get_processing_options_command.push(0x00); // le
            }
        }

        let (response_trailer, response_data) = self.send_apdu(&get_processing_options_command);
        if !is_success_response(&response_trailer) {
            warn!("Could not get processing options");
            return Err(());
        }

        if response_data[0] == 0x80 {
            self.process_tag_as_tlv("82", response_data[2..4].to_vec());
            self.process_tag_as_tlv("94", response_data[4..].to_vec());
        } else if response_data[0] != 0x77 {
            warn!("Unrecognized response");
            return Err(());
        }

        let tag_94_afl = self.get_tag_value("94").unwrap().clone();

        debug!("Read card Application File Locator (AFL) information:");

        let mut data_authentication: Vec<u8> = Vec::new();
        assert_eq!(tag_94_afl.len() % 4, 0);
        let mut records: Vec<u8> = Vec::new();
        for i in (0..tag_94_afl.len()).step_by(4) {
            let short_file_identifier: u8 = tag_94_afl[i] >> 3;
            let record_index_start: u8 = tag_94_afl[i + 1];
            let record_index_end: u8 = tag_94_afl[i + 2];
            let mut data_authentication_records: u8 = tag_94_afl[i + 3];

            for record_index in record_index_start..record_index_end + 1 {
                if let Some(data) = self.read_record(short_file_identifier, record_index) {
                    assert_eq!(data[0], 0x70);
                    records.extend(&data);

                    // Add data authentication input
                    // ref EMV Book 3, 10.3 Offline Data Authentication
                    if data_authentication_records > 0 {
                        data_authentication_records -= 1;

                        if short_file_identifier <= 10 {
                            if let Value::Constructed(tag_70_tags) =
                                parse_tlv(&data[..]).unwrap().value()
                            {
                                for tag in tag_70_tags {
                                    data_authentication.extend(tag.to_vec());
                                }
                            }
                        } else {
                            data_authentication.extend_from_slice(&data[..]);
                        }

                        if self.settings.censor_sensitive_fields {
                            trace!("Data authentication building: short_file_identifier:{}, data_authentication_records:{}, record_index:{}/{}, data:{} bytes", short_file_identifier, data_authentication_records, record_index, record_index_end, data_authentication.len());
                        } else {
                            trace!("Data authentication building: short_file_identifier:{}, data_authentication_records:{}, record_index:{}/{}, data:{:02X?}", short_file_identifier, data_authentication_records, record_index, record_index_end, data_authentication);
                        }
                    }
                }
            }
        }

        if self.settings.censor_sensitive_fields {
            debug!(
                "AFL data authentication: {} bytes",
                data_authentication.len()
            );
        } else {
            debug!(
                "AFL data authentication:\n{}",
                HexViewBuilder::new(&data_authentication).finish()
            );
        }

        let tag_82_aip = self.get_tag_value("82").unwrap();

        let auc_b1: u8 = tag_82_aip[0];
        // bit 7 = RFU
        self.icc.capabilities.sda = get_bit!(auc_b1, 6);
        self.icc.capabilities.dda = get_bit!(auc_b1, 5);
        if get_bit!(auc_b1, 4) {
            // Cardholder verification is supported

            let tag_8e_cvm_list = self.get_tag_value("8E").unwrap().clone();
            let amount1 = &tag_8e_cvm_list[0..4];
            let amount2 = &tag_8e_cvm_list[4..8];
            let amount_x = str::from_utf8(&bcdutil::bcd_to_ascii(&amount1[..]).unwrap()[..])
                .unwrap()
                .parse::<u32>()
                .unwrap();
            let amount_y = str::from_utf8(&bcdutil::bcd_to_ascii(&amount2[..]).unwrap()[..])
                .unwrap()
                .parse::<u32>()
                .unwrap();

            let tag_84_cvm_rules = &tag_8e_cvm_list[8..];
            assert_eq!(tag_84_cvm_rules.len() % 2, 0);
            for i in (0..tag_84_cvm_rules.len()).step_by(2) {
                let cvm_rule = &tag_84_cvm_rules[i..i + 2];
                let cvm_code = cvm_rule[0];
                let cvm_condition_code = cvm_rule[1];

                // bit 7 = RFU
                let fail_if_unsuccessful = !get_bit!(cvm_code, 6);
                let cvm_code = (cvm_code << 2) >> 2;
                let code: CvmCode = cvm_code.try_into().unwrap();
                let condition: CvmConditionCode = cvm_condition_code.try_into().unwrap();

                let rule = CvmRule {
                    amount_x: amount_x,
                    amount_y: amount_y,
                    fail_if_unsuccessful: fail_if_unsuccessful,
                    code: code,
                    condition: condition,
                };
                self.icc.cvm_rules.push(rule);
            }
        }
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

        self.icc.data_authentication = Some(data_authentication);

        Ok(())
    }

    pub fn handle_verify_plaintext_pin(&mut self, ascii_pin: &[u8]) -> Result<(), ()> {
        debug!("Verify plaintext PIN:");

        let pin_bcd_cn = bcdutil::ascii_to_bcd_cn(ascii_pin, 6).unwrap();

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

    fn fill_random(&self, data: &mut [u8]) {
        if self.settings.terminal.use_random {
            let mut rng = ChaCha20Rng::from_entropy();
            rng.try_fill(data).unwrap();
        }
    }

    pub fn handle_verify_enciphered_pin(&mut self, ascii_pin: &[u8]) -> Result<(), ()> {
        debug!("Verify enciphered PIN:");

        let pin_bcd_cn = bcdutil::ascii_to_bcd_cn(ascii_pin, 6).unwrap();

        const PK_MAX_SIZE: usize = 248; // ref. EMV Book 2, B2.1 RSA Algorithm
        let mut random_padding = [0u8; PK_MAX_SIZE];
        self.fill_random(&mut random_padding[..]);

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
        // Random padding
        plaintext_data.extend_from_slice(
            &random_padding[0..self.icc.icc_pin_pk.as_ref().unwrap().get_key_byte_size() - 17],
        );

        let ciphered_pin_data = self
            .icc
            .icc_pin_pk
            .as_ref()
            .unwrap()
            .public_encrypt(&plaintext_data[..])
            .unwrap();

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

    fn handle_application_cryptogram_card_authentication(
        &mut self,
        tag_77_data: &[u8],
        cdol_tag: &str,
    ) -> Result<(), ()> {
        //ref. EMV Book 2, 6.6.2 Dynamic Signature Verification

        debug!("Perform Application Cryptogram Data Authentication (CDA):");

        let tag_9f37_unpredictable_number = self.get_tag_value("9F37").unwrap();

        let tag_9f4b_signed_data_decrypted_dynamic_data = self
            .validate_signed_dynamic_application_data(&tag_9f37_unpredictable_number[..])
            .unwrap();
        let mut i = 0;
        let icc_dynamic_number_length = tag_9f4b_signed_data_decrypted_dynamic_data[i] as usize;
        i += 1;
        let _icc_dynamic_number =
            &tag_9f4b_signed_data_decrypted_dynamic_data[i..i + icc_dynamic_number_length];
        i += icc_dynamic_number_length;
        let cryptogram_information_data = &tag_9f4b_signed_data_decrypted_dynamic_data[i..i + 1];
        i += 1;
        let tag_9f26_application_cryptogram =
            &tag_9f4b_signed_data_decrypted_dynamic_data[i..i + 8];
        i += 8;
        let transaction_data_hash_code = &tag_9f4b_signed_data_decrypted_dynamic_data[i..i + 20];

        let tag_9f27_cryptogram_information_data = self.get_tag_value("9F27").unwrap();

        if &tag_9f27_cryptogram_information_data[..] != cryptogram_information_data {
            warn!(
                "Cryptogram information data mismatch in CDE! 9F27:{:02X?}, 9F4B.CID:{:02X?}",
                &tag_9f27_cryptogram_information_data[..],
                cryptogram_information_data
            );
            return Err(());
        }

        let mut checksum_data: Vec<u8> = Vec::new();

        let tag_9f38_pdol = self.get_tag_value("9F38");
        if tag_9f38_pdol.is_some() {
            let pdol_data =
                DataObjectList::process_data_object_list(self, &tag_9f38_pdol.unwrap()[..])
                    .unwrap()
                    .get_tag_list_tag_values(self);
            assert!(pdol_data.len() <= 0xFF);
            checksum_data.extend_from_slice(&pdol_data);
        }

        let cdol1_data =
            DataObjectList::process_data_object_list(self, &self.get_tag_value("8C").unwrap()[..])
                .unwrap()
                .get_tag_list_tag_values(self);
        assert!(cdol1_data.len() <= 0xFF);
        checksum_data.extend_from_slice(&cdol1_data);

        if cdol_tag == "8D" {
            let cdol2_data = DataObjectList::process_data_object_list(
                self,
                &self.get_tag_value("8D").unwrap()[..],
            )
            .unwrap()
            .get_tag_list_tag_values(self);
            assert!(cdol2_data.len() <= 0xFF);
            checksum_data.extend_from_slice(&cdol2_data);
        }

        let mut tag_77_hex_encoded = hex::encode_upper(tag_77_data);

        let tag_9f4b_signed_dynamic_application_data_hex_encoded =
            hex::encode_upper(self.get_tag_value("9F4B").unwrap());

        let tag_9f4b_tlv_header_length = 4 /* tag */ + 2 /* tag length */;
        let tag_77_part1: String = tag_77_hex_encoded
            .drain(
                ..tag_77_hex_encoded
                    .find(&tag_9f4b_signed_dynamic_application_data_hex_encoded)
                    .unwrap()
                    - tag_9f4b_tlv_header_length,
            )
            .collect();
        checksum_data.extend_from_slice(&hex::decode(&tag_77_part1).unwrap()[..]);

        let tag_9f4b_whole_size = tag_9f4b_signed_dynamic_application_data_hex_encoded.len()
            + tag_9f4b_tlv_header_length
            + 2;
        if tag_77_hex_encoded.len() > tag_9f4b_whole_size {
            let tag_77_part2: String = tag_77_hex_encoded.drain(tag_9f4b_whole_size..).collect();
            checksum_data.extend_from_slice(&hex::decode(&tag_77_part2).unwrap()[..]);
        }

        let transaction_data_hash_code_checksum = sha::sha1(&checksum_data[..]);

        if &transaction_data_hash_code_checksum[..] != &transaction_data_hash_code[..] {
            warn!("Transaction data hash code mismatch!");
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
                HexViewBuilder::new(transaction_data_hash_code).finish()
            );

            return Err(());
        }

        self.process_tag_as_tlv("9F26", tag_9f26_application_cryptogram.to_vec());

        Ok(())
    }

    fn validate_ac(&self, requested_cryptogram_type: CryptogramType) -> Result<CryptogramType, ()> {
        if let CryptogramType::ApplicationAuthenticationCryptogram = requested_cryptogram_type {
            warn!("Transaction declined by terminal (AAC)");
            return Err(());
        }

        let tag_9f27_cryptogram_information_data = self.get_tag_value("9F27").unwrap();
        let icc_cryptogram_type =
            CryptogramType::try_from(tag_9f27_cryptogram_information_data[0] as u8).unwrap();

        if let CryptogramType::ApplicationAuthenticationCryptogram = icc_cryptogram_type {
            warn!("Transaction declined by ICC (AAC)");
            return Err(());
        }

        let _tag_9f36_application_transaction_counter = self.get_tag_value("9F36").unwrap();
        let _tag_9f26_application_cryptogram = self.get_tag_value("9F26");
        let _tag_9f10_issuer_application_data = self.get_tag_value("9F10");

        Ok(icc_cryptogram_type)
    }

    // ref. EMV Book 3, 6.5.5 GENERATE APPLICATION CRYPTOGRAM
    // ref. EMV Contactless Book C-2, 7.6 Procedure – Prepare Generate AC Command
    fn send_generate_ac(
        &mut self,
        requested_cryptogram_type: CryptogramType,
        cdol_tag: &str,
    ) -> Result<CryptogramType, ()> {
        let mut p1_reference_control_parameter: u8 = requested_cryptogram_type.into();
        if self.icc.capabilities.cda {
            set_bit!(
                p1_reference_control_parameter,
                4,
                self.settings.terminal.capabilities.cda
            );
        }

        let cdol_list = DataObjectList::process_data_object_list(
            self,
            &self.get_tag_value(cdol_tag).unwrap()[..],
        )
        .unwrap();

        if cdol_list.has_tag("9F4C") {
            // GET CHALLENGE might be needed to the 9F4C value
            if let None = self.get_tag_value("9F4C") {
                let tag_9f4c_icc_dynamic_number = self.handle_get_challenge().unwrap();
                self.process_tag_as_tlv("9F4C", tag_9f4c_icc_dynamic_number);
            }
        }

        let cdol_data = cdol_list.get_tag_list_tag_values(self);
        assert!(cdol_data.len() <= 0xFF);

        let apdu_command_generate_ac = b"\x80\xAE";
        let mut generate_ac_command = apdu_command_generate_ac.to_vec();
        generate_ac_command.push(p1_reference_control_parameter);
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
            self.process_tag_as_tlv("9F27", response_data[2..3].to_vec());
            self.process_tag_as_tlv("9F36", response_data[3..5].to_vec());
            self.process_tag_as_tlv("9F26", response_data[5..13].to_vec());
            if response_data.len() > 13 {
                self.process_tag_as_tlv("9F10", response_data[13..].to_vec());
            }
        } else if response_data[0] != 0x77 {
            warn!("Unrecognized response");
            return Err(());
        }

        if get_bit!(p1_reference_control_parameter, 4) {
            let tag_9f27_cryptogram_information_data = self.get_tag_value("9F27").unwrap();
            let icc_cryptogram_type =
                CryptogramType::try_from(tag_9f27_cryptogram_information_data[0] as u8).unwrap();

            match icc_cryptogram_type {
                CryptogramType::TransactionCertificate
                | CryptogramType::AuthorisationRequestCryptogram => {
                    self.handle_application_cryptogram_card_authentication(
                        &response_data[3..],
                        cdol_tag,
                    )?;
                }
                _ => {}
            }
        }

        self.validate_ac(requested_cryptogram_type)
    }

    pub fn handle_1st_generate_ac(&mut self) -> Result<CryptogramType, ()> {
        debug!("Generate Application Cryptogram (GENERATE AC) - first issuance:");

        let icc_cryptogram_type;
        if self.contactless && self.get_tag_value("9F26").is_some() {
            debug!("Application Cryptogram returned in GET PROCESSING OPTIONS");
            // ref. EMV Contactless Book C-3, A.2 Data Elements by Name - cryptogram returned in GET PROCESSING OPTIONS (Kernel 3, Visa)
            icc_cryptogram_type = self.validate_ac(self.settings.terminal.cryptogram_type)?;
        } else {
            icc_cryptogram_type =
                self.send_generate_ac(self.settings.terminal.cryptogram_type, "8C")?;

            if let CryptogramType::AuthorisationRequestCryptogram = icc_cryptogram_type {
                // handle_2nd_generate_ac needed
            } else if let CryptogramType::AuthorisationRequestCryptogram =
                self.settings.terminal.cryptogram_type
            {
                warn!("Transaction terminated by terminal - ARQC requested but got unexpected return type from ICC");
                return Err(());
            }
        }

        Ok(icc_cryptogram_type)
    }

    pub fn handle_2nd_generate_ac(&mut self) -> Result<CryptogramType, ()> {
        debug!("Generate Application Cryptogram (GENERATE AC) - second issuance:");

        let icc_cryptogram_type =
            self.send_generate_ac(self.settings.terminal.cryptogram_type_arqc, "8D")?;

        if let CryptogramType::TransactionCertificate = icc_cryptogram_type {
            return Ok(icc_cryptogram_type);
        }

        warn!("Transaction has unexpected return type from ICC");
        Err(())
    }

    fn read_record(&mut self, short_file_identifier: u8, record_index: u8) -> Option<Vec<u8>> {
        let mut records: Vec<u8> = Vec::new();

        let apdu_command_read = b"\x00\xB2";

        let mut read_record = apdu_command_read.to_vec();
        read_record.push(record_index);
        read_record.push((short_file_identifier << 3) | 0x04);

        const RECORD_LENGTH_DEFAULT: u8 = 0x00;
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

    pub fn handle_select_payment_system_environment(&mut self) -> Result<Vec<EmvApplication>, ()> {
        debug!("Selecting Payment System Environment (PSE):");
        let contact_pse_name = "1PAY.SYS.DDF01";
        let contactless_pse_name = "2PAY.SYS.DDF01";

        let mut pse_name = contact_pse_name;

        if self.contactless {
            self.contactless = true;
            pse_name = contactless_pse_name;
        }

        let (response_trailer, response_data) = self.send_apdu_select(&pse_name.as_bytes());
        if !is_success_response(&response_trailer) {
            warn!("Could not select {:?}", pse_name);
            return Err(());
        }

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

                                let tag_4f_aid = self.get_tag_value("4F").unwrap();
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
                                });

                                // TODO: Since in NFC we're interested only of a single application
                                //       However we should select the one with the best priority

                                break;
                            }
                        }
                    }
                }
                None => {
                    warn!("Expected tag BF0C not found! pse:{}", pse_name);
                    return Err(());
                }
            }
        } else {
            let sfi_data = self.get_tag_value("88").unwrap().clone();
            assert_eq!(sfi_data.len(), 1);
            let short_file_identifier = sfi_data[0];

            debug!("Read available AIDs:");

            for record_index in 0x01..0xFF {
                match self.read_record(short_file_identifier, record_index) {
                    Some(data) => {
                        if data[0] != 0x70 {
                            warn!("Expected template data");
                            return Err(());
                        }

                        if let Value::Constructed(application_templates) =
                            parse_tlv(&data).unwrap().value()
                        {
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

                                    let tag_4f_aid = self.get_tag_value("4F").unwrap();
                                    let default_label = "UNKNOWN".as_bytes().to_vec();
                                    let tag_50_label =
                                        self.get_tag_value("50").unwrap_or(&default_label);

                                    if let Some(tag_87_priority) = self.get_tag_value("87") {
                                        all_applications.push(EmvApplication {
                                            aid: tag_4f_aid.clone(),
                                            label: tag_50_label.clone(),
                                            priority: tag_87_priority.clone(),
                                        });
                                    } else {
                                        debug!(
                                            "Skipping application. AID:{:02X?}, label:{:?}",
                                            tag_4f_aid,
                                            str::from_utf8(&tag_50_label).unwrap()
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
            warn!("No application records found!");
            return Err(());
        }

        Ok(all_applications)
    }

    pub fn handle_select_payment_application(
        &mut self,
        application: &EmvApplication,
    ) -> Result<(), ()> {
        info!(
            "Selecting application. AID:{:02X?}, label:{:?}, priority:{:02X?}",
            application.aid,
            str::from_utf8(&application.label).unwrap(),
            application.priority
        );
        let (response_trailer, _) = self.send_apdu_select(&application.aid);
        if !is_success_response(&response_trailer) {
            warn!(
                "Could not select payment application! {:02X?}, {:?}",
                application.aid, application.label
            );
            return Err(());
        }

        Ok(())
    }

    pub fn select_payment_application(&mut self) -> Result<EmvApplication, ()> {
        let applications = self.handle_select_payment_system_environment()?;

        let application = self.pse_application_select_callback.unwrap()(&applications)?;
        self.handle_select_payment_application(&application)?;

        Ok(application)
    }

    pub fn process_settings(&mut self) -> Result<(), Box<dyn error::Error>> {
        let default_tags = self.settings.default_tags.clone();
        for (tag_name, tag_value) in default_tags.iter() {
            self.process_tag_as_tlv(&tag_name, hex::decode(&tag_value.clone())?);
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
            self.process_tag_as_tlv(
                "9A",
                bcdutil::ascii_to_bcd_cn(transaction_date_ascii_yymmdd.as_bytes(), 3).unwrap(),
            );
        }

        if !self.get_tag_value("9F21").is_some() {
            let time = now.time();
            let transaction_time_ascii_hhmmss =
                format!("{:02}{:02}{:02}", time.hour(), time.minute(), time.second());
            self.process_tag_as_tlv(
                "9F21",
                bcdutil::ascii_to_bcd_cn(transaction_time_ascii_hhmmss.as_bytes(), 3).unwrap(),
            );
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

    pub fn handle_get_data(&mut self, tag: &[u8]) -> Result<Vec<u8>, ()> {
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

        let mut output: Vec<u8> = Vec::new();
        output.extend_from_slice(&response_data);

        Ok(output)
    }

    pub fn handle_get_challenge(&mut self) -> Result<Vec<u8>, ()> {
        debug!("GET CHALLENGE:");

        let apdu_command_get_challenge = b"\x00\x84\x00\x00\x00";

        let (response_trailer, response_data) = self.send_apdu(&apdu_command_get_challenge[..]);
        if !is_success_response(&response_trailer) {
            // 67 00 = wrong length (i.e. CDOL data incorrect)
            warn!("Could not process get challenge");
            return Err(());
        }

        let mut output: Vec<u8> = Vec::new();
        output.extend_from_slice(&response_data);

        Ok(output)
    }

    pub fn handle_public_keys(&mut self, application: &EmvApplication) -> Result<(), ()> {
        if self.get_tag_value("8F").is_none() {
            debug!("Card does not support offline data authentication");
            return Ok(());
        }

        let (issuer_pk_modulus, issuer_pk_exponent) = self.get_issuer_public_key(application)?;
        self.icc.issuer_pk = Some(RsaPublicKey::new(
            &issuer_pk_modulus[..],
            &issuer_pk_exponent[..],
            self.settings.censor_sensitive_fields,
        ));

        let data_authentication = &self.icc.data_authentication.as_ref().unwrap()[..];

        let tag_9f46_icc_pk_certificate = self.get_tag_value("9F46");
        let tag_9f47_icc_pk_exponent = self.get_tag_value("9F47");
        if tag_9f46_icc_pk_certificate.is_some() && tag_9f47_icc_pk_exponent.is_some() {
            let tag_9f48_icc_pk_remainder = self.get_tag_value("9F48");
            let (icc_pk_modulus, icc_pk_exponent) = self.get_icc_public_key(
                tag_9f46_icc_pk_certificate.unwrap(),
                tag_9f47_icc_pk_exponent.unwrap(),
                tag_9f48_icc_pk_remainder,
                data_authentication,
            )?;
            self.icc.icc_pk = Some(RsaPublicKey::new(
                &icc_pk_modulus[..],
                &icc_pk_exponent[..],
                self.settings.censor_sensitive_fields,
            ));
            self.icc.icc_pin_pk = self.icc.icc_pk.clone();
        }

        let tag_9f2d_icc_pin_pk_certificate = self.get_tag_value("9F2D");
        let tag_9f2e_icc_pin_pk_exponent = self.get_tag_value("9F2E");
        if tag_9f2d_icc_pin_pk_certificate.is_some() && tag_9f2e_icc_pin_pk_exponent.is_some() {
            let tag_9f2f_icc_pin_pk_remainder = self.get_tag_value("9F2F");

            // ICC has a separate ICC PIN Encipherement public key
            let (icc_pin_pk_modulus, icc_pin_pk_exponent) = self.get_icc_public_key(
                tag_9f2d_icc_pin_pk_certificate.unwrap(),
                tag_9f2e_icc_pin_pk_exponent.unwrap(),
                tag_9f2f_icc_pin_pk_remainder,
                data_authentication,
            )?;

            self.icc.icc_pin_pk = Some(RsaPublicKey::new(
                &icc_pin_pk_modulus[..],
                &icc_pin_pk_exponent[..],
                self.settings.censor_sensitive_fields,
            ));
        }

        Ok(())
    }

    pub fn get_issuer_public_key(
        &self,
        application: &EmvApplication,
    ) -> Result<(Vec<u8>, Vec<u8>), ()> {
        // ref. https://www.emvco.com/wp-content/uploads/2017/05/EMV_v4.3_Book_2_Security_and_Key_Management_20120607061923900.pdf - 6.3 Retrieval of Issuer Public Key
        let ca_data: HashMap<String, CertificateAuthority> = serialize_yaml!(
            &self.settings.configuration_files.scheme_ca_public_keys,
            "config/scheme_ca_public_keys_test.yaml"
        );

        let tag_92_issuer_pk_remainder = self.get_tag_value("92");
        let tag_9f32_issuer_pk_exponent = self.get_tag_value("9F32").unwrap();
        let tag_90_issuer_public_key_certificate = self.get_tag_value("90").unwrap();

        let rid = &application.aid[0..5];
        let tag_8f_ca_pk_index = self.get_tag_value("8F").unwrap();

        let ca_pk = get_ca_public_key(&ca_data, &rid[..], &tag_8f_ca_pk_index[..]).unwrap();

        let issuer_certificate = ca_pk
            .public_decrypt(&tag_90_issuer_public_key_certificate[..])
            .unwrap();
        let issuer_certificate_length = issuer_certificate.len();

        if issuer_certificate[1] != 0x02 {
            warn!(
                "Incorrect issuer certificate type {:02X?}",
                issuer_certificate[1]
            );
            return Err(());
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

        assert_eq!(issuer_certificate_hash_algorithm[0], 0x01); // SHA-1
        assert_eq!(issuer_pk_algorithm[0], 0x01); // RSA as defined in EMV Book 2, B2.1 RSA Algorihm

        let issuer_certificate_checksum =
            &issuer_certificate[checksum_position..checksum_position + 20];

        let mut checksum_data: Vec<u8> = Vec::new();
        checksum_data.extend_from_slice(&issuer_certificate[1..checksum_position]);
        if tag_92_issuer_pk_remainder.is_some() {
            checksum_data.extend_from_slice(&tag_92_issuer_pk_remainder.unwrap()[..]);
        }
        checksum_data.extend_from_slice(&tag_9f32_issuer_pk_exponent[..]);

        let cert_checksum = sha::sha1(&checksum_data[..]);

        if &cert_checksum[..] != &issuer_certificate_checksum[..] {
            warn!("Issuer cert checksum mismatch!");
            warn!(
                "Calculated checksum\n{}",
                HexViewBuilder::new(&cert_checksum[..]).finish()
            );
            warn!(
                "Issuer provided checksum\n{}",
                HexViewBuilder::new(&issuer_certificate_checksum[..]).finish()
            );

            return Err(());
        }

        let tag_5a_pan = self.get_tag_value("5A").unwrap();
        let ascii_pan = bcdutil::bcd_to_ascii(&tag_5a_pan[..]).unwrap();
        let ascii_iin = bcdutil::bcd_to_ascii(&issuer_certificate_iin).unwrap();
        if ascii_iin != &ascii_pan[0..ascii_iin.len()] {
            warn!(
                "IIN mismatch! Cert IIN: {:02X?}, PAN IIN: {:02X?}",
                ascii_iin,
                &ascii_pan[0..ascii_iin.len()]
            );

            return Err(());
        }

        is_certificate_expired(&issuer_certificate_expiry[..]);

        let issuer_pk_leftmost_digits_length = issuer_pk_leftmost_digits
            .iter()
            .rev()
            .position(|c| -> bool { *c != 0xBB })
            .map(|i| issuer_pk_leftmost_digits.len() - i)
            .unwrap();

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

    pub fn get_icc_public_key(
        &self,
        icc_pk_certificate: &Vec<u8>,
        icc_pk_exponent: &Vec<u8>,
        icc_pk_remainder: Option<&Vec<u8>>,
        data_authentication: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), ()> {
        // ICC public key retrieval: EMV Book 2, 6.4 Retrieval of ICC Public Key
        debug!(
            "Retrieving ICC public key {:02X?}",
            &icc_pk_certificate[0..2]
        );

        let tag_9f46_icc_pk_certificate = icc_pk_certificate;

        let icc_certificate = self
            .icc
            .issuer_pk
            .as_ref()
            .unwrap()
            .public_decrypt(&tag_9f46_icc_pk_certificate[..])
            .unwrap();
        let icc_certificate_length = icc_certificate.len();
        if icc_certificate[1] != 0x04 {
            warn!("Incorrect ICC certificate type {:02X?}", icc_certificate[1]);
            return Err(());
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
            let pan: String =
                String::from_utf8_lossy(&bcdutil::bcd_to_ascii(&icc_certificate_pan).unwrap())
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

        assert_eq!(icc_certificate_hash_algo[0], 0x01); // SHA-1
        assert_eq!(icc_certificate_pk_algo[0], 0x01); // RSA as defined in EMV Book 2, B2.1 RSA Algorihm

        let tag_9f47_icc_pk_exponent = icc_pk_exponent;

        let mut checksum_data: Vec<u8> = Vec::new();
        checksum_data.extend_from_slice(&icc_certificate[1..checksum_position]);

        let tag_9f48_icc_pk_remainder = icc_pk_remainder;
        if let Some(tag_9f48_icc_pk_remainder) = tag_9f48_icc_pk_remainder {
            checksum_data.extend_from_slice(&tag_9f48_icc_pk_remainder[..]);
        }

        checksum_data.extend_from_slice(&tag_9f47_icc_pk_exponent[..]);

        checksum_data.extend_from_slice(data_authentication);

        if let Some(tag_9f4a_static_data_authentication_tag_list) = self.get_tag_value("9F4A") {
            let static_data_authentication_tag_list_tag_values =
                DataObjectList::process_data_object_list(
                    self,
                    &tag_9f4a_static_data_authentication_tag_list[..],
                )
                .unwrap()
                .get_tag_list_tag_values(self);
            checksum_data.extend_from_slice(&static_data_authentication_tag_list_tag_values[..]);
        }

        let cert_checksum = sha::sha1(&checksum_data[..]);

        let icc_certificate_checksum = &icc_certificate[checksum_position..checksum_position + 20];

        if !self.settings.censor_sensitive_fields {
            trace!("Checksum data: {:02X?}", &checksum_data[..]);
        }
        trace!("Calculated checksum: {:02X?}", cert_checksum);
        trace!("Stored ICC checksum: {:02X?}", icc_certificate_checksum);
        assert_eq!(cert_checksum, icc_certificate_checksum);

        let tag_5a_pan = self.get_tag_value("5A").unwrap();
        let ascii_pan = bcdutil::bcd_to_ascii(&tag_5a_pan[..]).unwrap();
        let icc_ascii_pan = bcdutil::bcd_to_ascii(&icc_certificate_pan).unwrap();
        if icc_ascii_pan != ascii_pan {
            warn!(
                "PAN mismatch! Cert PAN: {:02X?}, PAN: {:02X?}",
                icc_ascii_pan, ascii_pan
            );

            return Err(());
        }

        is_certificate_expired(&icc_certificate_expiry[..]);

        let mut icc_pk_modulus: Vec<u8> = Vec::new();

        let icc_certificate_pk_leftmost_digits_length = icc_certificate_pk_leftmost_digits
            .iter()
            .rev()
            .position(|c| -> bool { *c != 0xBB })
            .map(|i| icc_certificate_pk_leftmost_digits.len() - i)
            .unwrap();

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

    pub fn validate_signed_dynamic_application_data(
        &self,
        auth_data: &[u8],
    ) -> Result<Vec<u8>, ()> {
        let tag_9f4b_signed_data = self.get_tag_value("9F4B").unwrap();
        trace!(
            "9F4B signed data result moduluslength: ({} bytes):\n{}",
            tag_9f4b_signed_data.len(),
            HexViewBuilder::new(&tag_9f4b_signed_data[..]).finish()
        );

        if self.icc.icc_pk.is_none() {
            warn!("ICC PK missing, can't validate");
            return Err(());
        }

        let tag_9f4b_signed_data_decrypted = self
            .icc
            .icc_pk
            .as_ref()
            .unwrap()
            .public_decrypt(&tag_9f4b_signed_data[..])
            .unwrap();
        let tag_9f4b_signed_data_decrypted_length = tag_9f4b_signed_data_decrypted.len();
        if tag_9f4b_signed_data_decrypted[1] != 0x05 {
            warn!("Unrecognized format");
            return Err(());
        }

        let tag_9f4b_signed_data_decrypted_hash_algo = tag_9f4b_signed_data_decrypted[2];
        assert_eq!(tag_9f4b_signed_data_decrypted_hash_algo, 0x01);

        let tag_9f4b_signed_data_decrypted_dynamic_data_length =
            tag_9f4b_signed_data_decrypted[3] as usize;

        let tag_9f4b_signed_data_decrypted_dynamic_data = &tag_9f4b_signed_data_decrypted
            [4..4 + tag_9f4b_signed_data_decrypted_dynamic_data_length];

        let checksum_position = tag_9f4b_signed_data_decrypted_length - 21;
        let mut checksum_data: Vec<u8> = Vec::new();
        checksum_data.extend_from_slice(&tag_9f4b_signed_data_decrypted[1..checksum_position]);
        checksum_data.extend_from_slice(&auth_data[..]);

        let signed_data_checksum = sha::sha1(&checksum_data[..]);

        let tag_9f4b_signed_data_decrypted_checksum =
            &tag_9f4b_signed_data_decrypted[checksum_position..checksum_position + 20];

        if &signed_data_checksum[..] != &tag_9f4b_signed_data_decrypted_checksum[..] {
            warn!("Signed data checksum mismatch!");
            warn!(
                "Calculated checksum\n{}",
                HexViewBuilder::new(&signed_data_checksum[..]).finish()
            );
            warn!(
                "Signed data checksum\n{}",
                HexViewBuilder::new(&tag_9f4b_signed_data_decrypted_checksum[..]).finish()
            );

            return Err(());
        }

        Ok(tag_9f4b_signed_data_decrypted_dynamic_data.to_vec())
    }

    pub fn handle_signed_static_application_data(
        &mut self,
        data_authentication: &[u8],
    ) -> Result<(), ()> {
        debug!("Validate Signed Static Application Data (SDA):");

        if self.icc.issuer_pk.is_none() {
            warn!("Issuer PK missing, can't perform SDA");
            return Err(());
        }

        let tag_93_ssad = self.get_tag_value("93").unwrap();

        if tag_93_ssad.len() != self.icc.issuer_pk.as_ref().unwrap().get_key_byte_size() {
            warn!("SDA and issuer key mismatch");
            return Err(());
        }

        let tag_93_ssad_decrypted = self
            .icc
            .issuer_pk
            .as_ref()
            .unwrap()
            .public_decrypt(&tag_93_ssad[..])
            .unwrap();

        assert_eq!(tag_93_ssad_decrypted[1], 0x03);

        let mut checksum_data: Vec<u8> = Vec::new();
        checksum_data
            .extend_from_slice(&tag_93_ssad_decrypted[1..tag_93_ssad_decrypted.len() - 22]);
        checksum_data.extend_from_slice(data_authentication);
        let static_data_authentication_tag_list_tag_values =
            DataObjectList::process_data_object_list(
                self,
                &self.get_tag_value("9F4A").unwrap()[..],
            )
            .unwrap()
            .get_tag_list_tag_values(self);
        checksum_data.extend_from_slice(&static_data_authentication_tag_list_tag_values[..]);

        let ssad_checksum_calculated = sha::sha1(&checksum_data[..]);

        let ssad_checksum = &tag_93_ssad_decrypted
            [tag_93_ssad_decrypted.len() - 22..tag_93_ssad_decrypted.len() - 1];

        if &ssad_checksum_calculated[..] != ssad_checksum {
            warn!("SDA verification mismatch!");
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

            return Err(());
        }

        self.process_tag_as_tlv("9F45", tag_93_ssad_decrypted[3..5].to_vec());

        Ok(())
    }

    pub fn handle_dynamic_data_authentication(&mut self) -> Result<(), ()> {
        let mut auth_data: Vec<u8> = Vec::new();

        if let Some(tag_9f69_card_authentication_related_data) = self.get_tag_value("9F69") {
            // ref. EMV Contactless Book C-3, Annex C Fast Dynamic Data Authentication (fDDA)
            // ref. EMV Contactless Book C-7, Annex B Fast Dynamic Data Authentication (fDDA)

            debug!("Perform Fast Dynamic Data Authentication (fDDA):");

            if !self.contactless {
                warn!("fDDA expected only for contactless");
                return Err(());
            }

            if tag_9f69_card_authentication_related_data[0] != 0x01 {
                warn!(
                    "fDDA version not recognized:{}",
                    tag_9f69_card_authentication_related_data[0]
                );
                return Err(());
            }

            auth_data.extend_from_slice(&self.get_tag_value("9F37").unwrap()[..]);
            auth_data.extend_from_slice(&self.get_tag_value("9F02").unwrap()[..]);
            auth_data.extend_from_slice(&self.get_tag_value("5F2A").unwrap()[..]);
            auth_data.extend_from_slice(&tag_9f69_card_authentication_related_data[..]);
        } else {
            debug!("Perform Dynamic Data Authentication (DDA):");

            let ddol_default_value = b"\x9f\x37\x04".to_vec();
            let tag_9f49_ddol = match self.get_tag_value("9F49") {
                Some(ddol) => ddol,
                // fall-back to a default DDOL
                None => &ddol_default_value,
            };

            let ddol_data = DataObjectList::process_data_object_list(self, &tag_9f49_ddol[..])
                .unwrap()
                .get_tag_list_tag_values(self);

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
                self.process_tag_as_tlv("9F4B", response_data[3..].to_vec());
            } else if response_data[0] != 0x77 {
                warn!("Unrecognized response");
                return Err(());
            }
        }

        let tag_9f4b_signed_data_decrypted_dynamic_data = self
            .validate_signed_dynamic_application_data(&auth_data[..])
            .unwrap();

        let tag_9f4c_icc_dynamic_number = &tag_9f4b_signed_data_decrypted_dynamic_data[1..];
        self.process_tag_as_tlv("9F4C", tag_9f4c_icc_dynamic_number.to_vec());

        Ok(())
    }

    pub fn start_transaction(&mut self, application: &EmvApplication) -> Result<(), ()> {
        self.process_settings().unwrap();

        self.start_transaction_callback.unwrap()(self)?;

        self.handle_get_processing_options()?;

        self.handle_public_keys(application).unwrap();

        Ok(())
    }

    pub fn handle_card_verification_methods(&mut self) -> Result<(), ()> {
        let purchase_amount = str::from_utf8(
            &bcdutil::bcd_to_ascii(&self.get_tag_value("9F02").unwrap()[..]).unwrap()[..],
        )
        .unwrap()
        .parse::<u32>()
        .unwrap();

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
                    if purchase_amount >= rule.amount_x {
                        continue;
                    }
                }
                CvmConditionCode::IccCurrencyOverX => {
                    if purchase_amount <= rule.amount_x {
                        continue;
                    }
                }
                CvmConditionCode::IccCurrencyUnderY => {
                    if purchase_amount >= rule.amount_y {
                        continue;
                    }
                }
                CvmConditionCode::IccCurrencyOverY => {
                    if purchase_amount <= rule.amount_y {
                        continue;
                    }
                }
                _ => (),
            }

            match rule.code {
                CvmCode::FailCvmProcessing => success = false,
                CvmCode::EncipheredPinOnline => {
                    debug!("Enciphered PIN online is not supported");

                    if skip_if_not_supported {
                        continue;
                    }

                    success = false;
                }
                CvmCode::PlaintextPin
                | CvmCode::PlaintextPinAndSignature
                | CvmCode::EncipheredPinOffline
                | CvmCode::EncipheredPinOfflineAndSignature => {
                    let enciphered_pin = match rule.code {
                        CvmCode::EncipheredPinOffline
                        | CvmCode::EncipheredPinOfflineAndSignature => true,
                        _ => false,
                    };

                    let ascii_pin = self.pin_callback.unwrap()()?;

                    if enciphered_pin && self.settings.terminal.capabilities.enciphered_pin {
                        success = match self.handle_verify_enciphered_pin(ascii_pin.as_bytes()) {
                            Ok(_) => true,
                            Err(_) => false,
                        };
                    } else if self.settings.terminal.capabilities.plaintext_pin {
                        success = match self.handle_verify_plaintext_pin(ascii_pin.as_bytes()) {
                            Ok(_) => true,
                            Err(_) => false,
                        };
                    } else if skip_if_not_supported {
                        continue;
                    }
                }
                CvmCode::Signature | CvmCode::NoCvm => {
                    success = true;
                }
            }

            if success {
                self.settings
                    .terminal
                    .tvr
                    .cardholder_verification_was_not_successful = false;
                self.process_tag_as_tlv("9F34", CvmRule::into_9f34_value(Ok(rule)));
                break;
            } else {
                self.settings
                    .terminal
                    .tvr
                    .cardholder_verification_was_not_successful = true;
                self.process_tag_as_tlv("9F34", CvmRule::into_9f34_value(Err(rule)));

                if !skip_if_not_supported {
                    break;
                }
            }
        }

        self.settings
            .terminal
            .tsi
            .cardholder_verification_was_performed = true;

        if !self.get_tag_value("9F34").is_some() {
            self.settings
                .terminal
                .tvr
                .cardholder_verification_was_not_successful = true;

            // "no CVM performed"
            self.process_tag_as_tlv("9F34", b"\x3F\x00\x01".to_vec());
        }

        Ok(())
    }

    pub fn handle_terminal_risk_management(&mut self) -> Result<(), ()> {
        //ref. EMV 4.3 Book 3 - 10.6 Terminal Risk Management
        //risk management for online transaction:
        //- check terminal floor limit
        //- random transaction selection; select a transaction randomly for online authorization
        //- velocity checking; check offline transaction counter / limits from the card

        Ok(())
    }

    pub fn handle_offline_data_authentication(&mut self) -> Result<(), ()> {
        //ref. EMV 4.3 Book 3 - 10.3 Offline Data Authentication

        if !(self.settings.terminal.capabilities.cda && self.icc.capabilities.cda) {
            if self.settings.terminal.capabilities.dda && self.icc.capabilities.dda {
                if let Err(_) = self.handle_dynamic_data_authentication() {
                    self.settings.terminal.tvr.dda_failed = true;
                }
            } else if self.settings.terminal.capabilities.sda && self.icc.capabilities.sda {
                if let Err(_) = self.handle_signed_static_application_data(
                    &self.icc.data_authentication.as_ref().unwrap().clone()[..],
                ) {
                    self.settings.terminal.tvr.sda_failed = true;
                }
            }
        }

        self.settings
            .terminal
            .tsi
            .offline_data_authentication_was_performed = true;

        Ok(())
    }

    pub fn handle_terminal_action_analysis(&mut self) -> Result<(), ()> {
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

        let tag_95_tvr: Vec<u8> = self.settings.terminal.tvr.into();
        let tvr_len = tag_95_tvr.len();
        self.process_tag_as_tlv("95", tag_95_tvr);
        debug!("{:?}", self.settings.terminal.tvr);

        let action_zero: TerminalVerificationResults = vec![0; tvr_len].into();
        let action_one: TerminalVerificationResults = vec![1; tvr_len].into();

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

        // TODO: actually make the GENERATE AC happen

        if TerminalVerificationResults::action_code_matches(
            &self.settings.terminal.tvr,
            &tag_9f0e_issuer_action_code_denial,
            &terminal_action_code_denial,
        ) {
            debug!("Action Code - Denial matches => GENERATE AC AAC needed");
        } else if TerminalVerificationResults::action_code_matches(
            &self.settings.terminal.tvr,
            &tag_9f0f_issuer_action_code_online,
            &terminal_action_code_online,
        ) {
            // online action codes for online capable terminals
            debug!("Action Code - Online matches => GENERATE AC ARQC needed");
        } else if TerminalVerificationResults::action_code_matches(
            &self.settings.terminal.tvr,
            &tag_9f0d_issuer_action_code_default,
            &terminal_action_code_default,
        ) {
            // TODO: offline-only terminals or if online authorization is not possible this is to be done
            debug!("Action Code - Default matches => GENERATE AC AAC needed");
        } else {
            debug!("Action Codes vs. TVR are OK => GENERATE AC TC needed");
        }

        Ok(())
    }

    pub fn handle_issuer_authentication_data(&mut self) -> Result<(), ()> {
        // ref. EMV 4.3 Book 3 - 10.9 Online Processing
        // ref. EMV 4.3 Book 3 - 6.5.4 EXTERNAL AUTHENTICATE Command-Response APDUs

        let tag_91_issuer_authentication_data = self.get_tag_value("91");
        if !self.icc.capabilities.issuer_authentication
            && tag_91_issuer_authentication_data.is_none()
        {
            return Ok(());
        }

        debug!("Validating issuer authentication data");
        // TODO: call external authenticate
        let apdu_command_external_authenticate = b"\x00\x82\x00\x00"; // EXTERNAL AUTHENTICATE
        let mut external_authenticate_command = apdu_command_external_authenticate.to_vec();
        external_authenticate_command.push(tag_91_issuer_authentication_data.unwrap().len() as u8);
        external_authenticate_command
            .extend_from_slice(&tag_91_issuer_authentication_data.unwrap()[..]);

        let (response_trailer, _response_data) = self.send_apdu(&external_authenticate_command);
        if !is_success_response(&response_trailer) {
            self.settings.terminal.tvr.issuer_authentication_failed = true;
        }

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct EmvApplication {
    pub aid: Vec<u8>,
    pub label: Vec<u8>,
    pub priority: Vec<u8>,
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

    pub fn public_encrypt(&self, plaintext_data: &[u8]) -> Result<Vec<u8>, ()> {
        let pk_modulus_raw = hex::decode(&self.modulus).unwrap();
        let pk_modulus = BigNum::from_slice(&pk_modulus_raw[..]).unwrap();
        let pk_exponent = BigNum::from_slice(&(hex::decode(&self.exponent).unwrap())[..]).unwrap();

        let rsa = Rsa::from_public_components(pk_modulus, pk_exponent).unwrap();

        let mut encrypt_output = [0u8; 4096];

        let length =
            match rsa.public_encrypt(plaintext_data, &mut encrypt_output[..], Padding::NONE) {
                Ok(length) => length,
                Err(_) => {
                    warn!("Could not encrypt data");
                    return Err(());
                }
            };

        let mut data = Vec::new();
        data.extend_from_slice(&encrypt_output[..length]);

        if let Some(true) = self.sensitive {
            trace!("Encrypt result ({} bytes)", data.len());
        } else {
            trace!(
                "Encrypt result ({} bytes):\n{}",
                data.len(),
                HexViewBuilder::new(&data[..]).finish()
            );
        }

        if data.len() != pk_modulus_raw.len() {
            warn!("Data length discrepancy");
            return Err(());
        }

        Ok(data)
    }

    pub fn public_decrypt(&self, cipher_data: &[u8]) -> Result<Vec<u8>, ()> {
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

        if let Some(true) = self.sensitive {
            trace!("Decrypt result ({} bytes)", data.len());
        } else {
            trace!(
                "Decrypt result ({} bytes):\n{}",
                data.len(),
                HexViewBuilder::new(&data[..]).finish()
            );
        }

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
pub struct CertificateAuthority {
    issuer: String,
    certificates: HashMap<String, RsaPublicKey>,
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

pub fn is_certificate_expired(date_bcd: &[u8]) -> bool {
    let today = Utc::now().date_naive();
    let expiry_date =
        NaiveDate::parse_from_str(&format!("01{:02X?}", date_bcd), "%d[%m, %y]").unwrap();
    let duration = today.signed_duration_since(expiry_date).num_days();

    if duration > 30 {
        warn!(
            "Certificate expiry date (MMYY) {:02X?} is {} days in the past",
            date_bcd,
            duration.to_string()
        );

        return true;
    }

    false
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
        fn send_apdu(&self, apdu: &[u8]) -> Result<Vec<u8>, ()> {
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

    fn pse_application_select(applications: &Vec<EmvApplication>) -> Result<EmvApplication, ()> {
        Ok(applications[0].clone())
    }

    fn pin_entry() -> Result<String, ()> {
        Ok("1234".to_string())
    }

    fn amount_entry() -> Result<u64, ()> {
        Ok(1)
    }

    fn start_transaction(connection: &mut EmvConnection) -> Result<(), ()> {
        // force transaction date as 24.07.2020
        connection.process_tag_as_tlv("9A", b"\x20\x07\x24".to_vec());

        // force unpreditable number
        connection.process_tag_as_tlv("9F37", b"\x01\x23\x45\x67".to_vec());
        connection.settings.terminal.use_random = false;

        // force issuer authentication data
        connection.process_tag_as_tlv("91", b"\x12\x34\x56\x78\x12\x34\x56\x78".to_vec());

        Ok(())
    }

    fn setup_connection(connection: &mut EmvConnection) -> Result<(), ()> {
        connection.contactless = false;
        connection.pse_application_select_callback = Some(&pse_application_select);
        connection.pin_callback = Some(&pin_entry);
        connection.amount_callback = Some(&amount_entry);
        connection.start_transaction_callback = Some(&start_transaction);

        Ok(())
    }

    #[test]
    fn test_get_data() -> Result<(), ()> {
        init_logging();

        let mut connection = EmvConnection::new(SETTINGS_FILE).unwrap();
        let smart_card_connection = DummySmartCardConnection {
            test_data_file: "test_data.yaml".to_string(),
        };
        connection.interface = Some(&smart_card_connection);
        setup_connection(&mut connection)?;

        connection.select_payment_application()?;

        let search_tag = b"\x9f\x36";
        connection.handle_get_data(&search_tag[..])?;

        Ok(())
    }

    #[test]
    fn test_pin_verification_methods() -> Result<(), ()> {
        init_logging();

        let mut connection = EmvConnection::new(SETTINGS_FILE).unwrap();
        let smart_card_connection = DummySmartCardConnection {
            test_data_file: "test_data.yaml".to_string(),
        };
        connection.interface = Some(&smart_card_connection);
        setup_connection(&mut connection)?;

        let application = connection.select_payment_application()?;

        connection.start_transaction(&application).unwrap();

        let ascii_pin = connection.pin_callback.unwrap()()?;

        connection.handle_verify_plaintext_pin(ascii_pin.as_bytes())?;
        connection.handle_verify_enciphered_pin(ascii_pin.as_bytes())?;

        Ok(())
    }

    #[test]
    fn test_purchase_transaction() -> Result<(), ()> {
        init_logging();

        let mut connection = EmvConnection::new(SETTINGS_FILE).unwrap();
        let smart_card_connection = DummySmartCardConnection {
            test_data_file: "test_data.yaml".to_string(),
        };
        connection.interface = Some(&smart_card_connection);
        setup_connection(&mut connection)?;

        let amount = connection.amount_callback.unwrap()()?;

        let application = connection.select_payment_application()?;

        connection.start_transaction(&application)?;

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
                assert!(
                    !connection
                        .settings
                        .terminal
                        .tvr
                        .issuer_authentication_failed
                );

                match connection.handle_2nd_generate_ac()? {
                    CryptogramType::AuthorisationRequestCryptogram => {
                        return Err(());
                    }
                    CryptogramType::TransactionCertificate => { /* Expected */ }
                    CryptogramType::ApplicationAuthenticationCryptogram => {
                        return Err(());
                    }
                }
            }
            CryptogramType::TransactionCertificate => {
                return Err(()); /* For test case 2ND GEN AC TC is expected */
            }
            CryptogramType::ApplicationAuthenticationCryptogram => {
                return Err(());
            }
        }

        Ok(())
    }

    #[test]
    fn test_data_object_list_processing() -> Result<(), ()> {
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
    fn test_track2_human_readable() -> Result<(), ()> {
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
    fn test_track2_icc() -> Result<(), ()> {
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
    fn test_track1() -> Result<(), ()> {
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
    fn test_bcd_conversion() -> Result<(), ()> {
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

    #[test]
    fn test_pan_truncation() {
        assert_eq!(get_truncated_pan("0000000000000000"), "00000000****0000");
        assert_eq!(get_truncated_pan("000000000000000"), "000000*****0000");
        assert_eq!(get_truncated_pan("00000000000000"), "000000****0000");
    }
}
