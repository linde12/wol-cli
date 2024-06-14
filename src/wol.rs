//! Parses an IEEE EUI-48 MAC address and continues to construct a
//! WakeOnLAN packet (so called "Magic Packet Technology")
use std::net::UdpSocket;

use thiserror::Error;

type Eui48 = u64;

const MAGIC_PACKET_LEN: usize = 102;
pub struct MagicPacket([u8; MAGIC_PACKET_LEN]);

#[derive(Error, Debug)]
pub enum ParseError {
    /// Invalid MAC address
    #[error("invalid length")]
    InvalidLength,

    /// Expected a hyphen
    #[error("expected a hyphen at position '{0}")]
    ExpectedHyphen(usize),
}

/// Parses an ASCII representation of an EUI-48 address into a unsigned 64-bit integer.
fn parse_eui48(input: &str) -> Result<Eui48, ParseError> {
    // must be exactly 17 characters long
    if input.len() != 17 {
        return Err(ParseError::InvalidLength);
    }

    // must contain exactly 12 hexadecimal digits
    if input.chars().filter(|x| x.is_ascii_hexdigit()).count() != 12 {
        return Err(ParseError::InvalidLength);
    }

    // every 2nd character must be separated by a hyphen
    let mut it = input.chars().enumerate();
    while let Some((index, c)) = it.nth(2) {
        if c != '-' {
            return Err(ParseError::ExpectedHyphen(index));
        }
    }

    let mut eui: Eui48 = 0;
    for c in input.chars().filter(|x| x.is_ascii_hexdigit()) {
        let nibble = c.to_digit(16).ok_or(ParseError::InvalidLength)?;
        eui = eui << 4 | (nibble as u64 & 0xF);
    }

    Ok(eui)
}

/// Creates a magic packet byte array for the given MAC address. The input address must follow the
/// IEEE EUI-48 notation (hexadecimal character separated by hyphens), alternatively colons (:) can
/// be used instead of hyphens.
pub fn create_magic_packet(mac: &str) -> Result<MagicPacket, ParseError> {
    let mut packet = [0xFFu8; 102];
    let mac_with_hyphens = mac
        .chars()
        .map(|c| match c {
            ':' => '-',
            _ => c,
        })
        .collect::<String>();
    let mac = parse_eui48(&mac_with_hyphens)?;

    // fill the packet with 16 occurrences of the MAC
    // starting at the 7th byte so that the first 6
    // bytes stay as 0xFF
    for i in 1..17 {
        let dst = i * 6;
        for j in 0..6 {
            packet[dst + j] = (mac >> 40 - (j * 8) & 0xFF) as u8;
        }
    }

    Ok(MagicPacket(packet))
}

impl MagicPacket {
    pub fn broadcast(&self) -> std::io::Result<()> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_broadcast(true)?;
        socket.send_to(&self.0, "255.255.255.255:9")?;

        Ok(())
    }
}

#[test]
fn test_magic_gibberish() {
    assert!(create_magic_packet("hello").is_err());
}
#[test]
fn test_magic_invalid_alphabet() {
    assert!(create_magic_packet("he-js-an-cc-dd-ee").is_err());
}

#[test]
fn test_magic_too_short() {
    assert!(create_magic_packet("ab-cd").is_err());
}

#[test]
fn test_magic_too_long() {
    assert!(create_magic_packet("ab-cd-ab-cd-ab-cd-ab-cd-ab").is_err());
}

#[test]
fn test_magic_separator_mixed() {
    assert!(create_magic_packet("AA-aa:aa-aa-aa-aa").is_ok());
}

#[test]
fn test_magic_separator_order() {
    assert!(create_magic_packet("-----abababababab").is_err());
}

#[test]
fn test_magic() {
    let pkt = create_magic_packet("AA-aa-aa-aa-aa-aa").unwrap();

    // starts with padding
    let cmp = [255, 255, 255, 255, 255, 255];
    assert_eq!(&pkt.0[..6], &cmp);

    // follows with mac
    let cmp = [170, 170, 170, 170, 170, 170];
    assert_eq!(&pkt.0[6..12], &cmp);

    // ends with mac
    let cmp = [170, 170, 170, 170, 170, 170];
    assert_eq!(&pkt.0[102 - 6..102], &cmp);
}
