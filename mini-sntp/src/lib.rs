// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::use_self,
    clippy::unusual_byte_groupings
)]

use std::net::{ToSocketAddrs, UdpSocket};

mod error;
pub use error::{BadServerResponseReason, Error};

/// The result of [`query`]
#[derive(Debug)]
pub struct SntpTimeQueryResult {
    pub local_clock_offset: time::Duration,
    pub round_trip_delay: time::Duration,
}

/// Executes an SNTP query against the NTPv3 server at the given address.
///
/// Ref: <https://tools.ietf.org/html/rfc2030>
pub fn query(addr: impl ToSocketAddrs + Copy) -> Result<SntpTimeQueryResult, Error> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(Error::BindLocalSocket)?;
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .map_err(Error::SetReadTimeoutOnSocket)?;
    socket
        .set_write_timeout(Some(std::time::Duration::from_secs(10)))
        .map_err(Error::SetWriteTimeoutOnSocket)?;

    let mut num_retries_remaining = 3;
    loop {
        match query_inner(&socket, addr) {
            Ok(result) => return Ok(result),
            Err(err) => {
                let is_retriable = match &err {
                    // Transient errors from DNS failure or bad unsynchronized servers in the pool.
                    Error::BadServerResponse(_) | Error::ResolveNtpPoolHostname(_) => true,

                    // Read / write timeout expired
                    Error::SendClientRequest(err) | Error::ReceiveServerResponse(err) => {
                        err.kind() == std::io::ErrorKind::TimedOut
                            || err.kind() == std::io::ErrorKind::WouldBlock
                    }

                    _ => false,
                };
                if !is_retriable || num_retries_remaining == 0 {
                    return Err(err);
                }
                num_retries_remaining -= 1;
            }
        }
    }
}

fn query_inner(socket: &UdpSocket, addr: impl ToSocketAddrs) -> Result<SntpTimeQueryResult, Error> {
    let addr = addr
        .to_socket_addrs()
        .map_err(|err| Error::ResolveNtpPoolHostname(Some(err)))?
        .next()
        .ok_or(Error::ResolveNtpPoolHostname(None))?;

    let request_transmit_timestamp = {
        let (buf, request_transmit_timestamp) = create_client_request();

        #[cfg(test)]
        std::thread::sleep(std::time::Duration::from_secs(5)); // simulate network delay

        let mut buf = &buf[..];
        while !buf.is_empty() {
            let sent = socket
                .send_to(buf, addr)
                .map_err(Error::SendClientRequest)?;
            buf = &buf[sent..];
        }

        request_transmit_timestamp
    };

    let result = {
        let mut buf = [0_u8; 48];

        {
            let mut buf = &mut buf[..];
            while !buf.is_empty() {
                let (received, received_from) = socket
                    .recv_from(buf)
                    .map_err(Error::ReceiveServerResponse)?;
                if received_from == addr {
                    buf = &mut buf[received..];
                }
            }
        }

        #[cfg(test)]
        std::thread::sleep(std::time::Duration::from_secs(5)); // simulate network delay

        parse_server_response(buf, request_transmit_timestamp)?
    };

    Ok(result)
}

fn create_client_request() -> ([u8; 48], time::OffsetDateTime) {
    let sntp_epoch = sntp_epoch();

    let mut buf = [0_u8; 48];
    buf[0] = 0b00_011_011; // version_number: 3, mode: 3 (client)

    let transmit_timestamp = time::OffsetDateTime::now_utc();

    #[cfg(test)]
    let transmit_timestamp = transmit_timestamp - time::Duration::seconds(30); // simulate unsynced local clock

    let mut duration_since_sntp_epoch = transmit_timestamp - sntp_epoch;

    let integral_part = duration_since_sntp_epoch.whole_seconds();
    duration_since_sntp_epoch -= time::Duration::seconds(integral_part);

    assert!(integral_part >= 0 && integral_part < i64::from(u32::max_value()));
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let integral_part = (integral_part as u32).to_be_bytes();
    buf[40..44].copy_from_slice(&integral_part[..]);

    let fractional_part = duration_since_sntp_epoch
        .whole_nanoseconds();
    let fractional_part = (fractional_part << 32) / 1_000_000_000;
    assert!(fractional_part >= 0 && fractional_part < i128::from(u32::max_value()));
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let fractional_part = (fractional_part as u32).to_be_bytes();
    buf[44..48].copy_from_slice(&fractional_part[..]);

    let packet = Packet::parse(buf, sntp_epoch);
    #[cfg(test)]
    let packet = dbg!(packet);

    // Re-extract transmit timestamp from the packet. This may not be the same as the original `transmit_timestamp`
    // that was serialized into the packet due to rounding. Specifically, it's usually off by 1ns.
    let transmit_timestamp = packet.transmit_timestamp;

    (buf, transmit_timestamp)
}

fn parse_server_response(
    buf: [u8; 48],
    request_transmit_timestamp: time::OffsetDateTime,
) -> Result<SntpTimeQueryResult, Error> {
    let sntp_epoch = sntp_epoch();

    let destination_timestamp = time::OffsetDateTime::now_utc();

    #[cfg(test)]
    let destination_timestamp = destination_timestamp - time::Duration::seconds(30); // simulate unsynced local clock

    let packet = Packet::parse(buf, sntp_epoch);
    #[cfg(test)]
    let packet = dbg!(packet);

    match packet.leap_indicator {
        0..=2 => (),
        leap_indicator => {
            return Err(Error::BadServerResponse(
                BadServerResponseReason::LeapIndicator(leap_indicator),
            ));
        }
    };

    // RFC 2030 says:
    //
    // >Version 4 servers are required to
    // >reply in the same version as the request, so the VN field of the
    // >request also specifies the version of the reply.
    //
    // But at least one pool.ntp.org server does not respect this and responds with VN=4
    // even though our client requests have VN=3.
    //
    // So allow both VN=3 and VN=4 in the server response. The response body format is identical for both anyway.
    if packet.version_number != 3 && packet.version_number != 4 {
        return Err(Error::BadServerResponse(
            BadServerResponseReason::VersionNumber(packet.version_number),
        ));
    }

    if packet.mode != 4 {
        return Err(Error::BadServerResponse(BadServerResponseReason::Mode(
            packet.mode,
        )));
    }

    if packet.originate_timestamp != request_transmit_timestamp {
        return Err(Error::BadServerResponse(
            BadServerResponseReason::OriginateTimestamp {
                expected: request_transmit_timestamp,
                actual: packet.originate_timestamp,
            },
        ));
    }

    Ok(SntpTimeQueryResult {
        local_clock_offset: ((packet.receive_timestamp - request_transmit_timestamp)
            + (packet.transmit_timestamp - destination_timestamp))
            / 2,

        round_trip_delay: (destination_timestamp - request_transmit_timestamp)
            - (packet.receive_timestamp - packet.transmit_timestamp),
    })
}

fn sntp_epoch() -> time::OffsetDateTime {
    time::macros::datetime!(
        1900-01-01 00:00 UTC
    )
}

#[allow(dead_code)]
#[derive(Debug)]
struct Packet {
    leap_indicator: u8,
    version_number: u8,
    mode: u8,
    stratum: u8,
    poll_interval: u8,
    precision: u8,
    root_delay: u32,
    root_dispersion: u32,
    reference_identifier: u32,
    reference_timestamp: time::OffsetDateTime,
    originate_timestamp: time::OffsetDateTime,
    receive_timestamp: time::OffsetDateTime,
    transmit_timestamp: time::OffsetDateTime,
}

impl Packet {
    fn parse(buf: [u8; 48], sntp_epoch: time::OffsetDateTime) -> Self {
        let leap_indicator = (buf[0] & 0b11_000_000) >> 6;
        let version_number = (buf[0] & 0b00_111_000) >> 3;
        let mode = buf[0] & 0b00_000_111;
        let stratum = buf[1];
        let poll_interval = buf[2];
        let precision = buf[3];
        let root_delay = u32::from_be_bytes(buf[4..8].try_into().unwrap());
        let root_dispersion = u32::from_be_bytes(buf[8..12].try_into().unwrap());
        let reference_identifier = u32::from_be_bytes(buf[12..16].try_into().unwrap());
        let reference_timestamp = deserialize_timestamp(
            buf[16..24].try_into().unwrap(),
            sntp_epoch,
        );
        let originate_timestamp = deserialize_timestamp(
            buf[24..32].try_into().unwrap(),
            sntp_epoch,
        );
        let receive_timestamp = deserialize_timestamp(
            buf[32..40].try_into().unwrap(),
            sntp_epoch,
        );
        let transmit_timestamp = deserialize_timestamp(
            buf[40..48].try_into().unwrap(),
            sntp_epoch,
        );

        Packet {
            leap_indicator,
            version_number,
            mode,
            stratum,
            poll_interval,
            precision,
            root_delay,
            root_dispersion,
            reference_identifier,
            reference_timestamp,
            originate_timestamp,
            receive_timestamp,
            transmit_timestamp,
        }
    }
}

fn deserialize_timestamp(
    raw: [u8; 8],
    sntp_epoch: time::OffsetDateTime,
) -> time::OffsetDateTime {
    let integral_part = i64::from(u32::from_be_bytes(raw[..4].try_into().unwrap()));
    let fractional_part = i64::from(u32::from_be_bytes(raw[4..].try_into().unwrap()));
    let duration_since_sntp_epoch = time::Duration::nanoseconds(
        integral_part * 1_000_000_000 + ((fractional_part * 1_000_000_000) >> 32),
    );

    sntp_epoch + duration_since_sntp_epoch
}

#[cfg(test)]
mod tests {
    use super::{query, Error, SntpTimeQueryResult};

    #[test]
    fn it_works() -> Result<(), Error> {
        let SntpTimeQueryResult {
            local_clock_offset,
            round_trip_delay,
        } = query(&("pool.ntp.org", 123))?;

        println!("local clock offset: {}", local_clock_offset);
        println!("round-trip delay: {}", round_trip_delay);

        assert!(
            (local_clock_offset - time::Duration::seconds(30))
                .whole_seconds()
                .abs()
                < 1
        );
        assert!(
            (round_trip_delay - time::Duration::seconds(10))
                .whole_seconds()
                .abs()
                < 1
        );

        Ok(())
    }
}
