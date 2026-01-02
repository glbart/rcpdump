use std::fmt::Display;

use time::OffsetDateTime;

use crate::shared::ParseError;
use crate::shared::take_next_bytes;

pub struct NtpPacket {
    li: u8,
    vn: u8,
    mode: u8,
    stratum: u8,
    poll_interval: u8,
    precision: u8,
    root_delay: u32,
    root_dispersion: u32,
    reference_identifier: u32,
    reference_timestamp: NTPTimestamp,
    originate_timestamp: NTPTimestamp,
    receive_timestamp: NTPTimestamp,
    transmit_timestamp: NTPTimestamp,
}

struct NTPTimestamp {
    t_seconds: u32,
    t_fraction: u32,
    datetime: OffsetDateTime,
}

impl NtpPacket {
    pub fn try_parse(data: &[u8]) -> Result<NtpPacket, ParseError> {
        let mut cursor = data;

        // fitst byte is leap indicator (2 bits) + version number (3 bits) + mode (3 bits)
        let byte = u8::from_be_bytes(take_next_bytes::<1>(&mut cursor)?);
        let li = byte >> 6;
        let vn = (byte >> 3) & 0x7;
        let mode = byte & 0x7;

        // next byte is stratum
        let stratum = u8::from_be_bytes(take_next_bytes::<1>(&mut cursor)?);

        // next byte is poll_interval
        let poll_interval = u8::from_be_bytes(take_next_bytes::<1>(&mut cursor)?);

        // next byte is precision
        let precision = u8::from_be_bytes(take_next_bytes::<1>(&mut cursor)?);

        // next 4 bytes is root_delay
        let root_delay = u32::from_be_bytes(take_next_bytes::<4>(&mut cursor)?);

        // next 4 bytes is root_dispersion
        let root_dispersion = u32::from_be_bytes(take_next_bytes::<4>(&mut cursor)?);

        // next 4 bytes is reference_identifier
        let reference_identifier = u32::from_be_bytes(take_next_bytes::<4>(&mut cursor)?);

        // next 8 bytes is reference_timestamp
        let reference_timestamp = NTPTimestamp::from_be_bytes(take_next_bytes::<8>(&mut cursor)?);

        // next 8 bytes is originate_timestamp
        let originate_timestamp = NTPTimestamp::from_be_bytes(take_next_bytes::<8>(&mut cursor)?);

        // next 8 bytes is receive_timestamp
        let receive_timestamp = NTPTimestamp::from_be_bytes(take_next_bytes::<8>(&mut cursor)?);

        // next 8 bytes is transmit_timestamp
        let transmit_timestamp = NTPTimestamp::from_be_bytes(take_next_bytes::<8>(&mut cursor)?);

        Ok(NtpPacket {
            li,
            vn,
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
        })
    }

    pub fn format_output(&self) {
        println!("Network Time Protocol");
        println!("\tPeer Clock Stratum: {}", self.stratum);
        println!("\tPeer Pooling Interval: {}", self.poll_interval);
        println!("\tPeer Clock Precision: {}", self.precision);
        println!("\tRoot Delay: {}", self.root_delay);
        println!("\tRoot Dispersion: {}", self.root_dispersion);
        println!("\tReference ID: {}", self.reference_identifier);
        println!("\tReference Timestamp: {}", self.reference_timestamp);
        println!("\tOrigin Timestamp: {}", self.originate_timestamp);
        println!("\tReceive Timestamp: {}", self.receive_timestamp);
        println!("\tTransmit Timestmap: {}", self.transmit_timestamp);
    }
}

impl NTPTimestamp {
    const NTP_TO_UNIX_EPOCH: u64 = 2_208_988_800;
    fn from_be_bytes(bytes: [u8; 8]) -> Self {
        let t_seconds = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
        let t_fraction = u32::from_be_bytes(bytes[4..8].try_into().unwrap());

        if t_seconds == 0 {
            return Self {
                t_seconds,
                t_fraction,
                datetime: OffsetDateTime::from_unix_timestamp(0).unwrap(),
            };
        }

        // in ntp Timestamp format epoch start from January 1, 1900
        let unix_secs = t_seconds as u64 - Self::NTP_TO_UNIX_EPOCH;

        // fraction to nanoseconds: (fraction * 10^9) / 2^32
        let nanos = (t_fraction as u64 * 1_000_000_000) >> 32;

        let total_nanos = (unix_secs as i128 * 1_000_000_000) + nanos as i128;

        let datetime = OffsetDateTime::from_unix_timestamp_nanos(total_nanos).unwrap();

        Self {
            t_seconds,
            t_fraction,
            datetime,
        }
    }
}

impl Display for NTPTimestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} UTC", self.datetime)
    }
}
