use crate::ipv4::IPv4Addr;
use crate::shared::{ParseError, take_next_bytes};

pub struct DnsPacket {
    header: DnsHeader,
    question: DnsQuestion,
    answers: Vec<DnsResourceRecord>,
}

struct DnsHeader {
    id: u16,
    // query or response flag
    qr: u8,
    opcode: u8,
    aa: u8,
    tc: u8,
    rd: u8,
    ra: u8,
    z: u8,
    rcode: u8,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

struct DnsQuestion {
    qname: String,
    qtype: u16,
    qclass: u16,
}

struct DnsResourceRecord {
    name: String,
    type_: u16,
    class: u16,
    ttl: u32,
    rdlength: u16,
    rdata: IPv4Addr,
}

impl DnsPacket {
    const HEADER_SIZE: usize = 12;
    pub fn try_parse(data: &[u8]) -> Result<DnsPacket, ParseError> {
        if data.len() < Self::HEADER_SIZE {
            return Err(ParseError::UnexpectedEOF);
        }

        let header_data = &data[..Self::HEADER_SIZE];
        let header = DnsHeader::try_parse(header_data)?;

        let mut cursor = &data[Self::HEADER_SIZE..];
        let question = DnsQuestion::try_parse(&mut cursor, data)?;

        let mut answers: Vec<DnsResourceRecord> = Vec::new();

        println!("ancount: {}", header.ancount);
        for _ in 0..header.ancount {
            let answer = DnsResourceRecord::try_parse(&mut cursor, data)?;
            answers.push(answer);
        }

        Ok(DnsPacket {
            header,
            question,
            answers,
        })
    }

    pub fn format_output(&self) {
        print!("Domain Name System ");
        if self.header.qr == 0 {
            print!("(query)");
        } else {
            print!("(response)");
        }
        println!();
        println!("\tID: 0x{:4x}", self.header.id);
        println!("\tQuestions: {}", self.header.qdcount);
        println!("\tAnswers: {}", self.header.ancount);
        println!("\tAuthority: {}", self.header.nscount);
        println!("\tAdditional: {}", self.header.arcount);
        println!("\tQueries:");
        println!("\t\tName: {}", self.question.qname);
        println!("\t\tType: {}", self.question.qtype);
        println!("\t\tClass: {}", self.question.qclass);

        println!("\tAnswers:");
        for (i, answer) in self.answers.iter().enumerate() {
            println!("\t\t{}. Name: {}", i + 1, answer.name);
            println!("\t\t   Type: {}", answer.type_);
            println!("\t\t   Class: {}", answer.class);
            println!("\t\t   TTL: {}", answer.ttl);
            println!("\t\t   Data length: {}", answer.rdlength);
            println!("\t\t   Addr: {}", answer.rdata);
        }
    }
}

impl DnsHeader {
    const MIN_SIZE: usize = 12;
    fn try_parse(data: &[u8]) -> Result<DnsHeader, ParseError> {
        if data.len() < Self::MIN_SIZE {
            return Err(ParseError::UnexpectedEOF);
        }

        let mut cursor = data;

        // first 2 bytes is id
        let id = u16::from_be_bytes(take_next_bytes::<2>(&mut cursor)?);

        // next 2 bytes = qr (1 bit) + opcode (4 bit) + aa (1 bit) + tc (1 bit) + rd (1 bit)
        // + ra (1 bit) + z (3 bit) + rcode (4 bit)
        let bytes = u16::from_be_bytes(take_next_bytes::<2>(&mut cursor)?);

        let qr = (bytes >> 15) as u8;
        let opcode = ((bytes >> 11) & 0x1F) as u8;
        let aa = ((bytes >> 10) & 0x1) as u8;
        let tc = ((bytes >> 9) & 0x1) as u8;
        let rd = ((bytes >> 8) & 0x1) as u8;
        let ra = ((bytes >> 7) & 0x1) as u8;
        let z = ((bytes >> 4) & 0x7) as u8;
        let rcode = (bytes & 0xF) as u8;

        // next 2 bytes is qdcount
        let qdcount = u16::from_be_bytes(take_next_bytes::<2>(&mut cursor)?);

        // next 2 bytes is ancount
        let ancount = u16::from_be_bytes(take_next_bytes::<2>(&mut cursor)?);

        // next 2 bytes nscount
        let nscount = u16::from_be_bytes(take_next_bytes::<2>(&mut cursor)?);

        // next 2 bytes arcount
        let arcount = u16::from_be_bytes(take_next_bytes::<2>(&mut cursor)?);

        Ok(DnsHeader {
            id,
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            z,
            rcode,
            qdcount,
            ancount,
            nscount,
            arcount,
        })
    }
}

impl DnsQuestion {
    fn try_parse<'a>(cursor: &mut &'a [u8], data: &'a [u8]) -> Result<DnsQuestion, ParseError> {
        let mut part_names: Vec<String> = Vec::new();
        // first field is name
        // first byte is lable length or offset (if 2 first bits as 11)
        let mut byte_len = u8::from_be_bytes(take_next_bytes::<1>(cursor)?);

        let mut with_compression = false;
        let mut ptr_cursor = *cursor;

        while byte_len != 0x00 {
            let type_len = byte_len & 0xC0;
            if type_len == 0x00 {
                // is len label
                let len = byte_len as usize;
                let (string_bytes, rest) = cursor.split_at(len);
                let name = str::from_utf8(string_bytes).map_err(|_| ParseError::UnexpectedEOF)?;
                part_names.push(String::from(name));
                *cursor = rest;
                byte_len = u8::from_be_bytes(take_next_bytes::<1>(cursor)?);
            } else if type_len == 0xC0 {
                // is offset (compression)
                // 14 bits is pointer offset
                let first_byte = byte_len & 0x3F;
                let second_byte = u8::from_be_bytes(take_next_bytes::<1>(cursor)?);
                let offset = ((first_byte as u16) << 8) | (second_byte as u16);
                byte_len = u8::from_be(data[offset as usize]);

                with_compression = true;
                ptr_cursor = *cursor;
                *cursor = &data[(offset + 1) as usize..];
            } else {
                eprintln!("opps...");
                return Err(ParseError::UnexpectedEOF);
            }
        }

        // если есть компрессия значит переходили в начало для чтения QNAME, поэтому теперь нужно
        // вернуться на позицию перед переходом чтобы прочитать следующие поля в dns question
        if with_compression {
            *cursor = ptr_cursor;
        }

        // next 2 byte is qtype
        let qtype = u16::from_be_bytes(take_next_bytes::<2>(cursor)?);
        // next 2 byte is qclass
        let qclass = u16::from_be_bytes(take_next_bytes::<2>(cursor)?);

        let qname = part_names.join(".");

        Ok(DnsQuestion {
            qname,
            qtype,
            qclass,
        })
    }
}

impl DnsResourceRecord {
    fn try_parse<'a>(
        cursor: &mut &'a [u8],
        data: &'a [u8],
    ) -> Result<DnsResourceRecord, ParseError> {
        let mut part_names: Vec<String> = Vec::new();
        // first field is name
        // first byte is lable length or offset (if 2 first bits as 11)
        let mut byte_len = u8::from_be_bytes(take_next_bytes::<1>(cursor)?);

        let mut with_compression = false;
        let mut ptr_cursor = *cursor;

        while byte_len != 0x00 {
            let type_len = byte_len & 0xC0;
            if type_len == 0x00 {
                // is len label
                let len = byte_len as usize;
                let (string_bytes, rest) = cursor.split_at(len);
                let name = str::from_utf8(string_bytes).map_err(|_| ParseError::UnexpectedEOF)?;
                part_names.push(String::from(name));
                *cursor = rest;
                byte_len = u8::from_be_bytes(take_next_bytes::<1>(cursor)?);
            } else if type_len == 0xC0 {
                // is offset (compression)
                // 14 bits is pointer offset
                let first_byte = byte_len & 0x3F;
                let second_byte = u8::from_be_bytes(take_next_bytes::<1>(cursor)?);
                let offset = ((first_byte as u16) << 8) | (second_byte as u16);
                byte_len = u8::from_be(data[offset as usize]);

                with_compression = true;
                ptr_cursor = *cursor;
                *cursor = &data[(offset + 1) as usize..];
            } else {
                eprintln!("opps...");
                return Err(ParseError::UnexpectedEOF);
            }
        }

        // если есть компрессия значит переходили в начало для чтения NAME, поэтому теперь нужно
        // вернуться на позицию перед переходом чтобы прочитать следующие поля в dns resource record
        if with_compression {
            *cursor = ptr_cursor;
        }

        // next 2 byte is qtype
        let type_ = u16::from_be_bytes(take_next_bytes::<2>(cursor)?);

        // next 2 byte is qclass
        let class = u16::from_be_bytes(take_next_bytes::<2>(cursor)?);

        // next 4 bytes is ttl
        let ttl = u32::from_be_bytes(take_next_bytes::<4>(cursor)?);

        // next 2 bytes ir rdlength
        let rdlength = u16::from_be_bytes(take_next_bytes::<2>(cursor)?);

        let rdata = match type_ {
            1 => {
                let (bytes, rest) = cursor.split_at(rdlength as usize);
                assert_eq!(bytes.len(), 4, "IPv4Addr must have 4 bytes length");
                let bytes: [u8; 4] = bytes.try_into().unwrap();
                *cursor = rest;
                IPv4Addr::from_bytes(bytes)
            }
            t => unimplemented!("Unhandled rdata type: {}", t),
        };

        let name = part_names.join(".");

        Ok(DnsResourceRecord {
            name,
            type_,
            class,
            ttl,
            rdlength,
            rdata,
        })
    }
}
