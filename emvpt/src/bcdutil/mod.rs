pub fn bcd_to_ascii(bcd_data: &[u8]) -> Result<Vec<u8>, ()> {
    let mut ascii_output: Vec<u8> = Vec::with_capacity(bcd_data.len() * 2);

    const ASCII_CHARACTER_0: u8 = 0x30;

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
pub fn ascii_to_bcd_cn(ascii_data: &[u8], size: usize) -> Result<Vec<u8>, ()> {
    let mut bcd_output: Vec<u8> = Vec::with_capacity(size);

    assert!(ascii_data.len() <= size * 2);

    const ASCII_CHARACTER_0: u8 = 0x30;

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
pub fn ascii_to_bcd_n(ascii_data: &[u8], size: usize) -> Result<Vec<u8>, ()> {
    let mut bcd_output: Vec<u8> = Vec::with_capacity(size);

    assert!(ascii_data.len() <= size * 2);

    const ASCII_CHARACTER_0: u8 = 0x30;

    let mut ascii_data_aligned: Vec<u8> = Vec::new();
    if ascii_data.len() % 2 == 1 {
        ascii_data_aligned.push(ASCII_CHARACTER_0);
    }
    ascii_data_aligned.extend_from_slice(&ascii_data[..]);

    for _ in ascii_data_aligned.len() / 2..size {
        let bcd_byte = 0x00;
        bcd_output.push(bcd_byte);
    }

    for i in (0..ascii_data_aligned.len()).step_by(2) {
        let b1 = ascii_data_aligned[i] - ASCII_CHARACTER_0;
        if b1 > 0x9 {
            return Err(());
        }

        let b2 = ascii_data_aligned[i + 1] - ASCII_CHARACTER_0;
        if b2 > 0x9 {
            return Err(());
        }

        let bcd_byte = b2 + (b1 << 4);

        bcd_output.push(bcd_byte);
    }

    assert_eq!(bcd_output.len(), size);

    Ok(bcd_output)
}
