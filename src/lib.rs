use chacha20poly1305::AeadInPlace;
use chacha20poly1305::aead::KeyInit;
use chacha20poly1305::XChaCha8Poly1305;

pub use chacha20poly1305::Key;
pub use chacha20poly1305::XNonce as Nonce;

/*pub fn generate_nonce () -> Nonce {
    XChaCha8Poly1305::generate_nonce(&mut OsRng)
}*/

pub use std::io::{Read, Write, Seek};

const BUFF_SIZE: usize = 1024*100;
const MAC_SIZE: usize = 16;

fn gen_nonce(prefix: &[u8; 20], counter: u32) -> Nonce {
    let mut nonce = Vec::with_capacity(24);
    nonce.extend_from_slice(prefix);
    nonce.extend_from_slice(&counter.to_le_bytes());
    Nonce::clone_from_slice(nonce.as_slice())
}

//-----------------------------
pub struct XChacha8Poly1305Writer<W: std::io::Write> {
    writer: W,
    cipher: XChaCha8Poly1305,
    nonce_prefix: [u8; 20],
    chunk_counter: u32,
    buffer: Vec<u8>, 
    crypt_data_len: usize,
}

impl<W: std::io::Write> XChacha8Poly1305Writer<W> {
    pub fn new(writer: W, key: &chacha20poly1305::Key, nonce: &Nonce) -> Self {               
        Self {
            writer, 
            cipher: XChaCha8Poly1305::new(key), 
            nonce_prefix: nonce[0..20].try_into().unwrap(), 
            chunk_counter: 0,
            buffer: Vec::with_capacity(BUFF_SIZE), 
            crypt_data_len: 0}
    }

    pub fn finalize(mut self) -> std::io::Result<W> {
        if self.buffer.len() > 0 { //otherwise there would be additional MAC for empty chunk
            self.cipher.encrypt_in_place(&gen_nonce(&self.nonce_prefix, self.chunk_counter), b"", &mut self.buffer).unwrap();
            self.chunk_counter += 1;
            self.writer.write_all(self.buffer.as_slice())?;
            self.crypt_data_len += self.buffer.len();
        }
        self.writer.flush()?;
        Ok(self.writer)
    }
}

impl<W: std::io::Write> std::io::Write for XChacha8Poly1305Writer<W> {
    fn write(&mut self, in_buf: &[u8]) -> std::io::Result<usize> {
        let mut in_idx: usize = 0;
        while in_idx != in_buf.len() {
            let available = BUFF_SIZE - self.buffer.len();
            if in_buf.len() - in_idx < available {
                self.buffer.extend_from_slice(&in_buf[in_idx..]);
                in_idx = in_buf.len();
            } else {
                self.buffer.extend_from_slice(&in_buf[in_idx..in_idx + available]);
                in_idx += available;
                //println!("before: {}", self.buffer.len());
                self.cipher.encrypt_in_place(&gen_nonce(&self.nonce_prefix, self.chunk_counter), b"", &mut self.buffer).unwrap();  
                self.chunk_counter += 1;              
                //println!("after: {}", self.buffer.len());
                self.writer.write_all(self.buffer.as_slice())?;
                self.crypt_data_len += self.buffer.len();
                self.buffer.clear();
            }
        }
        Ok(in_buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {                
        self.writer.flush()?;
        Ok(())   
    }
}

//-----------------------------

pub struct XChacha8Poly1305Reader<R: std::io::Read + std::io::Seek> {
    reader: R,
    cipher: XChaCha8Poly1305,
    nonce_prefix: [u8; 20],
    chunk_counter: u32,
    buffer: Vec<u8>, 
    buff_idx: usize,
}

impl<R: std::io::Read + std::io::Seek> XChacha8Poly1305Reader<R> {
    pub fn new(reader: R, key: &chacha20poly1305::Key, nonce: &Nonce) -> Self {        
        Self {reader, 
            cipher: XChaCha8Poly1305::new(key), 
            nonce_prefix: nonce[0..20].try_into().unwrap(), 
            chunk_counter: 0,
            buffer: Vec::with_capacity(BUFF_SIZE), 
            buff_idx: 0
        }
    }

    fn load_and_decrypt_next_chunk(&mut self) -> std::io::Result<usize>{
        use std::io::{Error, ErrorKind};
        self.buffer.resize(BUFF_SIZE+MAC_SIZE, 0);  //+16 for auth tag
        let len = self.reader.read(self.buffer.as_mut_slice())?;
        self.buffer.truncate(len); 
        self.buff_idx = 0;
        if len == 0 {return Ok(0);} // no more data available
        self.cipher.decrypt_in_place(&gen_nonce(&self.nonce_prefix, self.chunk_counter), b"", &mut self.buffer)
        .map_err(|_e| Error::new(ErrorKind::Other, "Decryption failed"))?;
        self.chunk_counter += 1;
        
        Ok(len)
    }
}

impl<R: std::io::Read + std::io::Seek> std::io::Read for XChacha8Poly1305Reader<R> {
    fn read(&mut self, out_buf: &mut [u8]) -> std::io::Result<usize> {
        let mut out_idx: usize = 0;

        while out_buf.len() > out_idx{
            if self.buffer.len() == self.buff_idx {  // read more data if nothing is available
                let loaded = self.load_and_decrypt_next_chunk()?;
                if loaded == 0 {return Ok(out_idx);}     
            }
            let bytes_available = self.buffer.len() - self.buff_idx;
            let bytes_left = out_buf.len() - out_idx;
            let bytes_to_copy = std::cmp::min(bytes_available, bytes_left);
            out_buf[out_idx .. out_idx+bytes_to_copy].copy_from_slice(&self.buffer.as_slice()[self.buff_idx .. self.buff_idx+bytes_to_copy]);
            self.buff_idx += bytes_to_copy;
            out_idx += bytes_to_copy;
        }        
        Ok(out_idx)
    }
}

impl<R: std::io::Read + std::io::Seek> std::io::Seek for XChacha8Poly1305Reader<R> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        use std::io::SeekFrom;
        let plain_pos = match pos {
            SeekFrom::Start(p) => p as usize,
            SeekFrom::End(p) => {
                let crypt_pos = self.reader.seek(SeekFrom::End(0)).unwrap() as usize;
                let plain_pos = crypt_pos - ((crypt_pos / (BUFF_SIZE + MAC_SIZE)) * MAC_SIZE);  //substract number of MACs in every chunk
                (plain_pos as i64 + p) as usize
            }
            SeekFrom::Current(p) => {
                let crypt_pos = self.reader.seek(SeekFrom::Current(0)).unwrap() as usize;
                let plain_pos = crypt_pos - ((crypt_pos / (BUFF_SIZE + MAC_SIZE)) * MAC_SIZE);  //substract number of MACs in every chunk
                (plain_pos as i64 + p) as usize 
            }
        };

        let chunk_idx = plain_pos / BUFF_SIZE;
        let chunk_start = chunk_idx * (BUFF_SIZE + MAC_SIZE);
        let chunk_offset = plain_pos % BUFF_SIZE;
        self.reader.seek(SeekFrom::Start(chunk_start as u64)).unwrap();
        self.chunk_counter = chunk_idx as u32;
        self.load_and_decrypt_next_chunk()?;
        self.buff_idx = chunk_offset;
        
        Ok(plain_pos as u64)
    }
}

//-----------------------------

#[cfg(test)]
mod test {
    use crate::*;

    #[test]
    fn test_incr_1(){
        for i in 1..10_000 {
            test_len(i);
        }        
    }

    #[test]
    fn test_incr_10_000(){
        for i in (1..10_000_000).step_by(51_111) {
            test_len(i);
        }        
    }
    #[test]
    fn test_incr_buff_size(){
        for i in BUFF_SIZE-100..BUFF_SIZE+100 {
            test_len(i);
        }        
    }
    fn test_len(plain_len: usize){
        let mut plain = Vec::with_capacity(plain_len);
        for i in 0..plain_len {
            plain.push((i % 256) as u8);
            
        }

        let mut crypt_buf = Vec::new();
        let mut writer = XChacha8Poly1305Writer::new(&mut crypt_buf, Key::from_slice(b"12345678901234567890123456789012"), Nonce::from_slice(b"123456789012345678901234"));
        writer.write_all(&plain).unwrap();
        writer.finalize().unwrap();

        let crypt_cur = std::io::Cursor::new(crypt_buf.clone());
        let mut reader = XChacha8Poly1305Reader::new(crypt_cur, Key::from_slice(b"wrong_key_wrong_key_wrong_key_wr"), Nonce::from_slice(b"123456789012345678901234"));
        let mut decrypt_buf = Vec::new();
        match reader.read_to_end(&mut decrypt_buf) {
            Ok(_) => panic!("Should have failed due to wrong key"),
            Err(_) => (),
        }
        assert_ne!(plain, decrypt_buf);

        let crypt_cur = std::io::Cursor::new(crypt_buf.clone());
        let mut reader = XChacha8Poly1305Reader::new(crypt_cur, Key::from_slice(b"12345678901234567890123456789012"), Nonce::from_slice(b"wrong_nonce_wrong_nonce_"));
        let mut decrypt_buf = Vec::new();
        match reader.read_to_end(&mut decrypt_buf) {
            Ok(_) => panic!("Should have failed due to wrong nonce"),
            Err(_) => (),
        }
        assert_ne!(plain, decrypt_buf);

        let crypt_cur = std::io::Cursor::new(crypt_buf.clone());
        let mut reader = XChacha8Poly1305Reader::new(crypt_cur, Key::from_slice(b"12345678901234567890123456789012"), Nonce::from_slice(b"123456789012345678901234"));
        let mut decrypt_buf: Vec<u8> = Vec::new();
        reader.read_to_end(&mut decrypt_buf).unwrap();
        assert_ne!(plain, crypt_buf);
        assert_ne!(decrypt_buf, crypt_buf);
        assert_eq!(plain, decrypt_buf);
    }

    #[test]
    fn seek(){
        let plain_len = 5*BUFF_SIZE;
        let mut plain = Vec::with_capacity(plain_len);
        for i in 0..plain_len {
            plain.push((i % 256) as u8);
            
        }

        let mut crypt_buf = Vec::new();
        let mut writer = XChacha8Poly1305Writer::new(&mut crypt_buf, Key::from_slice(b"12345678901234567890123456789012"), Nonce::from_slice(b"123456789012345678901234"));
        writer.write_all(&plain).unwrap();
        writer.finalize().unwrap();

        let crypt_cur = std::io::Cursor::new(crypt_buf.clone());
        let mut reader = XChacha8Poly1305Reader::new(crypt_cur, Key::from_slice(b"12345678901234567890123456789012"), Nonce::from_slice(b"123456789012345678901234"));
        
        seek_start_check(0, &mut reader);
        seek_start_check(1, &mut reader);
        seek_start_check(BUFF_SIZE*2-1, &mut reader);

        seek_start_check(1024, &mut reader);
        seek_start_check(1000, &mut reader);
        seek_start_check(BUFF_SIZE*4+24, &mut reader);

        let mut test_val = [0u8];
        reader.seek(std::io::SeekFrom::End(-1)).unwrap();
        reader.read_exact(&mut test_val).unwrap();
        assert_eq!(test_val[0], *plain.last().unwrap());

    }

    fn seek_start_check<R: Read + Seek>(test_pos: usize, reader: &mut R){
        let mut test_val = [0u8];
        reader.seek(std::io::SeekFrom::Start(test_pos as u64)).unwrap();
        reader.read_exact(&mut test_val).unwrap();
        assert_eq!(test_val[0], (test_pos % 256) as u8);
    }

}
