use crate::acts::{ActOne, ActThree, ActTwo};
use crate::cipher_state::CipherState;
use crate::common::{PACKET_LENGTH_SIZE, PROLOGUE, TAG_SIZE, VERSION};
use crate::error::Error;
use crate::handshake::HandshakeState;
use crate::types::{PublicKey, SecretKey, Tag};
use crate::util::{ecdh, expand, get_public_key};
use crate::Result;

use secp256k1;

pub struct Brontide {
    //TODO this needs to be public *ONLY* to tests
    pub handshake_state: HandshakeState,
    send_cipher: Option<CipherState>,
    receive_cipher: Option<CipherState>,
}

//Consider if we want to do this or not, might just require secret keys and pub keys to be passed
//in.
impl Brontide {
    pub fn new<L, R>(
        initiator: bool,
        local_pub: L,
        remote_pub: Option<R>,
        prologue: Option<&str>,
    ) -> Self
    where
        L: Into<SecretKey>,
        R: Into<PublicKey>,
    {
        //I think Prologue needs to be an option here actually.
        //Copy the loop below this instead.
        let brontide_prologue: &str;
        if prologue.is_some() {
            brontide_prologue = prologue.unwrap();
        } else {
            brontide_prologue = PROLOGUE;
        };
        //TODO rename local pub

        let remote_pub_key: Option<PublicKey>;

        if let Some(key) = remote_pub {
            remote_pub_key = Some(key.into());
        } else {
            remote_pub_key = None;
        }

        Brontide {
            handshake_state: HandshakeState::new(
                initiator,
                brontide_prologue,
                local_pub.into(),
                remote_pub_key,
            ),
            send_cipher: None,
            receive_cipher: None,
        }
    }

    pub fn gen_act_one(&mut self) -> Result<ActOne> {
        // e
        self.handshake_state.local_ephemeral = (self.handshake_state.generate_key)()?;
        let ephemeral = get_public_key(self.handshake_state.local_ephemeral)?;
        self.handshake_state.symmetric.mix_digest(&ephemeral, None);

        //ec
        let s = ecdh(
            self.handshake_state.remote_static,
            self.handshake_state.local_ephemeral,
        )?;
        self.handshake_state.symmetric.mix_key(&s);

        let mut cipher_text = Vec::with_capacity(0);
        let tag = self
            .handshake_state
            .symmetric
            .encrypt_hash(&[], &mut cipher_text)?;

        let act_one = ActOne::new(VERSION, ephemeral, tag);

        Ok(act_one)
    }

    pub fn recv_act_one(&mut self, act_one_bytes: [u8; 50]) -> Result<()> {
        let act_one = ActOne::from(act_one_bytes);

        if act_one.version() != VERSION {
            return Err(Error::Version("Act one: bad version.".to_owned()));
        }

        let e = act_one.key();
        let p = act_one.tag();
        //We just want to verify here, might be an easier way than creating the actual key.
        //TODO
        let result = secp256k1::PublicKey::from_slice(&e);

        if result.is_err() {
            return Err(Error::BadKey("Act one: bad key.".to_owned()));
        }

        //e
        self.handshake_state.remote_ephemeral = e;
        self.handshake_state
            .symmetric
            .mix_digest(&self.handshake_state.remote_ephemeral, None);

        //es
        let s = ecdh(
            self.handshake_state.remote_ephemeral,
            self.handshake_state.local_static,
        )?;
        self.handshake_state.symmetric.mix_key(&s);

        let mut plain_text = Vec::with_capacity(0);
        if !self
            .handshake_state
            .symmetric
            .decrypt_hash(&[], p, &mut plain_text)
        {
            return Err(Error::BadTag("Act one: bad tag".to_owned()));
        }

        Ok(())
    }

    pub fn gen_act_two(&mut self) -> Result<ActTwo> {
        // e
        self.handshake_state.local_ephemeral = (self.handshake_state.generate_key)()?;

        let ephemeral = get_public_key(self.handshake_state.local_ephemeral)?;
        self.handshake_state.symmetric.mix_digest(&ephemeral, None);

        // ee
        let s = ecdh(
            self.handshake_state.remote_ephemeral,
            self.handshake_state.local_ephemeral,
        )?;
        self.handshake_state.symmetric.mix_key(&s);

        let mut cipher_text = Vec::with_capacity(0);
        let tag = self
            .handshake_state
            .symmetric
            .encrypt_hash(&[], &mut cipher_text)?;

        let act_two = ActTwo::new(VERSION, ephemeral, tag);

        Ok(act_two)
    }

    pub fn recv_act_two(&mut self, act_two_bytes: [u8; 50]) -> Result<()> {
        let act_two = ActTwo::from(act_two_bytes);

        if act_two.version() != VERSION {
            return Err(Error::Version("Act two: bad version.".to_owned()));
        }

        let e = act_two.key();
        let p = act_two.tag();

        let result = secp256k1::PublicKey::from_slice(&e);

        if result.is_err() {
            return Err(Error::BadKey("Act two: bad key.".to_owned()));
        }

        //e
        self.handshake_state.remote_ephemeral = e;
        self.handshake_state
            .symmetric
            .mix_digest(&self.handshake_state.remote_ephemeral, None);

        //es
        let s = ecdh(
            self.handshake_state.remote_ephemeral,
            self.handshake_state.local_ephemeral,
        )?;
        self.handshake_state.symmetric.mix_key(&s);

        let mut plain_text = Vec::with_capacity(0);
        if !self
            .handshake_state
            .symmetric
            .decrypt_hash(&[], p, &mut plain_text)
        {
            return Err(Error::BadTag("Act two: bad tag.".to_owned()));
        }

        Ok(())
    }

    pub fn gen_act_three(&mut self) -> Result<ActThree> {
        let our_pub_key = get_public_key(self.handshake_state.local_static)?;

        //TODO let's get this number harded in ActThree.ct size?
        //no magic numbers
        let mut ct = Vec::with_capacity(33);
        let tag_1 = self
            .handshake_state
            .symmetric
            .encrypt_hash(&our_pub_key, &mut ct)?;

        let s = ecdh(
            self.handshake_state.remote_ephemeral,
            self.handshake_state.local_static,
        )?;

        self.handshake_state.symmetric.mix_key(&s);

        let mut cipher_text = Vec::with_capacity(0);
        let tag_2 = self
            .handshake_state
            .symmetric
            .encrypt_hash(&[], &mut cipher_text)?;

        let act_three = ActThree::new(VERSION, ct, tag_1, tag_2);

        self.split();

        Ok(act_three)
    }

    pub fn recv_act_three(&mut self, act_three_bytes: [u8; 66]) -> Result<()> {
        let act_three = ActThree::from(act_three_bytes);

        if act_three.version() != VERSION {
            return Err(Error::Version("Act three: bad version.".to_owned()));
        }

        let s1 = act_three.key();
        let p1 = act_three.tag();
        let s2: &[u8] = &[];
        let p2 = act_three.tag_two();

        let mut plain_text = Vec::with_capacity(s1.len());

        // s
        if !self
            .handshake_state
            .symmetric
            .decrypt_hash(&s1, p1, &mut plain_text)
        {
            return Err(Error::BadTag("Act three: bad tag.".to_owned()));
        }

        let remote_public = plain_text;

        let result = secp256k1::PublicKey::from_slice(&remote_public);

        if result.is_err() {
            return Err(Error::BadKey("Act three: bad key.".to_owned()));
        }

        self.handshake_state.remote_static = PublicKey::from(remote_public.as_slice());

        // se
        let se = ecdh(
            self.handshake_state.remote_static,
            self.handshake_state.local_ephemeral,
        )?;
        self.handshake_state.symmetric.mix_key(&se);

        let mut plain_text = Vec::with_capacity(0);
        if !self
            .handshake_state
            .symmetric
            .decrypt_hash(s2, p2, &mut plain_text)
        {
            return Err(Error::BadTag("Act three: bad tag.".to_owned()));
        }

        self.split();

        Ok(())
    }

    //TODO think about making a packet a struct and impl these on it
    pub fn write(&mut self, data: Vec<u8>) -> Result<Vec<u8>> {
        let length = data.len();

        if length > std::u16::MAX as usize {
            return Err(Error::DataTooLarge("Data length too big".to_owned()));
        }

        let mut packet = Vec::with_capacity(PACKET_LENGTH_SIZE + TAG_SIZE + data.len() + TAG_SIZE);

        let length_shortened = length as u16;
        let mut length_buffer = [0; PACKET_LENGTH_SIZE];
        length_buffer.copy_from_slice(&length_shortened.to_be_bytes());

        let mut cipher_text = Vec::with_capacity(PACKET_LENGTH_SIZE);
        let tag =
            self.send_cipher
                .as_mut()
                .unwrap()
                .encrypt(&length_buffer, &[], &mut cipher_text)?;

        //Write the encrypted data length, and the first tag.
        packet.append(&mut cipher_text);
        packet.append(&mut tag.to_vec());

        let mut cipher_text = Vec::with_capacity(length);
        let tag = self
            .send_cipher
            .as_mut()
            .ok_or_else(|| Error::NoCipher("send cipher not initalized".to_owned()))?
            .encrypt(&data, &[], &mut cipher_text)?;

        //Write the encrypted data, and the second tag.
        packet.append(&mut cipher_text);
        packet.append(&mut tag.to_vec());

        Ok(packet)
    }

    pub fn read(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        let len = &packet[..2];
        let tag1 = Tag::from(&packet[2..18]);

        let mut plain_text = Vec::with_capacity(PACKET_LENGTH_SIZE);
        let result = self
            .receive_cipher
            .as_mut()
            .ok_or_else(|| Error::NoCipher("receive cipher not initalized".to_owned()))?
            .decrypt(&len, tag1, &[], &mut plain_text);

        let mut length: u16 = 0;
        let mut length_bytes = [0; 2];

        if result {
            length_bytes.copy_from_slice(&plain_text);
            length = u16::from_be_bytes(length_bytes);
        } else {
            //throw error
        };

        let mut message = Vec::with_capacity(length as usize);

        if packet.len() != 16 + length as usize + 18 {
            //Throw error
            println!("bad size");
        };

        let encrypted_message = &packet[18..18 + length as usize];
        let tag2 = Tag::from(&packet[18 + length as usize..]);

        if !self.receive_cipher.as_mut().unwrap().decrypt(
            encrypted_message,
            tag2,
            &[],
            &mut message,
        ) {
            //Throw error in here.
        };

        Ok(message)
    }

    //TODO review thoroughly AND TEST
    //TODO I don't think this should be public
    pub fn split(&mut self) {
        //TODO must be buffer empty not new
        let (h1, h2) = expand(&[], &self.handshake_state.symmetric.chaining_key);

        if self.handshake_state.initiator {
            let send_key = h1;
            self.send_cipher = Some(CipherState::new(
                send_key,
                self.handshake_state.symmetric.chaining_key,
            ));
            let recv_key = h2;
            self.receive_cipher = Some(CipherState::new(
                recv_key,
                self.handshake_state.symmetric.chaining_key,
            ));
        } else {
            let recv_key = h1;
            self.receive_cipher = Some(CipherState::new(
                recv_key,
                self.handshake_state.symmetric.chaining_key,
            ));
            let send_key = h2;
            self.send_cipher = Some(CipherState::new(
                send_key,
                self.handshake_state.symmetric.chaining_key,
            ));
        }
    }

    pub fn initiator(&self) -> bool {
        self.handshake_state.initiator
    }
}
