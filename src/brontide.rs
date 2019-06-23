use crate::acts::{ActOne, ActThree, ActTwo};
use crate::cipher_state::CipherState;
use crate::common::{PROLOGUE, TAG_SIZE, VERSION};
use crate::error::Error;
use crate::handshake::HandshakeState;
use crate::types::{PacketSize, PublicKey, SecretKey, Tag};
use crate::util::{ecdh, expand, get_public_key};
use crate::Result;

use secp256k1;

pub struct Brontide {
    handshake_state: HandshakeState,
    send_cipher: Option<CipherState>,
    receive_cipher: Option<CipherState>,
    packet_size: PacketSize,
}

pub struct BrontideBuilder {
    initiator: bool,
    local_secret: SecretKey,
    remote_public: Option<PublicKey>,
    prologue: Option<String>,
    packet_size: PacketSize,
    gen_key_func: Option<fn() -> Result<SecretKey>>,
}

impl BrontideBuilder {
    pub fn new<T: Into<SecretKey>>(local_secret: T) -> Self {
        BrontideBuilder {
            initiator: false,
            local_secret: local_secret.into(),
            //Probably declare Defaults for these down below.
            remote_public: None,
            prologue: None,
            //Packet size defaults to u32 which is what Handshake needs
            //put this into default
            packet_size: PacketSize::U32,
            gen_key_func: None,
        }
    }

    pub fn with_remote_public<T: Into<PublicKey>>(mut self, remote_public: T) -> Self {
        self.remote_public = Some(remote_public.into());
        self
    }

    pub fn with_prologue(mut self, prologue: &str) -> Self {
        self.prologue = Some(prologue.to_owned());
        self
    }

    pub fn with_packet_size(mut self, size: PacketSize) -> Self {
        self.packet_size = size;
        self
    }

    pub fn with_generate_key(mut self, gen_key_func: fn() -> Result<SecretKey>) -> Self {
        self.gen_key_func = Some(gen_key_func);
        self
    }

    pub fn initiator(mut self) -> Self {
        self.initiator = true;
        self
    }

    pub fn responder(mut self) -> Self {
        self.initiator = false;
        self
    }

    pub fn build(self) -> Brontide {
        let mut brontide = Brontide::new(
            self.initiator,
            self.local_secret,
            self.remote_public,
            self.prologue,
            self.packet_size,
        );

        if self.gen_key_func.is_some() {
            brontide.handshake_state.generate_key = self.gen_key_func.unwrap();
        };

        brontide
    }
}

impl Brontide {
    pub fn new(
        initiator: bool,
        local_pub: SecretKey,
        remote_pub: Option<PublicKey>,
        prologue: Option<String>,
        packet_size: PacketSize,
    ) -> Self {
        //I think Prologue needs to be an option here actually.
        //Copy the loop below this instead.
        let brontide_prologue: String;
        if prologue.is_some() {
            brontide_prologue = prologue.unwrap();
        } else {
            brontide_prologue = PROLOGUE.to_owned();
        };
        //TODO rename local pub

        let remote_pub_key: Option<PublicKey>;

        if let Some(key) = remote_pub {
            remote_pub_key = Some(key);
        } else {
            remote_pub_key = None;
        }

        Brontide {
            handshake_state: HandshakeState::new(
                initiator,
                &brontide_prologue,
                local_pub,
                remote_pub_key,
            ),
            send_cipher: None,
            receive_cipher: None,
            packet_size,
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
    //TODO also make this the write trait
    //TODO this might be test only as well.
    pub fn write(&mut self, data: Vec<u8>) -> Result<Vec<u8>> {
        let length = data.len();

        let max_length = self.packet_size.max();

        if length > max_length {
            return Err(Error::DataTooLarge("Data length too big".to_owned()));
        }

        let size = self.packet_size.size();

        let mut packet = Vec::with_capacity(size + TAG_SIZE + data.len() + TAG_SIZE);

        let length_buffer = self.packet_size.length_buffer(length);

        let mut cipher_text = Vec::with_capacity(size);
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
        let size = self.packet_size.size();
        let len = &packet[..size];
        let tag1 = Tag::from(&packet[size..18]);

        let mut plain_text = Vec::with_capacity(size);
        let result = self
            .receive_cipher
            .as_mut()
            .ok_or_else(|| Error::NoCipher("receive cipher not initalized".to_owned()))?
            .decrypt(&len, tag1, &[], &mut plain_text);

        let length: u16;
        let mut length_bytes = [0; 2];

        if result {
            length_bytes.copy_from_slice(&plain_text);
            length = u16::from_be_bytes(length_bytes);
        } else {
            return Err(Error::BadTag("packet header: bad tag".to_owned()));
        };

        let mut message = Vec::with_capacity(length as usize);

        if packet.len() != 16 + length as usize + 18 {
            return Err(Error::PacketBadSize("Packet not correct size".to_owned()));
        };

        let encrypted_message = &packet[18..18 + length as usize];
        let tag2 = Tag::from(&packet[18 + length as usize..]);

        if !self
            .receive_cipher
            .as_mut()
            .ok_or_else(|| Error::NoCipher("receive cipher not initalized".to_owned()))?
            .decrypt(encrypted_message, tag2, &[], &mut message)
        {
            return Err(Error::BadTag("packet message: bad tag".to_owned()));
        };

        Ok(message)
    }

    fn split(&mut self) {
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
