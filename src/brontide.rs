use crate::cipher_state::CipherState;
use crate::handshake::HandshakeState;

use crate::common::{PROLOGUE, VERSION};

use crate::util::{ecdh, expand, get_public_key};

use crate::error::Error;
use crate::Result;

use secp256k1::PublicKey;

//TODO let's review props in this struct
pub struct Brontide {
    //TODO this needs to be public *ONLY* to tests
    pub handshake_state: HandshakeState,
    //Not sure if going option is the way to go here, but for now it works
    send_cipher: Option<CipherState>,
    receive_cipher: Option<CipherState>,
}

//TODO need to implement errors in all of this.
impl Brontide {
    //TODO I DON't think we need this here.
    //TODO remove option if it's not used..
    pub fn new(
        initiator: bool,
        local_pub: [u8; 32],
        remote_pub: Option<[u8; 33]>,
        prologue: Option<&str>,
    ) -> Self {
        //I think Prologue needs to be an option here actually.
        let brontide_prologue: &str;
        if prologue.is_some() {
            brontide_prologue = prologue.unwrap();
        } else {
            brontide_prologue = PROLOGUE;
        };

        Brontide {
            handshake_state: HandshakeState::new(
                initiator,
                brontide_prologue,
                local_pub,
                remote_pub,
            ),
            send_cipher: None,
            receive_cipher: None,
        }
    }

    //TODO replace with ACT_ONE Custom type.
    pub fn gen_act_one(&mut self) -> [u8; 50] {
        // e
        self.handshake_state.local_ephemeral = (self.handshake_state.generate_key)();
        let ephemeral = get_public_key(self.handshake_state.local_ephemeral);
        //TODO double check this.
        self.handshake_state.symmetric.mix_digest(&ephemeral, None);

        //ec
        let s = ecdh(
            self.handshake_state.remote_static,
            self.handshake_state.local_ephemeral,
        );
        self.handshake_state.symmetric.mix_key(&s);

        //TODO needs to be an empty buffer of 32 bytes. - Make this a constant when moved to new
        //package
        //TODO decide whether this is 32 0s, or empty.
        let mut cipher_text = Vec::with_capacity(0);
        let tag = self
            .handshake_state
            .symmetric
            .encrypt_hash(&[], &mut cipher_text);

        //const ACT_ONE_SIZE = 50;
        // let act_one = Buffer::new();
        let mut act_one = [0_u8; 50];
        act_one[0] = VERSION;
        //Double check this operation TODO
        //Might have to splice from 1..ephemeral.len() + 1
        //Double check this TODO
        act_one[1..34].copy_from_slice(&ephemeral);

        //Double check this operation TODO
        //Might have to splice from 1...tag.len() + 34
        act_one[34..].copy_from_slice(&tag);

        act_one
    }

    pub fn recv_act_one(&mut self, act_one: [u8; 50]) -> Result<()> {
        if act_one[0] != VERSION {
            return Err(Error::Version("Act one: bad version.".to_owned()));
        }

        //TODO check these operations to ensure proper slicing //inclusive/exclusive etc.
        //TODO also check on the borrowing here, doesn't smell right.
        //I think this is to 33 - double check
        //TODO change this to be what I did for recv act two
        let e = &act_one[1..34];
        //TODO custom type.
        let mut p = [0; 16];
        p.copy_from_slice(&act_one[34..act_one.len()]);

        //We just want to verify here, might be an easier way than creating the actual key.
        //TODO
        let result = PublicKey::from_slice(e);

        if !result.is_ok() {
            return Err(Error::BadKey("Act one: bad key.".to_owned()));
        }

        //e
        //TODO code smell
        self.handshake_state.remote_ephemeral.copy_from_slice(e);
        self.handshake_state
            .symmetric
            .mix_digest(&self.handshake_state.remote_ephemeral, None);

        //es
        let s = ecdh(
            self.handshake_state.remote_ephemeral,
            self.handshake_state.local_static,
        );
        self.handshake_state.symmetric.mix_key(&s);

        let mut plain_text = Vec::with_capacity(0);
        //TODO must be empty buffer, not new buffer.
        //TODO code smell
        if !self
            .handshake_state
            .symmetric
            .decrypt_hash(&[], p, &mut plain_text)
        {
            return Err(Error::BadTag("Act one: bad tag".to_owned()));
        }

        Ok(())
    }

    //TODO custom type return
    pub fn gen_act_two(&mut self) -> [u8; 50] {
        // e
        self.handshake_state.local_ephemeral = (self.handshake_state.generate_key)();

        let ephemeral = get_public_key(self.handshake_state.local_ephemeral);

        self.handshake_state.symmetric.mix_digest(&ephemeral, None);

        // ee
        let s = ecdh(
            self.handshake_state.remote_ephemeral,
            self.handshake_state.local_ephemeral,
        );
        self.handshake_state.symmetric.mix_key(&s);

        //TODO again this needs to be empty buffer, NOT new buffer.
        //TODO empty or 0s?
        let mut cipher_text = Vec::with_capacity(0);
        let tag = self
            .handshake_state
            .symmetric
            .encrypt_hash(&[], &mut cipher_text);

        // const ACT_TWO_SIZE = 50;
        let mut act_two = [0_u8; 50];
        act_two[0] = VERSION;

        //TODO all the issues from act one apply here as well, this code needs to be thoroughly
        //checked and tested.
        act_two[1..34].copy_from_slice(&ephemeral);
        act_two[34..].copy_from_slice(&tag);

        act_two
    }

    pub fn recv_act_two(&mut self, act_two: [u8; 50]) -> Result<()> {
        if act_two[0] != VERSION {
            return Err(Error::Version("Act two: bad version.".to_owned()));
        }

        //TODO check these operations to ensure proper slicing //inclusive/exclusive etc.
        //TODO also check on the borrowing here, doesn't smell right.
        let mut e = [0; 33];
        e.copy_from_slice(&act_two[1..34]);

        //TODO
        let mut p = [0; 16];

        p.copy_from_slice(&act_two[34..]);

        //We just want to verify here, might be an easier way than creating the actual key.
        //TODO
        let result = PublicKey::from_slice(&e);

        if !result.is_ok() {
            return Err(Error::BadKey("Act two: bad key.".to_owned()));
        }

        //e
        //TODO code smell
        self.handshake_state.remote_ephemeral.copy_from_slice(&e);
        self.handshake_state
            .symmetric
            .mix_digest(&self.handshake_state.remote_ephemeral, None);

        //es
        let s = ecdh(
            self.handshake_state.remote_ephemeral,
            self.handshake_state.local_ephemeral,
        );
        self.handshake_state.symmetric.mix_key(&s);

        let mut plain_text = Vec::with_capacity(0);
        //TODO must be empty buffer, not new buffer.
        //TODO code smell
        if !self
            .handshake_state
            .symmetric
            .decrypt_hash(&[], p, &mut plain_text)
        {
            return Err(Error::BadTag("Act two: bad tag.".to_owned()));
        }

        Ok(())
    }

    //TODO custom act three type
    pub fn gen_act_three(&mut self) -> [u8; 66] {
        let our_pub_key = get_public_key(self.handshake_state.local_static);
        //We need to pass cipher text into here, since we don't encrypt in memory.
        //TODO double check sizing on here.
        let mut ct = Vec::with_capacity(33);
        let tag_1 = self
            .handshake_state
            .symmetric
            .encrypt_hash(&our_pub_key, &mut ct);
        // let ct = our_pub_key;

        let s = ecdh(
            self.handshake_state.remote_ephemeral,
            self.handshake_state.local_static,
        );

        self.handshake_state.symmetric.mix_key(&s);

        let mut cipher_text = Vec::with_capacity(0);
        let tag_2 = self
            .handshake_state
            .symmetric
            .encrypt_hash(&[], &mut cipher_text);

        //const ACT_THREE_SIZE = 66;
        let mut act_three = [0_u8; 66];
        act_three[0] = VERSION;

        //TODO code smell
        act_three[1..34].copy_from_slice(&ct);
        act_three[34..50].copy_from_slice(&tag_1);
        act_three[50..].copy_from_slice(&tag_2);

        self.split();

        act_three
    }

    //Code smell on our errors here -> They are in different order than the above functions.
    //TODO double check on that.
    pub fn recv_act_three(&mut self, act_three: [u8; 66]) -> Result<()> {
        if act_three[0] != VERSION {
            return Err(Error::Version("Act three: bad version.".to_owned()));
        }

        //TODO code smell here...
        let s1 = &act_three[1..34];
        let mut p1 = [0; 16];
        p1.copy_from_slice(&act_three[34..50]);
        // let s2 = &act_three[50..50];
        let mut p2 = [0; 16];
        p2.copy_from_slice(&act_three[50..]);

        let mut plain_text = Vec::with_capacity(s1.len());
        // s
        if !self
            .handshake_state
            .symmetric
            .decrypt_hash(s1, p1, &mut plain_text)
        {
            return Err(Error::BadTag("Act three: bad tag.".to_owned()));
        }

        let remote_public = plain_text;

        let result = PublicKey::from_slice(&remote_public);

        if result.is_err() {
            return Err(Error::BadKey("Act three: bad key.".to_owned()));
        }

        self.handshake_state
            .remote_static
            .copy_from_slice(&remote_public);

        // se
        let se = ecdh(
            self.handshake_state.remote_static,
            self.handshake_state.local_ephemeral,
        );
        self.handshake_state.symmetric.mix_key(&se);

        let mut plain_text = Vec::with_capacity(0);
        if !self
            .handshake_state
            .symmetric
            .decrypt_hash(&[], p2, &mut plain_text)
        {
            return Err(Error::BadTag("Act three: bad tag.".to_owned()));
        }

        self.split();

        Ok(())
    }

    //TODO write and read
    pub fn write(&mut self, data: Vec<u8>) -> Vec<u8> {
        //if data.len() <= 0xffff {
        //this is covered below in the u16 max
        //    //throw error -> Not sure what yet though TODO
        //}

        //Needs to be a packet of length 2 + 16 + data.len() + 16
        //TODO I think this is correct
        let mut packet = Vec::new();

        //Code smell
        //TODO only supposed to copy the len if it were a u16
        // packet.copy_from_slice(&data.len().to_be_bytes()[..1]);
        let length = data.len();

        if length > std::u16::MAX as usize {
            //Throw error here.
            //TODO
        }

        //TODO constants here are probably the way to go. - no magic numbers aka 2.
        let length_buffer = [0; 2];

        //Write the length
        packet.append(&mut length_buffer.to_vec());

        //TODO not sure this is the correct capacity.
        let mut cipher_text = Vec::with_capacity(2);
        //TODO we should probably make ciphers as non-options since they need to hold state.
        let mut tag = self
            .send_cipher
            .as_mut()
            .unwrap()
            //TODO catch error here, don't unwrap
            .encrypt(&length.to_be_bytes(), &[], &mut cipher_text)
            .unwrap();

        //Write the first tag
        packet.append(&mut tag);

        //Write the message
        packet.append(&mut data.clone());

        let mut cipher_text = Vec::with_capacity(length);
        let mut tag = self
            .send_cipher
            .as_mut()
            .unwrap()
            .encrypt(&data, &[], &mut cipher_text)
            //Catch this error.
            .unwrap();

        packet.append(&mut tag);

        packet
    }

    //TODO review thoroughly AND TEST
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
