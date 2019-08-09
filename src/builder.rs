use crate::Brontide;
use crate::Result;
use crate::{PacketSize, PublicKey, SecretKey};

#[cfg(feature = "stream")]
use crate::BrontideStream;
#[cfg(feature = "stream")]
use runtime::net::TcpStream;

// ===== BrontideBuilder =====

pub struct BrontideBuilder {
    initiator: bool,
    local_secret: SecretKey,
    remote_public: Option<PublicKey>,
    prologue: Option<String>,
    packet_size: PacketSize,
    gen_key_func: Option<fn() -> Result<SecretKey>>,
}

// ===== impl BrontideBuilder =====

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

    pub fn initiator<U: Into<PublicKey>>(mut self, remote_public: U) -> Self {
        self.remote_public = Some(remote_public.into());
        self.initiator = true;
        self
    }

    pub fn responder(mut self) -> Self {
        self.remote_public = None;
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

    #[cfg(feature = "stream")]
    pub async fn connect(self, hostname: &str) -> Result<BrontideStream> {
        let stream = TcpStream::connect(hostname).await?;

        let inner = Inner {
            waiting: HEADER_SIZE,
            has_size: false,
            total: 0,
            pending: Vec::new(),
            waker: AtomicWaker::new(),
        };

        Ok(BrontideStream {
            stream,
            inner,
            brontide: Brontide::new(
                self.initiator,
                self.local_secret,
                self.remote_public,
                self.prologue,
                self.packet_size,
            ),
        })
    }
}

//TODO add listen might also be "bind"
