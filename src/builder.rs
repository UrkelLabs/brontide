use crate::{Brontide, PacketSize, PublicKey, Result, SecretKey};

#[cfg(feature = "stream")]
use crate::BrontideStream;
#[cfg(feature = "stream")]
use runtime::net::TcpStream;

// ===== BrontideBuilder =====

#[must_use = "builders do nothing unless a build funciton (build, connect, accept) is called"]
#[derive(Debug, Default)]
pub struct BrontideBuilder {
    pub(crate) initiator: bool,
    pub(crate) local_secret: SecretKey,
    pub(crate) remote_public: Option<PublicKey>,
    pub(crate) prologue: Option<String>,
    pub(crate) packet_size: PacketSize,
    pub(crate) gen_key_func: Option<fn() -> Result<SecretKey>>,
}

// ===== impl BrontideBuilder =====

impl BrontideBuilder {
    /// Returns a new Brontide Builder. Requires a secret key as all brontide constructions require
    /// at least a secret key.
    pub fn new<T: Into<SecretKey>>(local_secret: T) -> Self {
        BrontideBuilder {
            local_secret: local_secret.into(),
            ..Default::default()
        }
    }

    /// Sets the prologue to be used in the brontide construction. This is typically used
    /// to different protocols.
    pub fn with_prologue(mut self, prologue: &str) -> Self {
        self.prologue = Some(prologue.to_owned());
        self
    }

    /// Sets the packet size for the brontide construction. This defaults to u32 which allows
    /// for packets up to 2.14 GB. u16 is used for lightning network, and is recommended for
    /// smaller protocols.
    pub fn with_packet_size(mut self, size: PacketSize) -> Self {
        self.packet_size = size;
        self
    }

    //TODO is this still necessary?
    pub fn with_generate_key(mut self, gen_key_func: fn() -> Result<SecretKey>) -> Self {
        self.gen_key_func = Some(gen_key_func);
        self
    }

    //TODO is initiator needed for brontide?
    /// Sets the underlying brontide construction to be a initiator.
    pub fn initiator<U: Into<PublicKey>>(mut self, remote_public: U) -> Self {
        self.remote_public = Some(remote_public.into());
        self.initiator = true;
        self
    }

    //Only used if building just a brontide, not a stream
    pub fn responder(mut self) -> Self {
        self.remote_public = None;
        self.initiator = false;
        self
    }

    pub fn build(self) -> Brontide {
        let mut brontide = Brontide::new(
            self.initiator,
            self.local_secret,
            self.remote_public, self.prologue,
            self.packet_size,
        );

        if self.gen_key_func.is_some() {
            brontide.handshake_state.generate_key = self.gen_key_func.unwrap();
        };

        brontide
    }

    #[cfg(feature = "stream")]
    pub async fn connect<U: Into<PublicKey>>(
        self,
        hostname: &str,
        remote_public: U,
    ) -> Result<BrontideStream> {
        let stream = TcpStream::connect(hostname).await?;
        let mut brontide = Brontide::new(
            true,
            self.local_secret,
            Some(remote_public.into()),
            self.prologue,
            self.packet_size,
        );

        if self.gen_key_func.is_some() {
            brontide.handshake_state.generate_key = self.gen_key_func.unwrap();
        };

        BrontideStream::connect(stream, brontide).await
    }

    #[cfg(feature = "stream")]
    pub async fn accept(self, stream: TcpStream) -> Result<BrontideStream> {
        //initiator = False
        let mut brontide = Brontide::new(
            false,
            self.local_secret,
            self.remote_public,
            self.prologue,
            self.packet_size,
        );

        if self.gen_key_func.is_some() {
            brontide.handshake_state.generate_key = self.gen_key_func.unwrap();
        };

        BrontideStream::accept(stream, brontide).await
    }
}
