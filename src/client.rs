//! Client: connects to a bunker by EndpointId and issues requests.

use anyhow::{Context, Result};
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, SecretKey};
use iroh_mdns_address_lookup::MdnsAddressLookup;

use crate::proto::{self, Request, Response};

pub struct Client {
    endpoint: Endpoint,
    conn: iroh::endpoint::Connection,
}

impl Client {
    /// Connect using the n0 preset (relays + DNS/pkarr lookup, so a bare
    /// EndpointId works across NATs) plus mDNS lookup (resolve-only) for
    /// bunkers on the local network with no internet at all.
    pub async fn connect(secret: SecretKey, addr: impl Into<EndpointAddr>) -> Result<Self> {
        let endpoint = Endpoint::builder(presets::N0)
            .secret_key(secret)
            .address_lookup(MdnsAddressLookup::builder().advertise(false))
            .bind()
            .await
            .context("binding client endpoint")?;
        Self::with_endpoint(endpoint, addr).await
    }

    /// Connect over an existing endpoint (used by tests and embedders).
    pub async fn with_endpoint(endpoint: Endpoint, addr: impl Into<EndpointAddr>) -> Result<Self> {
        let conn = endpoint
            .connect(addr, proto::ALPN)
            .await
            .context("connecting to bunker")?;
        Ok(Client { endpoint, conn })
    }

    /// One request per bidirectional stream.
    pub async fn request(&self, req: &Request) -> Result<Response> {
        let (mut send, mut recv) = self
            .conn
            .open_bi()
            .await
            .context("opening request stream")?;
        send.write_all(&proto::encode(req)?)
            .await
            .context("sending request")?;
        send.finish().context("finishing request stream")?;
        let bytes = recv
            .read_to_end(proto::MAX_MSG)
            .await
            .context("reading response")?;
        proto::decode(&bytes).context("decoding response")
    }

    pub async fn close(self) {
        self.conn.close(0u32.into(), b"done");
        self.endpoint.close().await;
    }
}
