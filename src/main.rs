use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointAddr, EndpointId, TransportAddr};
use iroh_mdns_address_lookup::MdnsAddressLookup;

use secret_bunker_iroh::client::Client;
use secret_bunker_iroh::proto::{Request, Response};
use secret_bunker_iroh::server::Bunker;
use secret_bunker_iroh::store::{PERM_ADMIN, PERM_READ, PERM_WRITE, Store};
use secret_bunker_iroh::{crypto, keys};

#[derive(Parser)]
#[command(
    name = "secret-bunker-iroh",
    version,
    about = "Secrets bunker over iroh"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate an iroh endpoint secret key and print its EndpointId.
    KeygenEndpoint {
        /// File to write the secret key to (hex, mode 0600).
        #[arg(long)]
        out: PathBuf,
    },
    /// Generate an age X25519 identity and print its public recipient.
    KeygenAge {
        /// File to write the identity to (age format, mode 0600).
        #[arg(long)]
        out: PathBuf,
    },
    /// Initialize a new bunker database (one-shot).
    Init {
        #[arg(long)]
        db: PathBuf,
        /// Operational age identity file (private key stays with the server).
        #[arg(long)]
        operational_key: PathBuf,
        /// Backup age public key (`age1...`); private half stays offline.
        #[arg(long)]
        backup_pubkey: String,
        /// EndpointId (hex) of the first service admin.
        #[arg(long)]
        admin_id: String,
        #[arg(long, default_value = "admin")]
        admin_name: String,
    },
    /// Run the bunker.
    Serve {
        #[arg(long)]
        db: PathBuf,
        /// Iroh endpoint secret key file.
        #[arg(long)]
        endpoint_key: PathBuf,
        /// Operational age identity file.
        #[arg(long)]
        operational_key: PathBuf,
        /// Disable relays (direct connections only).
        #[arg(long)]
        no_relay: bool,
        /// Do not advertise or resolve on the local network via mDNS.
        #[arg(long)]
        no_mdns: bool,
    },
    /// Disaster recovery: re-wrap all group DEKs from the offline backup
    /// key to a new operational public key. Run offline, service stopped.
    Recover {
        #[arg(long)]
        db: PathBuf,
        /// Backup age identity file (normally kept offline).
        #[arg(long)]
        backup_key: PathBuf,
        /// New operational age public key (`age1...`).
        #[arg(long)]
        new_operational_pubkey: String,
    },
    /// Talk to a bunker.
    Client {
        /// This client's iroh endpoint secret key file.
        #[arg(long)]
        key: PathBuf,
        /// The bunker's EndpointId (hex).
        #[arg(long)]
        server: String,
        /// Direct socket address(es) of the bunker; when omitted, n0
        /// discovery resolves the EndpointId.
        #[arg(long)]
        server_addr: Vec<SocketAddr>,
        #[command(subcommand)]
        cmd: ClientCmd,
    },
}

#[derive(Subcommand)]
enum ClientCmd {
    /// Fetch a secret and write its value to stdout.
    Get {
        #[arg(long)]
        group: String,
        #[arg(long)]
        name: String,
    },
    /// Create (expected-version 0) or update a secret.
    Put {
        #[arg(long)]
        group: String,
        #[arg(long)]
        name: String,
        /// Value as a string; reads stdin when omitted.
        #[arg(long)]
        value: Option<String>,
        #[arg(long, default_value_t = 0)]
        expected_version: u64,
    },
    Delete {
        #[arg(long)]
        group: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        expected_version: u64,
    },
    /// List secrets in a group.
    Ls {
        #[arg(long)]
        group: String,
    },
    CreateGroup {
        name: String,
    },
    AddIdentity {
        #[arg(long)]
        name: String,
        /// EndpointId (hex) of the new identity.
        #[arg(long)]
        id: String,
        #[arg(long)]
        service_admin: bool,
    },
    RemoveIdentity {
        name: String,
    },
    ListIdentities,
    /// Set permissions ("r", "rw", "rwa", or "none") for an identity on a group.
    Grant {
        #[arg(long)]
        group: String,
        #[arg(long)]
        identity: String,
        #[arg(long)]
        perms: String,
    },
    RotateDek {
        #[arg(long)]
        group: String,
    },
}

fn parse_perms(s: &str) -> Result<u8> {
    if s == "none" {
        return Ok(0);
    }
    let mut perms = 0u8;
    for c in s.chars() {
        perms |= match c {
            'r' => PERM_READ,
            'w' => PERM_WRITE,
            'a' => PERM_ADMIN,
            _ => anyhow::bail!("invalid permission '{c}' (use r, w, a, or \"none\")"),
        };
    }
    Ok(perms)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "secret_bunker_iroh=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::KeygenEndpoint { out } => {
            let id = keys::generate_endpoint_key(&out)?;
            println!("{id}");
        }
        Cmd::KeygenAge { out } => {
            let recipient = keys::generate_age_identity(&out)?;
            println!("{recipient}");
        }
        Cmd::Init {
            db,
            operational_key,
            backup_pubkey,
            admin_id,
            admin_name,
        } => {
            let op = keys::load_age_identity(&operational_key)?;
            let backup = keys::parse_age_recipient(&backup_pubkey)?;
            let admin: EndpointId = admin_id.parse().context("parsing --admin-id")?;
            let mut store = Store::open(&db)?;
            store.init(
                &op.to_public().to_string(),
                &backup.to_string(),
                &admin.to_string(),
                &admin_name,
            )?;
            println!("initialized {}", db.display());
        }
        Cmd::Serve {
            db,
            endpoint_key,
            operational_key,
            no_relay,
            no_mdns,
        } => {
            let secret = keys::load_endpoint_key(&endpoint_key)?;
            let op = keys::load_age_identity(&operational_key)?;
            let store = Store::open(&db)?;
            let bunker = Bunker::new(store, op)?;
            // N0 presets publish to n0 pkarr/DNS and (unless --no-relay)
            // configure relays; hole punching is on by default, so clients
            // behind NATs can dial the bare EndpointId. mDNS additionally
            // announces on the local network for internet-free operation.
            let mut builder = if no_relay {
                Endpoint::builder(presets::N0DisableRelay)
            } else {
                Endpoint::builder(presets::N0)
            }
            .secret_key(secret);
            if !no_mdns {
                builder = builder.address_lookup(MdnsAddressLookup::builder());
            }
            let endpoint = builder
                .bind()
                .await
                .map_err(|e| anyhow::anyhow!("binding endpoint: {e}"))?;
            eprintln!("bunker endpoint id: {}", endpoint.id());
            for addr in endpoint.bound_sockets() {
                eprintln!("bound: {addr}");
            }
            let router = Router::builder(endpoint)
                .accept(secret_bunker_iroh::proto::ALPN, bunker)
                .spawn();
            if !no_relay {
                // Wait until at least one relay handshake completes, so the
                // printed EndpointId is actually dialable through NATs.
                match tokio::time::timeout(
                    std::time::Duration::from_secs(15),
                    router.endpoint().online(),
                )
                .await
                {
                    Ok(()) => eprintln!("online: reachable via relay"),
                    Err(_) => {
                        eprintln!("warning: no relay confirmed within 15s; continuing anyway")
                    }
                }
            }
            tokio::signal::ctrl_c().await?;
            eprintln!("shutting down");
            router
                .shutdown()
                .await
                .map_err(|e| anyhow::anyhow!("router shutdown: {e}"))?;
        }
        Cmd::Recover {
            db,
            backup_key,
            new_operational_pubkey,
        } => {
            let backup = keys::load_age_identity(&backup_key)?;
            let new_op = keys::parse_age_recipient(&new_operational_pubkey)?;
            let store = Store::open(&db)?;
            anyhow::ensure!(store.is_initialized()?, "database is not initialized");
            let mut rewrapped = 0usize;
            for (group_id, dek_row) in store.all_deks()? {
                let dek =
                    crypto::unwrap_dek(&dek_row.wrapped_backup, &backup).with_context(|| {
                        format!(
                            "unwrapping DEK v{} of group {group_id} with backup key",
                            dek_row.version
                        )
                    })?;
                let wrapped_op = crypto::wrap_dek(&dek, &new_op)?;
                store.replace_wrapped_operational(group_id, dek_row.version, &wrapped_op)?;
                rewrapped += 1;
            }
            store.meta_set("operational_pubkey", &new_op.to_string())?;
            println!("re-wrapped {rewrapped} DEK(s) to {new_op}");
        }
        Cmd::Client {
            key,
            server,
            server_addr,
            cmd,
        } => {
            let secret = keys::load_endpoint_key(&key)?;
            let server_id: EndpointId = server.parse().context("parsing --server")?;
            let addr = if server_addr.is_empty() {
                EndpointAddr::new(server_id)
            } else {
                EndpointAddr::from_parts(server_id, server_addr.into_iter().map(TransportAddr::Ip))
            };
            let client = Client::connect(secret, addr).await?;
            let req = match &cmd {
                ClientCmd::Get { group, name } => Request::Get {
                    group: group.clone(),
                    name: name.clone(),
                },
                ClientCmd::Put {
                    group,
                    name,
                    value,
                    expected_version,
                } => {
                    let value = match value {
                        Some(v) => v.clone().into_bytes(),
                        None => {
                            let mut buf = Vec::new();
                            std::io::stdin().read_to_end(&mut buf)?;
                            buf
                        }
                    };
                    Request::Put {
                        group: group.clone(),
                        name: name.clone(),
                        value,
                        expected_version: *expected_version,
                    }
                }
                ClientCmd::Delete {
                    group,
                    name,
                    expected_version,
                } => Request::Delete {
                    group: group.clone(),
                    name: name.clone(),
                    expected_version: *expected_version,
                },
                ClientCmd::Ls { group } => Request::List {
                    group: group.clone(),
                },
                ClientCmd::CreateGroup { name } => Request::CreateGroup { name: name.clone() },
                ClientCmd::AddIdentity {
                    name,
                    id,
                    service_admin,
                } => Request::AddIdentity {
                    name: name.clone(),
                    endpoint_id: id.clone(),
                    service_admin: *service_admin,
                },
                ClientCmd::RemoveIdentity { name } => {
                    Request::RemoveIdentity { name: name.clone() }
                }
                ClientCmd::ListIdentities => Request::ListIdentities,
                ClientCmd::Grant {
                    group,
                    identity,
                    perms,
                } => Request::Grant {
                    group: group.clone(),
                    identity: identity.clone(),
                    perms: parse_perms(perms)?,
                },
                ClientCmd::RotateDek { group } => Request::RotateDek {
                    group: group.clone(),
                },
            };
            let response = client.request(&req).await?;
            client.close().await;
            match response {
                Response::Secret { value, version } => {
                    eprintln!("version {version}");
                    std::io::stdout().write_all(&value)?;
                }
                Response::Version { version } => println!("version {version}"),
                Response::Ok => println!("ok"),
                Response::Names(names) => {
                    for (name, version) in names {
                        println!("{name}\tv{version}");
                    }
                }
                Response::Identities(ids) => {
                    for i in ids {
                        let admin = if i.service_admin {
                            "\tservice-admin"
                        } else {
                            ""
                        };
                        println!("{}\t{}{admin}", i.name, i.endpoint_id);
                    }
                }
                Response::VersionConflict { current } => {
                    eprintln!("version conflict: current version is {current}");
                    std::process::exit(2);
                }
                Response::Denied => {
                    eprintln!("denied");
                    std::process::exit(3);
                }
                Response::Failed { reason } => {
                    eprintln!("failed: {reason}");
                    std::process::exit(1);
                }
            }
        }
    }
    Ok(())
}
