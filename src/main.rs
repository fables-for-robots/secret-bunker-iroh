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
use secret_bunker_iroh::keys::KeyRole;
use secret_bunker_iroh::proto::{Request, Response};
use secret_bunker_iroh::server::Bunker;
use secret_bunker_iroh::store::{AuditVerification, PERM_ADMIN, PERM_READ, PERM_WRITE, Store};
use secret_bunker_iroh::{crypto, keys};
use zeroize::Zeroize;

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
    /// Show, import, or export the keys in the XDG data directory.
    Key {
        #[command(subcommand)]
        cmd: KeyCmd,
    },
    /// Initialize a new bunker database (one-shot).
    Init {
        #[arg(long)]
        db: PathBuf,
        /// Operational age identity file. Defaults to the XDG data dir,
        /// auto-generating there when missing.
        #[arg(long)]
        operational_key: Option<PathBuf>,
        /// Backup age public key (`age1...`); private half stays offline.
        /// When omitted, a backup identity is generated in the XDG data
        /// dir — export it and move it offline.
        #[arg(long)]
        backup_pubkey: Option<String>,
        /// EndpointId (hex) of the first service admin. Defaults to this
        /// machine's client key, auto-generating it when missing.
        #[arg(long)]
        admin_id: Option<String>,
        #[arg(long, default_value = "admin")]
        admin_name: String,
    },
    /// Run the bunker.
    Serve {
        #[arg(long)]
        db: PathBuf,
        /// Iroh endpoint secret key file. Defaults to the XDG data dir,
        /// auto-generating there when missing.
        #[arg(long)]
        endpoint_key: Option<PathBuf>,
        /// Operational age identity file. Defaults to the XDG data dir,
        /// auto-generating there when missing.
        #[arg(long)]
        operational_key: Option<PathBuf>,
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
    /// Manage server aliases stored in the XDG data dir.
    Server {
        #[command(subcommand)]
        cmd: ServerCmd,
    },
    /// Local database maintenance, run directly against the SQLite file
    /// (stop the server first).
    Db {
        #[command(subcommand)]
        cmd: DbCmd,
    },
    /// Interactive terminal UI (role-aware: user, group admin, service admin).
    Tui {
        /// This client's iroh endpoint secret key file. Defaults to the
        /// XDG data dir, auto-generating there when missing.
        #[arg(long)]
        key: Option<PathBuf>,
        /// The bunker's EndpointId (hex) or a server alias. Defaults to
        /// the "default" alias.
        #[arg(long)]
        server: Option<String>,
        /// Direct socket address(es) of the bunker; when omitted, n0
        /// discovery resolves the EndpointId.
        #[arg(long)]
        server_addr: Vec<SocketAddr>,
    },
    /// Talk to a bunker.
    Client {
        /// This client's iroh endpoint secret key file. Defaults to the
        /// XDG data dir, auto-generating there when missing.
        #[arg(long)]
        key: Option<PathBuf>,
        /// The bunker's EndpointId (hex) or a server alias. Defaults to
        /// the "default" alias.
        #[arg(long)]
        server: Option<String>,
        /// Direct socket address(es) of the bunker; when omitted, n0
        /// discovery resolves the EndpointId.
        #[arg(long)]
        server_addr: Vec<SocketAddr>,
        #[command(subcommand)]
        cmd: ClientCmd,
    },
}

#[derive(Subcommand)]
enum ServerCmd {
    /// Map an alias to a bunker EndpointId. The alias "default" is used
    /// whenever --server is omitted.
    Add {
        name: String,
        /// The bunker's EndpointId (hex).
        id: String,
        /// Replace the alias if it already exists.
        #[arg(long)]
        force: bool,
    },
    /// Remove an alias.
    Rm { name: String },
    /// List aliases.
    Ls,
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
    /// List groups you can see (service admins see all groups).
    ListGroups,
    /// Show a group's ACL (requires admin on the group).
    Acl {
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

#[derive(Subcommand)]
enum DbCmd {
    /// Set permissions directly in the database, bypassing the wire ACL
    /// checks: the recovery path for a group whose last admin is gone.
    Grant {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        group: String,
        #[arg(long)]
        identity: String,
        /// "r", "rw", "rwa", or "none".
        #[arg(long)]
        perms: String,
    },
    /// Verify the audit log hash chain and print the head entry. Record
    /// the head externally: the chain proves in-place integrity, but only
    /// an external anchor detects truncation.
    AuditVerify {
        #[arg(long)]
        db: PathBuf,
    },
}

#[derive(Subcommand)]
enum KeyCmd {
    /// List key locations and their public identifiers.
    Show,
    /// Ensure a key exists (generating it when missing) and print its
    /// public identifier. Idempotent.
    Generate {
        #[arg(value_enum)]
        role: KeyRole,
    },
    /// Print a key's secret material (canonical form) to stdout or --out.
    Export {
        #[arg(value_enum)]
        role: KeyRole,
        /// Write to this file (mode 0600) instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Import secret key material from --in (or stdin) into the XDG data dir.
    Import {
        #[arg(value_enum)]
        role: KeyRole,
        /// Read from this file instead of stdin.
        #[arg(long = "in")]
        input: Option<PathBuf>,
        /// Overwrite an existing key. The old key is irrecoverable
        /// afterwards unless exported first.
        #[arg(long)]
        force: bool,
    },
}

/// Resolve a key path: an explicit path must exist (no silent identity
/// minting on typos); the default XDG path is auto-generated when missing.
fn resolve_endpoint_key(explicit: Option<PathBuf>, role: KeyRole) -> Result<iroh::SecretKey> {
    match explicit {
        Some(path) => keys::load_endpoint_key(&path),
        None => {
            let path = keys::default_key_path(role)?;
            let (secret, generated) = keys::load_or_generate_endpoint_key(&path)?;
            if generated {
                eprintln!(
                    "generated new {} key at {} (endpoint id: {})",
                    role.filename(),
                    path.display(),
                    secret.public()
                );
            }
            Ok(secret)
        }
    }
}

fn resolve_operational_key(explicit: Option<PathBuf>) -> Result<age::x25519::Identity> {
    match explicit {
        Some(path) => keys::load_age_identity(&path),
        None => {
            let path = keys::default_key_path(KeyRole::Operational)?;
            let (identity, generated) = keys::load_or_generate_age_identity(&path)?;
            if generated {
                eprintln!(
                    "generated new operational key at {} (recipient: {})",
                    path.display(),
                    identity.to_public()
                );
            }
            Ok(identity)
        }
    }
}

fn run_key_cmd(cmd: KeyCmd) -> Result<()> {
    match cmd {
        KeyCmd::Show => {
            for role in [
                KeyRole::Client,
                KeyRole::Server,
                KeyRole::Operational,
                KeyRole::Backup,
            ] {
                let path = keys::default_key_path(role)?;
                let status = if path.exists() {
                    keys::public_identifier(role, &path)?
                } else {
                    "(not generated yet)".into()
                };
                println!("{:<16} {}  {}", role.filename(), path.display(), status);
            }
        }
        KeyCmd::Generate { role } => {
            let path = keys::default_key_path(role)?;
            let generated = if role.is_age() {
                keys::load_or_generate_age_identity(&path)?.1
            } else {
                keys::load_or_generate_endpoint_key(&path)?.1
            };
            if generated {
                eprintln!("generated {}", path.display());
            }
            println!("{}", keys::public_identifier(role, &path)?);
        }
        KeyCmd::Export { role, out } => {
            let path = keys::default_key_path(role)?;
            anyhow::ensure!(
                path.exists(),
                "{} does not exist; nothing to export",
                path.display()
            );
            let contents = std::fs::read_to_string(&path)?;
            let canonical = keys::canonicalize_key_material(role, &contents)?;
            match out {
                Some(out) => {
                    keys::import_key(role, &out, &canonical, false)?;
                    eprintln!("exported to {}", out.display());
                }
                None => {
                    eprintln!("warning: printing SECRET key material to stdout");
                    print!("{canonical}");
                }
            }
        }
        KeyCmd::Import { role, input, force } => {
            let contents = match &input {
                Some(path) => std::fs::read_to_string(path)
                    .with_context(|| format!("reading {}", path.display()))?,
                None => {
                    let mut buf = String::new();
                    std::io::stdin().read_to_string(&mut buf)?;
                    buf
                }
            };
            let path = keys::default_key_path(role)?;
            keys::import_key(role, &path, &contents, force)?;
            eprintln!(
                "imported {} to {} ({})",
                role.filename(),
                path.display(),
                keys::public_identifier(role, &path)?
            );
        }
    }
    Ok(())
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
            let secret = keys::generate_endpoint_key(&out)?;
            println!("{}", secret.public());
        }
        Cmd::KeygenAge { out } => {
            let identity = keys::generate_age_identity(&out)?;
            println!("{}", identity.to_public());
        }
        Cmd::Key { cmd } => run_key_cmd(cmd)?,
        Cmd::Init {
            db,
            operational_key,
            backup_pubkey,
            admin_id,
            admin_name,
        } => {
            let op = resolve_operational_key(operational_key)?;
            let backup = match backup_pubkey {
                Some(s) => keys::parse_age_recipient(&s)?,
                None => {
                    let path = keys::default_key_path(KeyRole::Backup)?;
                    let (identity, generated) = keys::load_or_generate_age_identity(&path)?;
                    let recipient = identity.to_public();
                    if generated {
                        eprintln!(
                            "generated new backup key at {} (recipient: {})",
                            path.display(),
                            recipient
                        );
                        eprintln!(
                            "IMPORTANT: the backup key is your disaster-recovery key. Move it \
                             OFFLINE: `key export backup --out <file>`, store the file safely, \
                             then delete {} from this machine.",
                            path.display()
                        );
                    } else {
                        eprintln!(
                            "using existing backup key at {} (recipient: {})",
                            path.display(),
                            recipient
                        );
                    }
                    recipient
                }
            };
            let admin: EndpointId = match admin_id {
                Some(s) => s.parse().context("parsing --admin-id")?,
                None => {
                    let id = resolve_endpoint_key(None, KeyRole::Client)?.public();
                    eprintln!("admin identity: {id} (this machine's client.key)");
                    id
                }
            };
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
            let secret = resolve_endpoint_key(endpoint_key, KeyRole::Server)?;
            let op = resolve_operational_key(operational_key)?;
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
            let mut store = Store::open(&db)?;
            anyhow::ensure!(store.is_initialized()?, "database is not initialized");
            // Re-wrap everything in memory first, then apply in one
            // transaction: a failure part-way must not leave a database
            // that is half old-key, half new-key.
            let mut rewrapped = Vec::new();
            for (group_id, dek_row) in store.all_deks()? {
                let dek =
                    crypto::unwrap_dek(&dek_row.wrapped_backup, &backup).with_context(|| {
                        format!(
                            "unwrapping DEK v{} of group {group_id} with backup key",
                            dek_row.version
                        )
                    })?;
                rewrapped.push((group_id, dek_row.version, crypto::wrap_dek(&dek, &new_op)?));
            }
            let count = rewrapped.len();
            store.apply_recovery(&rewrapped, &new_op.to_string())?;
            println!("re-wrapped {count} DEK(s) to {new_op}");
        }
        Cmd::Db { cmd } => match cmd {
            DbCmd::Grant {
                db,
                group,
                identity,
                perms,
            } => {
                let store = Store::open(&db)?;
                anyhow::ensure!(store.is_initialized()?, "database is not initialized");
                let perms = parse_perms(&perms)?;
                let gid = store
                    .group_id(&group)?
                    .with_context(|| format!("no group named '{group}'"))?;
                let target = store
                    .identity_by_name(&identity)?
                    .with_context(|| format!("no identity named '{identity}'"))?;
                store.set_perms(target.id, gid, perms)?;
                store.audit("(local)", "db-grant", &format!("{group}:{identity}"), "ok")?;
                println!(
                    "granted [{}] on '{group}' to '{identity}'",
                    secret_bunker_iroh::proto::perms_str(perms)
                );
            }
            DbCmd::AuditVerify { db } => {
                let store = Store::open(&db)?;
                match store.verify_audit_chain()? {
                    AuditVerification::Valid { entries, head } => match head {
                        Some((seq, hash)) => println!(
                            "ok: {entries} entries, head seq {seq} hash {}",
                            data_encoding::HEXLOWER.encode(&hash)
                        ),
                        None => println!("ok: audit log is empty (nothing to verify, no head)"),
                    },
                    AuditVerification::Broken { seq } => {
                        eprintln!("audit chain BROKEN at seq {seq}");
                        std::process::exit(1);
                    }
                }
            }
        },
        Cmd::Server { cmd } => match cmd {
            ServerCmd::Add { name, id, force } => {
                let id: EndpointId = id.parse().context("parsing endpoint id")?;
                secret_bunker_iroh::servers::add(&name, id, force)?;
                println!("{name} -> {id}");
            }
            ServerCmd::Rm { name } => {
                anyhow::ensure!(
                    secret_bunker_iroh::servers::remove(&name)?,
                    "no alias named '{name}'"
                );
                println!("removed {name}");
            }
            ServerCmd::Ls => {
                for (name, id) in secret_bunker_iroh::servers::list()? {
                    println!("{name}\t{id}");
                }
            }
        },
        Cmd::Tui {
            key,
            server,
            server_addr,
        } => {
            use std::io::IsTerminal;
            anyhow::ensure!(
                std::io::stdout().is_terminal(),
                "the TUI needs an interactive terminal"
            );
            let secret = resolve_endpoint_key(key, KeyRole::Client)?;
            let my_id = secret.public().to_string();
            let server_id = secret_bunker_iroh::servers::resolve(server.as_deref())?;
            let addr = if server_addr.is_empty() {
                EndpointAddr::new(server_id)
            } else {
                EndpointAddr::from_parts(server_id, server_addr.into_iter().map(TransportAddr::Ip))
            };
            let client = Client::connect(secret, addr).await?;
            let handle = tokio::runtime::Handle::current();
            tokio::task::spawn_blocking(move || {
                secret_bunker_iroh::tui::run(handle, client, my_id)
            })
            .await??;
        }
        Cmd::Client {
            key,
            server,
            server_addr,
            cmd,
        } => {
            let secret = resolve_endpoint_key(key, KeyRole::Client)?;
            let server_id = secret_bunker_iroh::servers::resolve(server.as_deref())?;
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
                        Some(v) => {
                            eprintln!(
                                "warning: --value exposes the secret to the local process list; prefer piping it via stdin"
                            );
                            v.clone().into_bytes()
                        }
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
                ClientCmd::ListGroups => Request::ListGroups,
                ClientCmd::Acl { group } => Request::GroupAcl {
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
                Response::Secret { mut value, version } => {
                    eprintln!("version {version}");
                    std::io::stdout().write_all(&value)?;
                    value.zeroize();
                }
                Response::Version { version } => println!("version {version}"),
                Response::Ok => println!("ok"),
                Response::Names(names) => {
                    for (name, version) in names {
                        println!("{name}\tv{version}");
                    }
                }
                Response::Groups {
                    service_admin,
                    groups,
                } => {
                    if service_admin {
                        eprintln!("role: service admin (all groups shown)");
                    }
                    for g in groups {
                        println!(
                            "{}\t[{}]",
                            g.name,
                            secret_bunker_iroh::proto::perms_str(g.perms)
                        );
                    }
                }
                Response::Acl(entries) => {
                    for (identity, perms) in entries {
                        println!(
                            "{identity}\t[{}]",
                            secret_bunker_iroh::proto::perms_str(perms)
                        );
                    }
                }
                Response::IdentityNames(names) => {
                    for name in names {
                        println!("{name}");
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
