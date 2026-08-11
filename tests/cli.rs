//! CLI end-to-end test: a real `serve` process and separate `client`
//! process invocations, each with its own XDG data directory. Exercises
//! key auto-generation, exit codes, and stdout/stdin handling — the same
//! permission lifecycle as the protocol tests, but through the binary.

use std::ffi::OsStr;
use std::fmt::Debug;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_secret-bunker-iroh");

/// Exit codes the CLI maps responses to.
const EXIT_CONFLICT: i32 = 2;
const EXIT_DENIED: i32 = 3;
const EXIT_READ_ONLY: i32 = 4;

/// One CLI actor: a set of invocations sharing an XDG data directory
/// (and therefore an auto-generated identity).
struct Actor {
    xdg: PathBuf,
}

impl Actor {
    fn new(root: &Path, name: &str) -> Self {
        Actor {
            xdg: root.join(name),
        }
    }

    fn run<S: AsRef<OsStr> + Debug>(&self, args: &[S], stdin: Option<&[u8]>) -> Output {
        let mut child = Command::new(BIN)
            .args(args)
            .env("XDG_DATA_HOME", &self.xdg)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawning CLI");
        if let Some(bytes) = stdin {
            child.stdin.take().unwrap().write_all(bytes).unwrap();
        }
        child.wait_with_output().expect("waiting for CLI")
    }

    /// Run and require success; returns trimmed stdout.
    fn expect_ok<S: AsRef<OsStr> + Debug>(&self, args: &[S], stdin: Option<&[u8]>) -> String {
        let out = self.run(args, stdin);
        assert!(
            out.status.success(),
            "command {args:?} failed (status {:?}): {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    }

    /// Run until the command succeeds or `timeout` elapses. For steps that
    /// wait on an asynchronous convergence — a replica finding the
    /// authoritative node and applying its manifest — where a single sleep
    /// would be a guess.
    fn expect_ok_within<S: AsRef<OsStr> + Debug>(&self, timeout: Duration, args: &[S]) -> String {
        let deadline = Instant::now() + timeout;
        loop {
            let out = self.run(args, None);
            if out.status.success() {
                return String::from_utf8(out.stdout).unwrap().trim().to_string();
            }
            assert!(
                Instant::now() < deadline,
                "command {args:?} never succeeded (last status {:?}): {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr)
            );
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    /// Run and require the given failure exit code.
    fn expect_exit<S: AsRef<OsStr> + Debug>(&self, code: i32, args: &[S]) {
        let out = self.run(args, None);
        assert_eq!(
            out.status.code(),
            Some(code),
            "command {args:?}: expected exit {code}, got {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// Kills the serve process when the test ends, pass or fail.
struct ServerGuard(Child);

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Spawn `serve` and wait until it logs its listening port.
fn spawn_server(server: &Actor, db: &Path, log_path: &Path) -> (ServerGuard, u16) {
    spawn_serve(
        server,
        log_path,
        &["--db", db.to_str().unwrap(), "--no-relay", "--no-mdns"],
    )
}

/// Spawn `serve` with arbitrary flags and wait until it logs the IPv4
/// socket it bound. Both roles announce the same `bound: ` lines, so this
/// gates readiness for an authoritative node and a replica alike.
fn spawn_serve(server: &Actor, log_path: &Path, args: &[&str]) -> (ServerGuard, u16) {
    let log = std::fs::File::create(log_path).unwrap();
    let child = Command::new(BIN)
        .arg("serve")
        .args(args)
        .env("XDG_DATA_HOME", &server.xdg)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log)
        .spawn()
        .expect("spawning serve");
    let guard = ServerGuard(child);

    let deadline = Instant::now() + Duration::from_secs(20);
    let port = loop {
        let contents = std::fs::read_to_string(log_path).unwrap_or_default();
        if let Some(port) = contents.lines().find_map(|l| {
            l.strip_prefix("bound: 0.0.0.0:")
                .and_then(|p| p.parse::<u16>().ok())
        }) {
            break port;
        }
        assert!(
            Instant::now() < deadline,
            "serve did not report a bound port; log so far:\n{contents}"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    (guard, port)
}

#[test]
fn cli_user_permission_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let db = root.join("bunker.sqlite");

    let server = Actor::new(root, "xdg-server");
    let admin = Actor::new(root, "xdg-admin");
    let user = Actor::new(root, "xdg-user");

    // Identities auto-generate in each actor's XDG dir.
    let admin_id = admin.expect_ok(&["key", "generate", "client"], None);
    let user_id = user.expect_ok(&["key", "generate", "client"], None);
    let server_id = server.expect_ok(&["key", "generate", "server"], None);

    // Operator: offline backup key, one-shot init (operational key
    // auto-generates in the server's XDG dir), then serve.
    let backup_path = root.join("backup.age");
    let backup_pub = server.expect_ok(
        &["keygen-age", "--out", backup_path.to_str().unwrap()],
        None,
    );
    server.expect_ok(
        &[
            "init",
            "--db",
            db.to_str().unwrap(),
            "--backup-pubkey",
            &backup_pub,
            "--admin-id",
            &admin_id,
        ],
        None,
    );
    let (_server_guard, port) = spawn_server(&server, &db, &root.join("serve.log"));

    // Server aliases: both actors store the bunker under the "default"
    // alias in their own XDG dir, so no invocation below needs --server.
    // The user also registers a named alias, exercised at the end.
    assert_eq!(
        admin.expect_ok(&["server", "add", "default", &server_id], None),
        format!("default -> {server_id}")
    );
    user.expect_ok(&["server", "add", "default", &server_id], None);
    user.expect_ok(&["server", "add", "bunker", &server_id], None);
    assert!(
        user.expect_ok(&["server", "ls"], None)
            .contains(&format!("bunker\t{server_id}"))
    );

    let server_addr = format!("127.0.0.1:{port}");
    let base = ["client", "--server-addr", &server_addr];
    let cmd =
        |rest: &[&str]| -> Vec<String> { base.iter().chain(rest).map(|s| s.to_string()).collect() };

    // Admin creates the group and registers the remote user.
    assert_eq!(admin.expect_ok(&cmd(&["create-group", "team"]), None), "ok");
    assert_eq!(
        admin.expect_ok(
            &cmd(&["add-identity", "--name", "remote-user", "--id", &user_id]),
            None
        ),
        "ok"
    );

    // Registration alone grants nothing.
    user.expect_exit(
        EXIT_DENIED,
        &cmd(&["get", "--group", "team", "--name", "api-key"]),
    );
    user.expect_exit(
        EXIT_DENIED,
        &cmd(&[
            "put", "--group", "team", "--name", "api-key", "--value", "nope",
        ]),
    );

    // Read+write grant: the user adds a secret, updates it (CAS), and can
    // delete. Values flow through stdin and out through stdout.
    assert_eq!(
        admin.expect_ok(
            &cmd(&[
                "grant",
                "--group",
                "team",
                "--identity",
                "remote-user",
                "--perms",
                "rw",
            ]),
            None
        ),
        "ok"
    );
    assert_eq!(
        user.expect_ok(
            &cmd(&["put", "--group", "team", "--name", "api-key"]),
            Some(b"secret-v1"),
        ),
        "version 1"
    );
    assert_eq!(
        user.expect_ok(
            &cmd(&[
                "put",
                "--group",
                "team",
                "--name",
                "api-key",
                "--expected-version",
                "1",
            ]),
            Some(b"secret-v2"),
        ),
        "version 2"
    );
    // A stale expected-version is a CAS conflict, not a denial.
    user.expect_exit(
        EXIT_CONFLICT,
        &cmd(&[
            "put",
            "--group",
            "team",
            "--name",
            "api-key",
            "--value",
            "stale",
            "--expected-version",
            "1",
        ]),
    );
    // --value works but warns: the secret is visible in the process list.
    let out = user.run(
        &cmd(&[
            "put", "--group", "team", "--name", "scratch", "--value", "temp",
        ]),
        None,
    );
    assert!(out.status.success(), "put --value failed");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "version 1");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("stdin"),
        "expected a warning steering --value users toward stdin, got: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        user.expect_ok(
            &cmd(&[
                "delete",
                "--group",
                "team",
                "--name",
                "scratch",
                "--expected-version",
                "1",
            ]),
            None
        ),
        "ok",
        "user with write access must be able to delete secrets"
    );
    user.expect_exit(
        EXIT_DENIED,
        &cmd(&["get", "--group", "team", "--name", "scratch"]),
    );

    // Full revocation: everything is denied again.
    assert_eq!(
        admin.expect_ok(
            &cmd(&[
                "grant",
                "--group",
                "team",
                "--identity",
                "remote-user",
                "--perms",
                "none",
            ]),
            None
        ),
        "ok"
    );
    user.expect_exit(
        EXIT_DENIED,
        &cmd(&["get", "--group", "team", "--name", "api-key"]),
    );
    user.expect_exit(
        EXIT_DENIED,
        &cmd(&[
            "put",
            "--group",
            "team",
            "--name",
            "api-key",
            "--value",
            "evil",
            "--expected-version",
            "2",
        ]),
    );
    user.expect_exit(
        EXIT_DENIED,
        &cmd(&[
            "delete",
            "--group",
            "team",
            "--name",
            "api-key",
            "--expected-version",
            "2",
        ]),
    );

    // Read-only: the secret value comes back on stdout; writes and
    // deletes stay denied.
    assert_eq!(
        admin.expect_ok(
            &cmd(&[
                "grant",
                "--group",
                "team",
                "--identity",
                "remote-user",
                "--perms",
                "r",
            ]),
            None
        ),
        "ok"
    );
    assert_eq!(
        user.expect_ok(&cmd(&["get", "--group", "team", "--name", "api-key"]), None),
        "secret-v2"
    );
    // Plain get reports the version on stderr; --quiet suppresses it.
    let out = user.run(&cmd(&["get", "--group", "team", "--name", "api-key"]), None);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("version 2"),
        "get must report the version on stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = user.run(
        &cmd(&["get", "--quiet", "--group", "team", "--name", "api-key"]),
        None,
    );
    assert!(
        out.status.success(),
        "get --quiet failed (status {:?}): {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "secret-v2");
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("version"),
        "get --quiet must not report the version: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        user.expect_ok(&cmd(&["ls", "--group", "team"]), None),
        "api-key\tv2"
    );
    user.expect_exit(
        EXIT_DENIED,
        &cmd(&[
            "put",
            "--group",
            "team",
            "--name",
            "api-key",
            "--value",
            "nope",
            "--expected-version",
            "2",
        ]),
    );
    user.expect_exit(
        EXIT_DENIED,
        &cmd(&[
            "delete",
            "--group",
            "team",
            "--name",
            "api-key",
            "--expected-version",
            "2",
        ]),
    );

    // --server still accepts a named alias and a raw EndpointId.
    for server_arg in ["bunker", server_id.as_str()] {
        assert_eq!(
            user.expect_ok(
                &[
                    "client",
                    "--server",
                    server_arg,
                    "--server-addr",
                    &server_addr,
                    "get",
                    "--group",
                    "team",
                    "--name",
                    "api-key",
                ],
                None,
            ),
            "secret-v2"
        );
    }
}

/// The local `db` commands: rescuing an orphaned group by granting directly
/// in the database (server stopped), and verifying the audit hash chain.
#[test]
fn cli_db_rescue_and_audit_verify() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let db = root.join("bunker.sqlite");
    let db_str = db.to_str().unwrap();

    let server = Actor::new(root, "xdg-server");
    let admin = Actor::new(root, "xdg-admin");
    let user = Actor::new(root, "xdg-user");

    let admin_id = admin.expect_ok(&["key", "generate", "client"], None);
    let user_id = user.expect_ok(&["key", "generate", "client"], None);
    let server_id = server.expect_ok(&["key", "generate", "server"], None);

    let backup_path = root.join("backup.age");
    let backup_pub = server.expect_ok(
        &["keygen-age", "--out", backup_path.to_str().unwrap()],
        None,
    );
    server.expect_ok(
        &[
            "init",
            "--db",
            db_str,
            "--backup-pubkey",
            &backup_pub,
            "--admin-id",
            &admin_id,
        ],
        None,
    );
    admin.expect_ok(&["server", "add", "default", &server_id], None);
    user.expect_ok(&["server", "add", "default", &server_id], None);

    // Round 1: create a group and register the user, then stop the server.
    {
        let (_guard, port) = spawn_server(&server, &db, &root.join("serve1.log"));
        let server_addr = format!("127.0.0.1:{port}");
        admin.expect_ok(
            &[
                "client",
                "--server-addr",
                &server_addr,
                "create-group",
                "team",
            ],
            None,
        );
        admin.expect_ok(
            &[
                "client",
                "--server-addr",
                &server_addr,
                "add-identity",
                "--name",
                "remote-user",
                "--id",
                &user_id,
            ],
            None,
        );
    }

    // Offline: grant directly in the database and verify the audit chain.
    let granted = server.expect_ok(
        &[
            "db",
            "grant",
            "--db",
            db_str,
            "--group",
            "team",
            "--identity",
            "remote-user",
            "--perms",
            "rwa",
        ],
        None,
    );
    assert!(granted.contains("granted"), "unexpected output: {granted}");
    let verified = server.expect_ok(&["db", "audit-verify", "--db", db_str], None);
    assert!(
        verified.starts_with("ok") && verified.contains("head"),
        "unexpected output: {verified}"
    );

    // Round 2: the grant is live after a restart.
    let (_guard, port) = spawn_server(&server, &db, &root.join("serve2.log"));
    let server_addr = format!("127.0.0.1:{port}");
    assert_eq!(
        user.expect_ok(
            &[
                "client",
                "--server-addr",
                &server_addr,
                "put",
                "--group",
                "team",
                "--name",
                "rescued",
            ],
            Some(b"it-works"),
        ),
        "version 1"
    );
}

#[test]
fn cli_init_autogenerates_backup_and_admin_keys() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let db = root.join("bunker.sqlite");

    // One actor plays operator and admin: bare init, no key flags at all.
    let op = Actor::new(root, "xdg-op");
    let out = op.run(&["init", "--db", db.to_str().unwrap()], None);
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        out.status.success(),
        "bare init failed (status {:?}): {stderr}",
        out.status.code()
    );

    // The backup identity was generated and its recipient announced.
    assert!(
        stderr.contains("age1"),
        "no backup recipient in init output: {stderr}"
    );
    let show = op.expect_ok(&["key", "show"], None);
    assert!(
        show.contains("backup.age") && show.contains("age1"),
        "key show does not list the backup key: {show}"
    );

    // The admin id defaulted to this actor's client key.
    let client_id = op.expect_ok(&["key", "generate", "client"], None);
    assert!(
        stderr.contains(&client_id),
        "init did not report client key {client_id} as admin: {stderr}"
    );

    // And that client really is the service admin: list-identities is
    // admin-gated and must show it under the default name.
    let server_id = op.expect_ok(&["key", "generate", "server"], None);
    let (_guard, port) = spawn_server(&op, &db, &root.join("serve.log"));
    op.expect_ok(&["server", "add", "default", &server_id], None);
    let server_addr = format!("127.0.0.1:{port}");
    let identities = op.expect_ok(
        &["client", "--server-addr", &server_addr, "list-identities"],
        None,
    );
    assert!(
        identities.contains(&client_id) && identities.contains("admin"),
        "unexpected identities: {identities}"
    );
}

/// Two processes, one mirror: `serve --replica-of` syncs from the
/// authoritative bunker, answers ordinary `client get` calls with
/// plaintext, refuses writes with the replica exit code, and keeps
/// serving once the authoritative process is gone — issue #1's headline
/// scenario, through the binary.
#[test]
fn cli_replica_serves_reads_and_outlives_the_authoritative() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let db = root.join("bunker.sqlite");
    let replica_db = root.join("replica.sqlite");

    let server = Actor::new(root, "xdg-server");
    let admin = Actor::new(root, "xdg-admin");
    let replica = Actor::new(root, "xdg-replica");
    let user = Actor::new(root, "xdg-user");

    let admin_id = admin.expect_ok(&["key", "generate", "client"], None);
    let user_id = user.expect_ok(&["key", "generate", "client"], None);
    let server_id = server.expect_ok(&["key", "generate", "server"], None);
    // The replica is registered under its SERVER key: that is the endpoint
    // `serve --replica-of` binds, hence the recipient its DEK wraps are
    // addressed to.
    let replica_id = replica.expect_ok(&["key", "generate", "server"], None);

    let backup_path = root.join("backup.age");
    let backup_pub = server.expect_ok(
        &["keygen-age", "--out", backup_path.to_str().unwrap()],
        None,
    );
    server.expect_ok(
        &[
            "init",
            "--db",
            db.to_str().unwrap(),
            "--backup-pubkey",
            &backup_pub,
            "--admin-id",
            &admin_id,
        ],
        None,
    );

    // No relays, no mDNS, no DNS — as hermetic as the rest of the suite.
    // The replica is handed the authoritative node's socket with
    // --replica-addr, which is what --server-addr does for clients.
    let (auth_guard, auth_port) = spawn_server(&server, &db, &root.join("serve.log"));
    let auth_addr = format!("127.0.0.1:{auth_port}");
    let to_auth = |rest: &[&str]| -> Vec<String> {
        [
            "client",
            "--server",
            &server_id,
            "--server-addr",
            &auth_addr,
        ]
        .iter()
        .map(|s| s.to_string())
        .chain(rest.iter().map(|s| s.to_string()))
        .collect()
    };

    assert_eq!(
        admin.expect_ok(&to_auth(&["create-group", "team"]), None),
        "ok"
    );
    assert_eq!(
        admin.expect_ok(
            &to_auth(&["put", "--group", "team", "--name", "api-key"]),
            Some(b"secret-v1"),
        ),
        "version 1"
    );
    for (name, id) in [("mirror", &replica_id), ("remote-user", &user_id)] {
        assert_eq!(
            admin.expect_ok(
                &to_auth(&["add-identity", "--name", name, "--id", id]),
                None
            ),
            "ok"
        );
        assert_eq!(
            admin.expect_ok(
                &to_auth(&[
                    "grant",
                    "--group",
                    "team",
                    "--identity",
                    name,
                    "--perms",
                    "r",
                ]),
                None
            ),
            "ok"
        );
    }

    // That address hint is replica-only: an authoritative `serve` refuses
    // it rather than silently ignoring it.
    let out = server.run(
        &[
            "serve",
            "--db",
            db.to_str().unwrap(),
            "--replica-addr",
            &auth_addr,
        ],
        None,
    );
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert_eq!(
        out.status.code(),
        Some(1),
        "--replica-addr without --replica-of must fail: {stderr}"
    );
    assert!(
        stderr.contains("--replica-of"),
        "the error must point at --replica-of: {stderr}"
    );

    let (_replica_guard, replica_port) = spawn_serve(
        &replica,
        &root.join("replica.log"),
        &[
            "--db",
            replica_db.to_str().unwrap(),
            "--replica-of",
            &server_id,
            "--replica-addr",
            &auth_addr,
            "--no-relay",
            "--no-mdns",
        ],
    );
    let replica_addr = format!("127.0.0.1:{replica_port}");
    let to_replica = |rest: &[&str]| -> Vec<String> {
        [
            "client",
            "--server",
            &replica_id,
            "--server-addr",
            &replica_addr,
        ]
        .iter()
        .map(|s| s.to_string())
        .chain(rest.iter().map(|s| s.to_string()))
        .collect()
    };
    let get = to_replica(&["get", "--quiet", "--group", "team", "--name", "api-key"]);

    // Discovery and the first sync are asynchronous, so poll rather than
    // guess a sleep: the mirror answers with the same plaintext the
    // authoritative node holds.
    assert_eq!(
        user.expect_ok_within(Duration::from_secs(120), &get),
        "secret-v1",
        "the replica must serve the mirrored plaintext"
    );

    // Writes are refused with the replica-specific exit code, and the
    // message names the node to write to instead.
    let out = user.run(
        &to_replica(&[
            "put",
            "--group",
            "team",
            "--name",
            "api-key",
            "--value",
            "nope",
            "--expected-version",
            "1",
        ]),
        None,
    );
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert_eq!(
        out.status.code(),
        Some(EXIT_READ_ONLY),
        "a write to a replica must exit {EXIT_READ_ONLY}: {stderr}"
    );
    assert!(
        stderr.contains(&server_id),
        "the redirect must name the authoritative node: {stderr}"
    );

    // The authoritative process dies; the mirror keeps answering reads.
    drop(auth_guard);
    assert_eq!(
        user.expect_ok(&get, None),
        "secret-v1",
        "the replica must serve reads with the authoritative node down"
    );
}
