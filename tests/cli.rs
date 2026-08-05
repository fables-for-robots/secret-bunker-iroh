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
    let log = std::fs::File::create(log_path).unwrap();
    let child = Command::new(BIN)
        .args([
            "serve",
            "--db",
            db.to_str().unwrap(),
            "--no-relay",
            "--no-mdns",
        ])
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

    let server_addr = format!("127.0.0.1:{port}");
    let base = [
        "client",
        "--server",
        &server_id,
        "--server-addr",
        &server_addr,
    ];
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
    assert_eq!(
        user.expect_ok(
            &cmd(&[
                "put", "--group", "team", "--name", "scratch", "--value", "temp",
            ]),
            None
        ),
        "version 1"
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
}
