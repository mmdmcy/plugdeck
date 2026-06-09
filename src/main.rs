use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use axum::{
    Json,
    body::Body,
    extract::{Form, Multipart, Path as AxumPath, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    env, fs,
    io::{self, Read},
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command as StdCommand, Stdio},
    sync::{Arc, Mutex},
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command as TokioCommand,
    sync::{Semaphore, oneshot},
};
use tokio_util::io::ReaderStream;
use url::Url;
use uuid::Uuid;

mod modules;

const DEFAULT_CHANNEL: &str = "general";
const DEFAULT_AGENT_SLOT: &str = "a";
const MAX_NOTE_CHARS: usize = 256 * 1024;
const MAX_IMAGE_BYTES: usize = 5 * 1024 * 1024;
const MAX_AGENT_MESSAGE_CHARS: usize = 128 * 1024;
const MAX_AGENT_UPLOAD_BYTES: usize = 25 * 1024 * 1024;
const MAX_CHANNEL_CHARS: usize = 40;
const MAX_AGENT_SLOT_CHARS: usize = 32;
const SESSION_COOKIE: &str = "plugdeck_session";
const SESSION_DAYS: i64 = 30;
const PAGE_CSS: &str = r#"
:root{color-scheme:light dark;--bg:#f6f7f5;--fg:#161816;--muted:#68706a;--line:#d7dcd5;--panel:#fff;--accent:#0d6b57;--accent-soft:#e3f1ec;--accent2:#315f9f;--danger:#ad2f28}
@media(prefers-color-scheme:dark){:root{--bg:#101211;--fg:#f4f5ef;--muted:#a2aaa4;--line:#323934;--panel:#171b18;--accent:#55b59c;--accent-soft:#19362f;--accent2:#8fb5f2;--danger:#ff8a7d}}
*{box-sizing:border-box}
html,body{min-height:100%}
body{margin:0;background:var(--bg);color:var(--fg);font:15px system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;letter-spacing:0}
a{color:inherit;text-decoration:none}
button,input,select,textarea{font:inherit;font-size:16px}
button,.button{min-height:42px;border:0;border-radius:7px;background:var(--accent);color:#fff;padding:0 15px;font-weight:700;cursor:pointer}
.ghost,.icon{background:transparent;color:var(--fg);border:1px solid var(--line)}
.icon{width:34px;min-height:34px;padding:0}
.danger-icon{color:var(--danger)}
input,select,textarea{width:100%;border:1px solid var(--line);border-radius:7px;background:transparent;color:var(--fg);padding:11px}
textarea{min-height:110px;resize:vertical}
nav,.hero{height:64px;display:flex;align-items:center;justify-content:space-between;gap:16px;padding:0 20px;border-bottom:1px solid var(--line)}
nav a{color:var(--accent2);font-weight:700}
h1{font-size:28px;line-height:1.1;margin:0}
main{width:min(1180px,calc(100% - 32px));margin:0 auto;padding:18px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px}
.tile,.download section{border:1px solid var(--line);background:var(--panel);border-radius:8px;padding:14px}
.tile{min-height:96px;display:flex;flex-direction:column;justify-content:space-between}
.tile.primary{border-color:var(--accent)}
.tile strong{font-size:18px}
.tile span,.muted{color:var(--muted)}
.split{display:grid;grid-template-columns:minmax(210px,280px) minmax(0,1fr);gap:14px}
.stack{display:grid;gap:10px}
.list{display:grid;gap:8px;margin-top:14px}
.row,.note-head{display:flex;align-items:center;justify-content:space-between;gap:10px}
.notes{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px;margin-top:14px}
.note p{white-space:normal;word-break:break-word;line-height:1.45}
.note img{max-width:100%;border-radius:6px;border:1px solid var(--line)}
.chat-shell{width:min(1180px,calc(100% - 32px));height:calc(100svh - 64px);padding:12px 0;display:grid;grid-template-columns:240px minmax(0,1fr);gap:12px;min-width:0}
.channel-rail,.chat-pane{min-width:0;min-height:0;border:1px solid var(--line);background:var(--panel);border-radius:8px}
.channel-rail{padding:12px;display:flex;flex-direction:column;gap:10px;overflow:hidden}
.rail-title{font-size:12px;font-weight:800;color:var(--muted);text-transform:uppercase}
.channel-list{display:grid;gap:6px;overflow:auto}
.channel-row{display:grid;grid-template-columns:minmax(0,1fr) 34px;gap:6px;align-items:center}
.channel-link{min-height:38px;display:flex;align-items:center;gap:6px;min-width:0;border-radius:6px;padding:0 10px;color:var(--muted);font-weight:700;overflow:hidden;text-overflow:ellipsis}
.channel-link span{color:var(--muted)}
.channel-row.active .channel-link{background:var(--accent-soft);color:var(--fg)}
.channel-row .icon{opacity:.75}
.channel-add{border-top:1px solid var(--line);padding-top:10px}
.channel-add summary{min-height:38px;display:flex;align-items:center;color:var(--accent2);font-weight:800;cursor:pointer;list-style:none}
.channel-add summary::-webkit-details-marker{display:none}
.channel-form{display:grid;gap:8px;margin-top:8px}
.chat-pane{display:grid;grid-template-rows:auto minmax(0,1fr) auto;overflow:hidden}
.chat-head{min-height:54px;display:flex;align-items:center;justify-content:space-between;gap:12px;padding:0 16px;border-bottom:1px solid var(--line)}
.chat-head strong{font-size:17px}
.chat-head span{color:var(--muted)}
.message-list{min-height:0;overflow:auto;padding:16px;display:grid;align-content:end;gap:2px}
.message{display:grid;grid-template-columns:38px minmax(0,1fr);gap:10px;padding:8px 0}
.message-avatar{width:38px;height:38px;border-radius:50%;display:grid;place-items:center;background:var(--accent-soft);color:var(--accent);font-weight:900}
.message-body{min-width:0}
.message-meta{display:flex;align-items:center;justify-content:space-between;gap:8px;min-height:34px}
.message-meta form{opacity:0}
.message:hover .message-meta form,.message:focus-within .message-meta form{opacity:1}
.message p{margin:4px 0 0;white-space:normal;word-break:break-word;line-height:1.45}
.message-image{display:block;max-width:min(420px,100%);border-radius:6px;border:1px solid var(--line);margin-top:8px}
.empty{align-self:center;justify-self:center;color:var(--muted);text-align:center}
.composer{display:grid;grid-template-columns:minmax(0,1fr) auto auto;gap:8px;padding:12px;border-top:1px solid var(--line);background:var(--panel);min-width:0}
.composer textarea{min-height:46px;max-height:36svh;resize:vertical}
.composer button{white-space:nowrap}
.file-pill{position:relative;min-height:42px;border:1px solid var(--line);border-radius:7px;padding:0 13px;display:flex;align-items:center;justify-content:center;color:var(--fg);font-weight:700;cursor:pointer;overflow:hidden}
.file-pill input{position:absolute;inset:0;opacity:0;cursor:pointer}
.agent-shell{height:calc(100dvh - 64px)}
.agent-pane{grid-template-rows:auto minmax(0,1fr) auto}
.agent-status{color:var(--muted);font-weight:700;font-size:13px;white-space:nowrap}
.agent-compose-wrap{border-top:1px solid var(--line);background:var(--panel)}
.agent-quick{display:flex;gap:7px;overflow-x:auto;padding:10px 12px 0;scrollbar-width:thin}
.agent-quick button{flex:0 0 auto;min-width:max-content;min-height:36px;padding:0 11px;white-space:nowrap}
.agent-composer{display:grid;grid-template-columns:minmax(0,1fr) auto auto;gap:8px;padding:10px 12px 12px;min-width:0}
.agent-composer textarea{min-height:52px;max-height:30dvh;resize:vertical}
.attachment-link{display:inline-flex;align-items:center;min-height:34px;border:1px solid var(--line);border-radius:6px;padding:0 9px;margin-top:8px;color:var(--accent2);font-weight:800;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.message-log{color:var(--muted);font-size:13px}
.login{width:min(420px,calc(100% - 32px));padding-top:72px}
.login form,.download-form{display:grid;gap:10px;margin-top:18px}
.error{color:var(--danger);font-weight:700}
.download{max-width:760px}
.jobs{display:grid;gap:8px;margin-top:14px}
.job{display:flex;justify-content:space-between;gap:12px;border-bottom:1px solid var(--line);padding:10px 0}
.job span{color:var(--muted)}
.bar{height:12px;border:1px solid var(--line);border-radius:999px;overflow:hidden;margin:18px 0}
#fill{height:100%;width:6%;background:var(--accent)}
pre{white-space:pre-wrap;word-break:break-word;color:var(--muted);max-height:44vh;overflow:auto;border-top:1px solid var(--line);padding-top:12px}
@media(max-width:760px){
  nav,.hero{padding:0 14px}
  main{width:calc(100% - 20px)}
  .chat-shell{width:100%;height:calc(100svh - 64px);padding:0;gap:0;grid-template-columns:1fr;grid-template-rows:auto minmax(0,1fr)}
  .channel-rail{border-width:0 0 1px;border-radius:0;padding:10px;display:grid;grid-template-rows:auto auto auto;gap:8px;max-height:34svh}
  .channel-list{display:flex;gap:8px;overflow-x:auto;overflow-y:hidden;padding-bottom:2px}
  .channel-row{display:flex;flex:0 0 auto}
  .channel-link{white-space:nowrap}
  .channel-row .icon{display:none}
  .channel-add{padding-top:8px}
  .chat-pane{border:0;border-radius:0}
  .chat-head{min-height:48px;padding:0 12px}
  .message-list{padding:10px 12px}
  .message{grid-template-columns:32px minmax(0,1fr);gap:8px}
  .message-avatar{width:32px;height:32px}
  .composer{grid-template-columns:minmax(0,1fr) 88px;padding:10px}
  .composer textarea{grid-column:1/-1;min-height:56px}
  .agent-shell{height:calc(100dvh - 64px)}
  .agent-quick{padding:8px 10px 0}
  .agent-composer{grid-template-columns:minmax(0,1fr) 86px;padding:8px 10px max(10px,env(safe-area-inset-bottom))}
  .agent-composer textarea{grid-column:1/-1;min-height:54px;max-height:26dvh}
  .agent-composer .file-pill{min-width:0}
  .file-pill{min-width:0}
}
"#;

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str).unwrap_or("serve") {
        "serve" => serve().await,
        "hash-password" => {
            hash_password_cmd(&args[1..])?;
            Ok(())
        }
        "audit-public" => {
            if audit_public_cmd(&args[1..])? != 0 {
                std::process::exit(1);
            }
            Ok(())
        }
        "import-motehold" => {
            let Some(path) = args.get(1) else {
                eprintln!("usage: plugdeck import-motehold /path/to/messages.db");
                return Ok(());
            };
            let config = Config::from_env()?;
            let conn = open_db(&config.db_path)?;
            let imported = import_motehold(&conn, Path::new(path))?;
            println!("imported {imported} motehold messages");
            Ok(())
        }
        _ => {
            eprintln!(
                "usage: plugdeck [serve|hash-password --stdin|audit-public|import-motehold <db>]"
            );
            Ok(())
        }
    }
}

async fn serve() -> io::Result<()> {
    let config = Config::from_env()?;
    fs::create_dir_all(&config.download_dir)?;
    fs::create_dir_all(&config.agent_upload_dir)?;
    let conn = open_db(&config.db_path)?;
    ensure_agent_slot_seeds(&conn, &config.agent_slots, &config.agent_default_workdir)
        .map_err(io_other)?;

    let state = Arc::new(AppState {
        db: Mutex::new(conn),
        config,
        jobs: Mutex::new(HashMap::new()),
        download_slots: Semaphore::new(1),
        agent_jobs: Mutex::new(HashMap::new()),
        agent_cancels: Mutex::new(HashMap::new()),
    });

    state.set_download_slots();

    let app = modules::build_router(state.clone());

    let bind = state
        .config
        .bind
        .parse::<SocketAddr>()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    println!("Plugdeck listening on http://{bind}");
    axum::serve(listener, app).await
}

#[derive(Clone)]
struct Config {
    bind: String,
    db_path: PathBuf,
    download_dir: PathBuf,
    agent_default_workdir: PathBuf,
    agent_upload_dir: PathBuf,
    agent_codex_bin: String,
    agent_codex_args: Vec<String>,
    agent_slots: Vec<AgentSlotSeed>,
    ytdlp: String,
    js_runtime: Option<PathBuf>,
    max_active: usize,
    job_ttl: Duration,
    user: String,
    password_hash: Option<String>,
    cookie_secret: Vec<u8>,
    auth_disabled: bool,
    links: Vec<Link>,
}

#[derive(Clone)]
struct AgentSlotSeed {
    name: String,
    workdir: PathBuf,
}

#[derive(Clone, Serialize)]
struct AgentRun {
    status: String,
    current: String,
    started_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Link {
    name: String,
    url: String,
    #[serde(default)]
    category: String,
    #[serde(default)]
    description: String,
}

#[derive(Deserialize)]
struct LinksFile {
    #[serde(default)]
    link: Vec<Link>,
}

#[derive(Debug)]
struct AuditFinding {
    path: String,
    line: Option<usize>,
    message: String,
}

impl Config {
    fn from_env() -> io::Result<Self> {
        let bind = env::var("PLUGDECK_BIND").unwrap_or_else(|_| "127.0.0.1:8789".into());
        let db_path = env::var("PLUGDECK_DB")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("data/plugdeck.sqlite"));
        let download_dir = env::var("PLUGDECK_DOWNLOAD_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("data/downloads"));
        let agent_default_workdir = env::var("PLUGDECK_AGENT_DEFAULT_WORKDIR")
            .map(|value| expand_local_path(&value))
            .unwrap_or_else(|_| default_home_dir());
        let agent_upload_dir = env::var("PLUGDECK_AGENT_UPLOAD_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| download_dir.join("agent-uploads"));
        let agent_codex_bin =
            env::var("PLUGDECK_AGENT_CODEX_BIN").unwrap_or_else(|_| "codex".into());
        let agent_codex_args = env::var("PLUGDECK_AGENT_CODEX_ARGS")
            .ok()
            .map(|value| split_env_args(&value))
            .unwrap_or_default();
        let agent_slots = parse_agent_slot_seeds(
            env::var("PLUGDECK_AGENT_SLOTS").ok(),
            &agent_default_workdir,
        );
        let ytdlp = env::var("PLUGDECK_YTDLP").unwrap_or_else(|_| "yt-dlp".into());
        let js_runtime = env::var("PLUGDECK_JS_RUNTIME")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from)
            .filter(|path| path.exists());
        let max_active = env::var("PLUGDECK_MAX_ACTIVE")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(1);
        let ttl_hours = env::var("PLUGDECK_JOB_TTL_HOURS")
            .ok()
            .and_then(|value| value.parse::<i64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(24);
        let user = env::var("PLUGDECK_USER").unwrap_or_else(|_| "plugdeck".into());
        let password_hash = env::var("PLUGDECK_PASSWORD_HASH")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let auth_disabled = env_flag("PLUGDECK_AUTH_DISABLED", false);
        if password_hash.is_none() && !auth_disabled {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PLUGDECK_PASSWORD_HASH is required unless PLUGDECK_AUTH_DISABLED=1",
            ));
        }
        let cookie_secret = env::var("PLUGDECK_COOKIE_SECRET")
            .ok()
            .and_then(|value| hex::decode(value.trim()).ok())
            .filter(|bytes| bytes.len() >= 32)
            .unwrap_or_else(random_secret);

        let links = env::var("PLUGDECK_LINKS_FILE")
            .ok()
            .and_then(|path| fs::read_to_string(path).ok())
            .and_then(|raw| toml::from_str::<LinksFile>(&raw).ok())
            .map(|file| file.link)
            .unwrap_or_default();

        Ok(Self {
            bind,
            db_path,
            download_dir,
            agent_default_workdir,
            agent_upload_dir,
            agent_codex_bin,
            agent_codex_args,
            agent_slots,
            ytdlp,
            js_runtime,
            max_active,
            job_ttl: Duration::hours(ttl_hours),
            user,
            password_hash,
            cookie_secret,
            auth_disabled,
            links,
        })
    }
}

struct AppState {
    db: Mutex<Connection>,
    config: Config,
    jobs: Mutex<HashMap<String, Job>>,
    download_slots: Semaphore,
    agent_jobs: Mutex<HashMap<i64, AgentRun>>,
    agent_cancels: Mutex<HashMap<i64, oneshot::Sender<()>>>,
}

impl AppState {
    fn set_download_slots(&self) {
        let current = self.download_slots.available_permits();
        if self.config.max_active > current {
            self.download_slots
                .add_permits(self.config.max_active.saturating_sub(current));
        }
    }
}

#[derive(Clone, Serialize)]
struct Job {
    id: String,
    url: String,
    cache_key: String,
    created_at: DateTime<Utc>,
    status: String,
    progress: String,
    filename: Option<String>,
    file_path: Option<PathBuf>,
    error: Option<String>,
    log: Vec<String>,
}

impl Job {
    fn new(url: String, cache_key: String) -> Self {
        Self {
            id: Uuid::new_v4().simple().to_string()[..12].to_string(),
            url,
            cache_key,
            created_at: Utc::now(),
            status: "queued".into(),
            progress: String::new(),
            filename: None,
            file_path: None,
            error: None,
            log: Vec::new(),
        }
    }

    fn with_cached(url: String, cache_key: String, file_path: PathBuf, filename: String) -> Self {
        let mut job = Self::new(url, cache_key);
        job.status = "complete".into();
        job.progress = "100%".into();
        job.file_path = Some(file_path);
        job.filename = Some(filename);
        job.log.push("Using cached file".into());
        job
    }
}

fn open_db(path: &Path) -> io::Result<Connection> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(path).map_err(io_other)?;
    conn.execute_batch(
        r#"
        PRAGMA foreign_keys = ON;
        CREATE TABLE IF NOT EXISTS channels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL COLLATE NOCASE UNIQUE,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            channel_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            image_type TEXT,
            image_data BLOB,
            created_at TEXT NOT NULL,
            import_source TEXT UNIQUE,
            FOREIGN KEY (channel_id) REFERENCES channels(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_notes_channel_id ON notes(channel_id);
        CREATE TABLE IF NOT EXISTS download_cache (
            cache_key TEXT PRIMARY KEY,
            file_path TEXT NOT NULL,
            filename TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS agent_slots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL COLLATE NOCASE UNIQUE,
            workdir TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS agent_sessions (
            slot_id INTEGER PRIMARY KEY,
            thread_id TEXT NOT NULL,
            workdir TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (slot_id) REFERENCES agent_slots(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS agent_attachments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slot_id INTEGER NOT NULL,
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            content_type TEXT NOT NULL,
            file_path TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (slot_id) REFERENCES agent_slots(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS agent_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slot_id INTEGER NOT NULL,
            role TEXT NOT NULL,
            body TEXT NOT NULL,
            attachment_id INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY (slot_id) REFERENCES agent_slots(id) ON DELETE CASCADE,
            FOREIGN KEY (attachment_id) REFERENCES agent_attachments(id) ON DELETE SET NULL
        );
        CREATE INDEX IF NOT EXISTS idx_agent_messages_slot_id ON agent_messages(slot_id, id);
        CREATE INDEX IF NOT EXISTS idx_agent_attachments_slot_id ON agent_attachments(slot_id);
        "#,
    )
    .map_err(io_other)?;
    ensure_channel(&conn, DEFAULT_CHANNEL).map_err(io_other)?;
    Ok(conn)
}

fn ensure_channel(conn: &Connection, name: &str) -> rusqlite::Result<i64> {
    let existing = conn
        .query_row(
            "SELECT id FROM channels WHERE name = ?1",
            params![name],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    if let Some(id) = existing {
        return Ok(id);
    }
    conn.execute(
        "INSERT INTO channels (name, created_at) VALUES (?1, ?2)",
        params![name, Utc::now().to_rfc3339()],
    )?;
    Ok(conn.last_insert_rowid())
}

async fn home(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(response) = page_guard(&state, &headers) {
        return response;
    }
    let modules = modules::module_tiles(&state);
    let links = render_links(&state.config.links);
    page(
        "Plugdeck",
        &format!(
            r#"
<section class="hero">
  <h1>Plugdeck</h1>
  <form action="/logout" method="post"><button class="ghost" type="submit">Log out</button></form>
</section>
<main class="grid">
  {modules}
  {links}
</main>
"#
        ),
    )
}

async fn login_page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if authorized(&state.config, &headers) {
        return Redirect::to("/").into_response();
    }
    page(
        "Plugdeck Login",
        r#"
<main class="login">
  <h1>Plugdeck</h1>
  <form action="/login" method="post">
    <label>Password</label>
    <input name="password" type="password" autocomplete="current-password" autofocus required>
    <button type="submit">Log in</button>
  </form>
</main>
"#,
    )
}

#[derive(Deserialize)]
struct LoginForm {
    password: String,
}

async fn login_post(State(state): State<Arc<AppState>>, Form(form): Form<LoginForm>) -> Response {
    if !verify_password(&state.config, &form.password) {
        return page(
            "Plugdeck Login",
            r#"
<main class="login">
  <h1>Plugdeck</h1>
  <p class="error">Wrong password.</p>
  <form action="/login" method="post">
    <label>Password</label>
    <input name="password" type="password" autocomplete="current-password" autofocus required>
    <button type="submit">Log in</button>
  </form>
</main>
"#,
        );
    }
    let cookie = make_session_cookie(&state.config);
    (
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, HeaderValue::from_static("/")),
            (header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap()),
        ],
    )
        .into_response()
}

async fn logout_post() -> Response {
    (
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, HeaderValue::from_static("/login")),
            (
                header::SET_COOKIE,
                HeaderValue::from_static(
                    "plugdeck_session=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax",
                ),
            ),
        ],
    )
        .into_response()
}

#[derive(Deserialize)]
struct NotesQuery {
    channel: Option<i64>,
}

async fn notes_page(
    State(state): State<Arc<AppState>>,
    Query(query): Query<NotesQuery>,
    headers: HeaderMap,
) -> Response {
    if let Some(response) = page_guard(&state, &headers) {
        return response;
    }
    let channels = {
        let db = state.db.lock().unwrap();
        list_channels(&db).unwrap_or_default()
    };
    let active_channel = channels
        .iter()
        .find(|channel| Some(channel.id) == query.channel)
        .or_else(|| channels.first());
    let active_channel_id = active_channel.map(|channel| channel.id).unwrap_or(1);
    let active_channel_name = active_channel
        .map(|channel| channel.name.as_str())
        .unwrap_or(DEFAULT_CHANNEL);
    let notes = {
        let db = state.db.lock().unwrap();
        list_notes(&db, Some(active_channel_id)).unwrap_or_default()
    };
    let channels_html = channels
        .iter()
        .map(|channel| {
            let active_class = if channel.id == active_channel_id {
                " active"
            } else {
                ""
            };
            let channel_name = html_escape(&channel.name);
            let delete = if channels.len() > 1 {
                format!(
                    r#"<form action="/notes/channels/{}/delete" method="post"><button class="icon danger-icon" type="submit" aria-label="Delete channel {}">x</button></form>"#,
                    channel.id, channel_name
                )
            } else {
                String::new()
            };
            format!(
                r##"<div class="channel-row{active_class}"><a class="channel-link" href="/notes?channel={}"><span>#</span>{}</a>{}</div>"##,
                channel.id, channel_name, delete
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let active_channel_label = html_escape(active_channel_name);
    let notes_html = if notes.is_empty() {
        format!(
            r##"<p class="empty">No messages in #{} yet.</p>"##,
            active_channel_label
        )
    } else {
        notes
            .iter()
            .rev()
            .map(|note| {
                let body = if note.body.trim().is_empty() {
                    String::new()
                } else {
                    format!(
                        r#"<p>{}</p>"#,
                        html_escape(&note.body).replace('\n', "<br>")
                    )
                };
                let image = if note.has_image {
                    format!(
                        r#"<img class="message-image" src="/notes/images/{}" alt="">"#,
                        note.id
                    )
                } else {
                    String::new()
                };
                format!(
                    r##"<article class="message">
  <div class="message-avatar">#</div>
  <div class="message-body">
    <div class="message-meta"><strong>{}</strong><form action="/notes/{}/delete" method="post"><button class="icon danger-icon" type="submit" aria-label="Delete message">x</button></form></div>
    {}{}
  </div>
</article>"##,
                    html_escape(&note.channel),
                    note.id,
                    body,
                    image
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };
    let message_count = notes.len();
    page(
        "Notes",
        &format!(
            r#"
<nav><a href="/">Plugdeck</a><strong>Notes</strong></nav>
<main class="chat-shell">
  <aside class="channel-rail" aria-label="Channels">
    <div class="rail-title">Channels</div>
    <div class="channel-list">{channels_html}</div>
    <details class="channel-add">
      <summary>Add channel</summary>
      <form action="/notes/channels" method="post" class="channel-form">
        <input name="name" maxlength="{MAX_CHANNEL_CHARS}" placeholder="Channel name" required>
        <button type="submit">Add</button>
      </form>
    </details>
  </aside>
  <section class="chat-pane">
    <header class="chat-head"><strong># {active_channel_label}</strong><span>{message_count} messages</span></header>
    <div class="message-list">{notes_html}</div>
    <form action="/notes" method="post" enctype="multipart/form-data" class="composer">
      <input name="channel_id" type="hidden" value="{active_channel_id}">
      <textarea name="body" maxlength="{MAX_NOTE_CHARS}" placeholder="Message #{active_channel_label}"></textarea>
      <label class="file-pill"><input name="image" type="file" accept="image/png,image/jpeg,image/gif,image/webp"><span>Image</span></label>
      <button type="submit">Send</button>
    </form>
  </section>
</main>
<script>
const messages = document.querySelector(".message-list");
if (messages) messages.scrollTop = messages.scrollHeight;
</script>
"#
        ),
    )
}

#[derive(Deserialize)]
struct ChannelForm {
    name: String,
}

async fn channel_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<ChannelForm>,
) -> Response {
    if let Some(response) = page_guard(&state, &headers) {
        return response;
    }
    let name = form.name.trim();
    let mut channel_id = None;
    if !name.is_empty() && name.chars().count() <= MAX_CHANNEL_CHARS {
        let db = state.db.lock().unwrap();
        channel_id = ensure_channel(&db, name).ok();
    }
    Redirect::to(&notes_location(channel_id)).into_response()
}

async fn channel_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<i64>,
) -> Response {
    if let Some(response) = page_guard(&state, &headers) {
        return response;
    }
    let db = state.db.lock().unwrap();
    let channel_count: i64 = db
        .query_row("SELECT COUNT(*) FROM channels", [], |row| row.get(0))
        .unwrap_or(0);
    if channel_count > 1 {
        let _ = db.execute("DELETE FROM channels WHERE id = ?1", params![id]);
    }
    Redirect::to(&notes_location(None)).into_response()
}

async fn note_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    if let Some(response) = page_guard(&state, &headers) {
        return response;
    }
    let mut channel_id = None;
    let mut body = String::new();
    let mut image_type = None;
    let mut image_data = None;

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "channel_id" => {
                if let Ok(text) = field.text().await {
                    channel_id = text.trim().parse::<i64>().ok();
                }
            }
            "body" => {
                if let Ok(text) = field.text().await {
                    body = text;
                }
            }
            "image" => {
                let content_type = field.content_type().map(str::to_string);
                if content_type.as_deref().is_some_and(allowed_image_type)
                    && let Ok(bytes) = field.bytes().await
                    && !bytes.is_empty()
                    && bytes.len() <= MAX_IMAGE_BYTES
                {
                    image_type = content_type;
                    image_data = Some(bytes.to_vec());
                }
            }
            _ => {}
        }
    }

    let body = body.trim();
    let channel_id = channel_id.unwrap_or(1);
    if (!body.is_empty() || image_data.is_some()) && body.len() <= MAX_NOTE_CHARS {
        let db = state.db.lock().unwrap();
        let exists = db
            .query_row(
                "SELECT 1 FROM channels WHERE id = ?1",
                params![channel_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .unwrap_or(None)
            .is_some();
        if exists {
            let _ = db.execute(
                "INSERT INTO notes (channel_id, body, image_type, image_data, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![channel_id, body, image_type, image_data, Utc::now().to_rfc3339()],
            );
        }
    }
    Redirect::to(&notes_location(Some(channel_id))).into_response()
}

async fn note_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<i64>,
) -> Response {
    if let Some(response) = page_guard(&state, &headers) {
        return response;
    }
    let db = state.db.lock().unwrap();
    let channel_id = db
        .query_row(
            "SELECT channel_id FROM notes WHERE id = ?1",
            params![id],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .unwrap_or(None);
    let _ = db.execute("DELETE FROM notes WHERE id = ?1", params![id]);
    Redirect::to(&notes_location(channel_id)).into_response()
}

async fn note_image(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<i64>,
) -> Response {
    if let Some(response) = raw_guard(&state, &headers) {
        return response;
    }
    let row = {
        let db = state.db.lock().unwrap();
        db.query_row(
            "SELECT image_type, image_data FROM notes WHERE id = ?1 AND image_data IS NOT NULL",
            params![id],
            |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()
        .unwrap_or(None)
    };
    let Some((image_type, bytes)) = row else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };
    if bytes.len() > MAX_IMAGE_BYTES {
        return (StatusCode::PAYLOAD_TOO_LARGE, "image too large").into_response();
    }
    let content_type = image_type.unwrap_or_else(|| "application/octet-stream".into());
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_str(&content_type).unwrap(),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        bytes,
    )
        .into_response()
}

#[derive(Deserialize)]
struct AgentsQuery {
    slot: Option<i64>,
}

#[derive(Deserialize)]
struct AgentSlotForm {
    name: String,
    workdir: Option<String>,
}

struct PendingUpload {
    filename: String,
    content_type: String,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
struct AgentSlotRow {
    id: i64,
    name: String,
    workdir: String,
}

#[derive(Debug, Clone, Serialize)]
struct AgentAttachmentSummary {
    id: i64,
    name: String,
    content_type: String,
    size_bytes: i64,
    is_image: bool,
}

#[derive(Debug, Clone, Serialize)]
struct AgentMessageRow {
    role: String,
    body: String,
    created_at: String,
    attachment: Option<AgentAttachmentSummary>,
}

#[derive(Serialize)]
struct AgentSlotPoll {
    running: bool,
    current: String,
    message_count: usize,
    messages_html: String,
}

async fn agents_page(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AgentsQuery>,
    headers: HeaderMap,
) -> Response {
    if let Some(response) = page_guard(&state, &headers) {
        return response;
    }
    let slots = {
        let db = state.db.lock().unwrap();
        list_agent_slots(&db).unwrap_or_default()
    };
    let active_slot = slots
        .iter()
        .find(|slot| Some(slot.id) == query.slot)
        .or_else(|| slots.first());
    let Some(active_slot) = active_slot else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "missing agent slot").into_response();
    };
    let messages = {
        let db = state.db.lock().unwrap();
        list_agent_messages(&db, active_slot.id).unwrap_or_default()
    };
    let run = agent_run_for(&state, active_slot.id);
    let status_text = run
        .as_ref()
        .map(|run| {
            if run.current.trim().is_empty() {
                run.status.clone()
            } else {
                run.current.clone()
            }
        })
        .unwrap_or_else(|| "idle".into());
    let slots_html = agent_slots_html(&slots, active_slot.id);
    let messages_html = agent_messages_html(&messages);
    let active_slot_name = html_escape(&active_slot.name);
    let message_count = messages.len();
    page(
        "Agents",
        &format!(
            r##"
<nav><a href="/">Plugdeck</a><strong>Agents</strong></nav>
<main class="chat-shell agent-shell">
  <aside class="channel-rail" aria-label="Slots">
    <div class="rail-title">Slots</div>
    <div class="channel-list">{slots_html}</div>
    <details class="channel-add">
      <summary>Add slot</summary>
      <form action="/agents/slots" method="post" class="channel-form">
        <input name="name" maxlength="{MAX_AGENT_SLOT_CHARS}" placeholder="a" required>
        <input name="workdir" placeholder="Folder">
        <button type="submit">Add</button>
      </form>
    </details>
  </aside>
  <section class="chat-pane agent-pane">
    <header class="chat-head"><strong># {active_slot_name}</strong><span data-agent-count>{message_count} messages</span><span class="agent-status" data-agent-status>{}</span></header>
    <div class="message-list" data-agent-messages>{messages_html}</div>
    <section class="agent-compose-wrap">
      <div class="agent-quick">
        <button type="button" data-agent-cmd="!status">status</button>
        <button type="button" data-agent-cmd="!pwd">pwd</button>
        <button type="button" data-agent-cmd="!ls">ls</button>
        <button type="button" data-agent-cmd="!slots">slots</button>
        <button type="button" data-agent-cmd="!fresh">fresh</button>
        <button type="button" data-agent-cmd="!stayfresh">stayfresh</button>
        <button type="button" data-agent-cmd="!stop">stop</button>
      </div>
      <form action="/agents" method="post" enctype="multipart/form-data" class="agent-composer">
        <input name="slot_id" type="hidden" value="{}">
        <textarea id="agentBody" name="body" maxlength="{MAX_AGENT_MESSAGE_CHARS}" placeholder="Message #{active_slot_name}"></textarea>
        <label class="file-pill"><input name="attachment" type="file" accept="image/*,.pdf,.txt,.md,.csv,.json,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.zip,application/pdf,text/*"><span>Attach</span></label>
        <button type="submit">Send</button>
      </form>
    </section>
  </section>
</main>
<script>
(() => {{
  const list = document.querySelector("[data-agent-messages]");
  const status = document.querySelector("[data-agent-status]");
  const count = document.querySelector("[data-agent-count]");
  const input = document.getElementById("agentBody");
  document.querySelectorAll("[data-agent-cmd]").forEach((button) => {{
    button.addEventListener("click", () => {{
      input.value = button.dataset.agentCmd || "";
      try {{ input.focus({{preventScroll:true}}); }} catch (_) {{ input.focus(); }}
    }});
  }});
  let dirty = false;
  input.addEventListener("input", () => {{ dirty = input.value.length > 0; }});
  input.addEventListener("focus", () => setTimeout(() => input.scrollIntoView({{block:"nearest"}}), 80));
  async function poll() {{
    if (!list || dirty || document.activeElement === input) {{
      setTimeout(poll, 1800);
      return;
    }}
    const nearBottom = list.scrollTop + list.clientHeight >= list.scrollHeight - 90;
    try {{
      const response = await fetch("/agents/slots/{}/state", {{cache:"no-store"}});
      if (response.ok) {{
        const data = await response.json();
        list.innerHTML = data.messages_html;
        status.textContent = data.running ? (data.current || "running") : "idle";
        count.textContent = data.message_count + " messages";
        if (nearBottom) list.scrollTop = list.scrollHeight;
        setTimeout(poll, data.running ? 1200 : 4000);
        return;
      }}
    }} catch (_) {{}}
    setTimeout(poll, 4000);
  }}
  if (list) list.scrollTop = list.scrollHeight;
  setTimeout(poll, 1200);
}})();
</script>
"##,
            html_escape(&status_text),
            active_slot.id,
            active_slot.id
        ),
    )
}

async fn agent_slot_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<AgentSlotForm>,
) -> Response {
    if let Some(response) = page_guard(&state, &headers) {
        return response;
    }
    let name = normalize_agent_slot_name(&form.name);
    let workdir = form
        .workdir
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(expand_local_path)
        .unwrap_or_else(|| state.config.agent_default_workdir.clone());
    let mut slot_id = None;
    if !name.is_empty() && name.chars().count() <= MAX_AGENT_SLOT_CHARS && workdir.is_dir() {
        let db = state.db.lock().unwrap();
        slot_id = ensure_agent_slot(&db, &name, &workdir).ok();
    }
    Redirect::to(&agent_location(slot_id)).into_response()
}

async fn agent_slot_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<i64>,
) -> Response {
    if let Some(response) = page_guard(&state, &headers) {
        return response;
    }
    if let Some(cancel) = state.agent_cancels.lock().unwrap().remove(&id) {
        let _ = cancel.send(());
    }
    let db = state.db.lock().unwrap();
    let slot_count: i64 = db
        .query_row("SELECT COUNT(*) FROM agent_slots", [], |row| row.get(0))
        .unwrap_or(0);
    if slot_count > 1 {
        let _ = db.execute("DELETE FROM agent_slots WHERE id = ?1", params![id]);
    }
    Redirect::to("/agents").into_response()
}

async fn agent_message_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    if let Some(response) = page_guard(&state, &headers) {
        return response;
    }
    let mut slot_id = None;
    let mut body = String::new();
    let mut upload = None;

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "slot_id" => {
                if let Ok(text) = field.text().await {
                    slot_id = text.trim().parse::<i64>().ok();
                }
            }
            "body" => {
                if let Ok(text) = field.text().await {
                    body = text;
                }
            }
            "attachment" | "file" => {
                let filename = field
                    .file_name()
                    .map(str::to_string)
                    .unwrap_or_else(|| "attachment".into());
                let content_type = field
                    .content_type()
                    .map(str::to_string)
                    .unwrap_or_else(|| "application/octet-stream".into());
                if let Ok(bytes) = field.bytes().await
                    && !bytes.is_empty()
                    && bytes.len() <= MAX_AGENT_UPLOAD_BYTES
                {
                    upload = Some(PendingUpload {
                        filename,
                        content_type,
                        bytes: bytes.to_vec(),
                    });
                }
            }
            _ => {}
        }
    }

    let slot_id = slot_id.unwrap_or(1);
    let slot = {
        let db = state.db.lock().unwrap();
        get_agent_slot(&db, slot_id).unwrap_or(None)
    };
    let Some(slot) = slot else {
        return Redirect::to("/agents").into_response();
    };
    let body = body.trim().to_string();
    if body.len() > MAX_AGENT_MESSAGE_CHARS {
        return Redirect::to(&agent_location(Some(slot.id))).into_response();
    }
    let attachment_id = if let Some(upload) = upload {
        save_agent_upload(&state, &slot, upload).await.ok()
    } else {
        None
    };
    if body.is_empty() && attachment_id.is_none() {
        return Redirect::to(&agent_location(Some(slot.id))).into_response();
    }
    {
        let db = state.db.lock().unwrap();
        let _ = append_agent_message(&db, slot.id, "user", &body, attachment_id);
    }
    if handle_agent_control(&state, &slot, &body) {
        return Redirect::to(&agent_location(Some(slot.id))).into_response();
    }
    if state.agent_jobs.lock().unwrap().contains_key(&slot.id) {
        let db = state.db.lock().unwrap();
        let _ = append_agent_message(
            &db,
            slot.id,
            "assistant",
            &format!(
                "{} is already running. Use another slot or send `!stop` first.",
                slot.name
            ),
            None,
        );
        return Redirect::to(&agent_location(Some(slot.id))).into_response();
    }
    let request_body = if body.is_empty() {
        "Please inspect the attached file.".to_string()
    } else {
        body
    };
    start_agent_job(state.clone(), slot.id, request_body, attachment_id);
    Redirect::to(&agent_location(Some(slot.id))).into_response()
}

async fn agent_slot_state(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<i64>,
) -> Response {
    if let Some(response) = raw_guard(&state, &headers) {
        return response;
    }
    let messages = {
        let db = state.db.lock().unwrap();
        list_agent_messages(&db, id).unwrap_or_default()
    };
    let run = agent_run_for(&state, id);
    Json(AgentSlotPoll {
        running: run.is_some(),
        current: run.map(|run| run.current).unwrap_or_default(),
        message_count: messages.len(),
        messages_html: agent_messages_html(&messages),
    })
    .into_response()
}

async fn agent_attachment(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<i64>,
) -> Response {
    if let Some(response) = raw_guard(&state, &headers) {
        return response;
    }
    let row = {
        let db = state.db.lock().unwrap();
        db.query_row(
            "SELECT original_name, content_type, file_path, size_bytes FROM agent_attachments WHERE id = ?1",
            params![id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    PathBuf::from(row.get::<_, String>(2)?),
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .unwrap_or(None)
    };
    let Some((filename, content_type, path, size_bytes)) = row else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };
    if size_bytes < 0 || size_bytes as usize > MAX_AGENT_UPLOAD_BYTES {
        return (StatusCode::PAYLOAD_TOO_LARGE, "file too large").into_response();
    }
    let Ok(path) = path.canonicalize() else {
        return (StatusCode::NOT_FOUND, "missing file").into_response();
    };
    let Ok(root) = state.config.agent_upload_dir.canonicalize() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "bad upload dir").into_response();
    };
    if !path.starts_with(root) || !path.is_file() {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }
    let Ok(bytes) = tokio::fs::read(&path).await else {
        return (StatusCode::NOT_FOUND, "missing file").into_response();
    };
    let ascii_name = filename
        .chars()
        .filter(|ch| ch.is_ascii() && *ch != '"')
        .collect::<String>();
    let disposition = if content_type.starts_with("image/") {
        format!(
            "inline; filename=\"{}\"",
            if ascii_name.is_empty() {
                "attachment"
            } else {
                &ascii_name
            }
        )
    } else {
        format!(
            "attachment; filename=\"{}\"",
            if ascii_name.is_empty() {
                "attachment"
            } else {
                &ascii_name
            }
        )
    };
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_str(&content_type)
                    .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
            ),
            (
                header::CONTENT_DISPOSITION,
                HeaderValue::from_str(&disposition).unwrap(),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        bytes,
    )
        .into_response()
}

fn agent_run_for(state: &AppState, slot_id: i64) -> Option<AgentRun> {
    state.agent_jobs.lock().unwrap().get(&slot_id).cloned()
}

fn agent_slots_html(slots: &[AgentSlotRow], active_id: i64) -> String {
    slots
        .iter()
        .map(|slot| {
            let active_class = if slot.id == active_id { " active" } else { "" };
            let slot_name = html_escape(&slot.name);
            let delete = if slots.len() > 1 {
                format!(
                    r#"<form action="/agents/slots/{}/delete" method="post"><button class="icon danger-icon" type="submit" aria-label="Delete slot {}">x</button></form>"#,
                    slot.id, slot_name
                )
            } else {
                String::new()
            };
            format!(
                r##"<div class="channel-row{active_class}"><a class="channel-link" href="/agents?slot={}"><span>#</span>{}</a>{}</div>"##,
                slot.id, slot_name, delete
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn agent_messages_html(messages: &[AgentMessageRow]) -> String {
    if messages.is_empty() {
        return r#"<p class="empty">No messages in this slot yet.</p>"#.into();
    }
    messages
        .iter()
        .rev()
        .map(|message| {
            let avatar = if message.role == "user" { "U" } else { "A" };
            let body = if message.body.trim().is_empty() {
                String::new()
            } else {
                format!(
                    r#"<p>{}</p>"#,
                    html_escape(&message.body).replace('\n', "<br>")
                )
            };
            let attachment = message
                .attachment
                .as_ref()
                .map(|attachment| {
                    let name = html_escape(&attachment.name);
                    if attachment.is_image {
                        format!(
                            r#"<a class="attachment-link" href="/agents/attachments/{}">{}</a><img class="message-image" src="/agents/attachments/{}" alt="">"#,
                            attachment.id, name, attachment.id
                        )
                    } else {
                        format!(
                            r#"<a class="attachment-link" href="/agents/attachments/{}">{}</a>"#,
                            attachment.id, name
                        )
                    }
                })
                .unwrap_or_default();
            format!(
                r#"<article class="message">
  <div class="message-avatar">{avatar}</div>
  <div class="message-body">
    <div class="message-meta"><strong>{}</strong><span class="message-log">{}</span></div>
    {}{}
  </div>
</article>"#,
                html_escape(&message.role),
                html_escape(&message.created_at),
                body,
                attachment
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn list_agent_slots(db: &Connection) -> rusqlite::Result<Vec<AgentSlotRow>> {
    let mut stmt = db.prepare("SELECT id, name, workdir FROM agent_slots ORDER BY id ASC")?;
    stmt.query_map([], |row| {
        Ok(AgentSlotRow {
            id: row.get(0)?,
            name: row.get(1)?,
            workdir: row.get(2)?,
        })
    })?
    .collect()
}

fn get_agent_slot(db: &Connection, id: i64) -> rusqlite::Result<Option<AgentSlotRow>> {
    db.query_row(
        "SELECT id, name, workdir FROM agent_slots WHERE id = ?1",
        params![id],
        |row| {
            Ok(AgentSlotRow {
                id: row.get(0)?,
                name: row.get(1)?,
                workdir: row.get(2)?,
            })
        },
    )
    .optional()
}

fn ensure_agent_slot(db: &Connection, name: &str, workdir: &Path) -> rusqlite::Result<i64> {
    let existing = db
        .query_row(
            "SELECT id FROM agent_slots WHERE name = ?1",
            params![name],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    if let Some(id) = existing {
        return Ok(id);
    }
    db.execute(
        "INSERT INTO agent_slots (name, workdir, created_at) VALUES (?1, ?2, ?3)",
        params![name, workdir.to_string_lossy(), Utc::now().to_rfc3339()],
    )?;
    Ok(db.last_insert_rowid())
}

fn ensure_agent_slot_seeds(
    db: &Connection,
    seeds: &[AgentSlotSeed],
    default_workdir: &Path,
) -> rusqlite::Result<()> {
    if seeds.is_empty() {
        ensure_agent_slot(db, DEFAULT_AGENT_SLOT, default_workdir)?;
        return Ok(());
    }
    for seed in seeds {
        ensure_agent_slot(db, &seed.name, &seed.workdir)?;
    }
    Ok(())
}

fn list_agent_messages(db: &Connection, slot_id: i64) -> rusqlite::Result<Vec<AgentMessageRow>> {
    let mut stmt = db.prepare(
        "SELECT m.role, m.body, m.created_at, a.id, a.original_name, a.content_type, a.size_bytes
         FROM agent_messages m
         LEFT JOIN agent_attachments a ON a.id = m.attachment_id
         WHERE m.slot_id = ?1
         ORDER BY m.id DESC
         LIMIT 200",
    )?;
    stmt.query_map(params![slot_id], |row| {
        let attachment_id = row.get::<_, Option<i64>>(3)?;
        let attachment = if let Some(id) = attachment_id {
            let content_type = row.get::<_, String>(5)?;
            Some(AgentAttachmentSummary {
                id,
                name: row.get(4)?,
                is_image: content_type.starts_with("image/"),
                content_type,
                size_bytes: row.get(6)?,
            })
        } else {
            None
        };
        Ok(AgentMessageRow {
            role: row.get(0)?,
            body: row.get(1)?,
            created_at: row.get(2)?,
            attachment,
        })
    })?
    .collect()
}

fn append_agent_message(
    db: &Connection,
    slot_id: i64,
    role: &str,
    body: &str,
    attachment_id: Option<i64>,
) -> rusqlite::Result<i64> {
    db.execute(
        "INSERT INTO agent_messages (slot_id, role, body, attachment_id, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![slot_id, role, body, attachment_id, Utc::now().to_rfc3339()],
    )?;
    Ok(db.last_insert_rowid())
}

fn append_agent_assistant(state: &AppState, slot_id: i64, body: &str) {
    let db = state.db.lock().unwrap();
    let _ = append_agent_message(&db, slot_id, "assistant", body, None);
}

async fn save_agent_upload(
    state: &AppState,
    slot: &AgentSlotRow,
    upload: PendingUpload,
) -> io::Result<i64> {
    let safe_name = sanitize_filename(&upload.filename);
    let stored_name = format!("{}-{safe_name}", Uuid::new_v4().simple());
    let slot_dir = state
        .config
        .agent_upload_dir
        .join(format!("slot-{}", slot.id));
    tokio::fs::create_dir_all(&slot_dir).await?;
    let path = slot_dir.join(&stored_name);
    tokio::fs::write(&path, &upload.bytes).await?;
    let db = state.db.lock().unwrap();
    db.execute(
        "INSERT INTO agent_attachments (slot_id, original_name, stored_name, content_type, file_path, size_bytes, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            slot.id,
            upload.filename,
            stored_name,
            upload.content_type,
            path.to_string_lossy(),
            upload.bytes.len() as i64,
            Utc::now().to_rfc3339()
        ],
    )
    .map_err(io_other)?;
    Ok(db.last_insert_rowid())
}

fn handle_agent_control(state: &Arc<AppState>, slot: &AgentSlotRow, body: &str) -> bool {
    let trimmed = body.trim();
    let Some(text) = trimmed.strip_prefix('!').map(str::trim) else {
        return false;
    };
    let lower = text.to_ascii_lowercase();
    if matches!(lower.as_str(), "help" | "commands") {
        append_agent_assistant(state, slot.id, &agent_help_text(state));
        return true;
    }
    if matches!(lower.as_str(), "slots" | "list" | "overview") {
        append_agent_assistant(state, slot.id, &agent_slots_status_text(state));
        return true;
    }
    if lower == "pwd" {
        append_agent_assistant(
            state,
            slot.id,
            &format!("{} folder: `{}`", slot.name, slot.workdir),
        );
        return true;
    }
    if lower == "status" {
        let run = agent_run_for(state, slot.id);
        let status = run
            .as_ref()
            .map(|run| run.current.as_str())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(if run.is_some() { "running" } else { "idle" });
        append_agent_assistant(
            state,
            slot.id,
            &format!("{} is {status}. Folder: `{}`", slot.name, slot.workdir),
        );
        return true;
    }
    if lower == "model" || lower == "settings" {
        append_agent_assistant(
            state,
            slot.id,
            &format!(
                "Agent command: `{}` `{}`",
                state.config.agent_codex_bin,
                state.config.agent_codex_args.join(" ")
            ),
        );
        return true;
    }
    if matches!(lower.as_str(), "fresh" | "new" | "stayfresh") {
        let keep_workdir = lower == "stayfresh";
        let stopped = stop_agent_job(state, slot.id);
        let workdir = if keep_workdir {
            slot.workdir.clone()
        } else {
            state
                .config
                .agent_default_workdir
                .to_string_lossy()
                .to_string()
        };
        {
            let db = state.db.lock().unwrap();
            if !keep_workdir {
                let _ = db.execute(
                    "UPDATE agent_slots SET workdir = ?1 WHERE id = ?2",
                    params![workdir, slot.id],
                );
            }
            let _ = db.execute(
                "DELETE FROM agent_sessions WHERE slot_id = ?1",
                params![slot.id],
            );
            let _ = db.execute(
                "DELETE FROM agent_messages WHERE slot_id = ?1",
                params![slot.id],
            );
        }
        let folder_text = if keep_workdir {
            format!("Folder kept at `{workdir}`.")
        } else {
            format!("Folder reset to `{workdir}`.")
        };
        let stop_text = if stopped {
            " Stopped the current job."
        } else {
            ""
        };
        append_agent_assistant(
            state,
            slot.id,
            &format!(
                "{} chat reset. {folder_text}{stop_text} Your next message starts a new agent chat.",
                slot.name
            ),
        );
        return true;
    }
    if lower == "stop" {
        let stopped = stop_agent_job(state, slot.id);
        append_agent_assistant(
            state,
            slot.id,
            if stopped {
                "Stop requested."
            } else {
                "This slot is not running."
            },
        );
        return true;
    }
    if let Some(arg) = command_arg(text, "cd") {
        let target = if arg.trim().is_empty() {
            default_home_dir()
        } else {
            resolve_agent_path(arg, &slot.workdir)
        };
        if target.is_dir() {
            let db = state.db.lock().unwrap();
            let _ = db.execute(
                "UPDATE agent_slots SET workdir = ?1 WHERE id = ?2",
                params![target.to_string_lossy(), slot.id],
            );
            let _ = db.execute(
                "DELETE FROM agent_sessions WHERE slot_id = ?1",
                params![slot.id],
            );
            drop(db);
            append_agent_assistant(
                state,
                slot.id,
                &format!("{} folder set to `{}`", slot.name, target.display()),
            );
        } else {
            append_agent_assistant(
                state,
                slot.id,
                &format!("Folder does not exist: `{}`", target.display()),
            );
        }
        return true;
    }
    if let Some(arg) = command_arg(text, "ls") {
        append_agent_assistant(state, slot.id, &list_agent_path_text(slot, arg));
        return true;
    }
    append_agent_assistant(
        state,
        slot.id,
        &format!("Unknown Plugdeck agent command: `{text}`. Type `!help` for commands."),
    );
    true
}

fn stop_agent_job(state: &AppState, slot_id: i64) -> bool {
    let cancel = state.agent_cancels.lock().unwrap().remove(&slot_id);
    if let Some(cancel) = cancel {
        let _ = cancel.send(());
        true
    } else {
        false
    }
}

fn agent_help_text(state: &AppState) -> String {
    let slots = {
        let db = state.db.lock().unwrap();
        list_agent_slots(&db).unwrap_or_default()
    };
    let mut lines = vec!["Agent commands:".to_string()];
    lines.extend(
        [
            "- `!help` or `!commands`",
            "- `!slots`",
            "- `!pwd`",
            "- `!ls [path]`",
            "- `!cd [path]`",
            "- `!fresh`",
            "- `!stayfresh`",
            "- `!status`",
            "- `!stop`",
            "- `!model`",
        ]
        .into_iter()
        .map(str::to_string),
    );
    lines.push(String::new());
    lines.push("Slots:".into());
    for slot in slots {
        lines.push(format!("- `{}` at `{}`", slot.name, slot.workdir));
    }
    lines.join("\n")
}

fn agent_slots_status_text(state: &AppState) -> String {
    let slots = {
        let db = state.db.lock().unwrap();
        list_agent_slots(&db).unwrap_or_default()
    };
    let jobs = state.agent_jobs.lock().unwrap();
    let lines = slots
        .iter()
        .map(|slot| {
            let state = if jobs.contains_key(&slot.id) {
                "running"
            } else {
                "idle"
            };
            format!("{}: {state} | {}", slot.name, slot.workdir)
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!("Slots:\n```text\n{lines}\n```")
}

fn list_agent_path_text(slot: &AgentSlotRow, arg: &str) -> String {
    let target = if arg.trim().is_empty() {
        PathBuf::from(&slot.workdir)
    } else {
        resolve_agent_path(arg, &slot.workdir)
    };
    if !target.exists() {
        return format!("Path does not exist: `{}`", target.display());
    }
    if target.is_file() {
        return format!("{} file:\n```text\n{}\n```", slot.name, target.display());
    }
    if !target.is_dir() {
        return format!("Path is not a directory: `{}`", target.display());
    }
    let mut rows = match fs::read_dir(&target) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with('.') {
                    return None;
                }
                let suffix = if path.is_dir() { "/" } else { "" };
                Some((
                    if path.is_dir() { 0 } else { 1 },
                    name.to_lowercase(),
                    format!("{name}{suffix}"),
                ))
            })
            .collect::<Vec<_>>(),
        Err(err) => return format!("Could not list `{}`: {err}", target.display()),
    };
    rows.sort();
    let mut names = rows
        .into_iter()
        .take(120)
        .map(|(_, _, name)| name)
        .collect::<Vec<_>>();
    if names.is_empty() {
        names.push("(empty)".into());
    }
    format!(
        "{} listing `{}`:\n```text\n{}\n```",
        slot.name,
        target.display(),
        names.join("\n")
    )
}

fn start_agent_job(
    state: Arc<AppState>,
    slot_id: i64,
    request_body: String,
    attachment_id: Option<i64>,
) {
    state.agent_jobs.lock().unwrap().insert(
        slot_id,
        AgentRun {
            status: "starting".into(),
            current: "starting".into(),
            started_at: Utc::now().to_rfc3339(),
        },
    );
    tokio::spawn(run_agent_job(state, slot_id, request_body, attachment_id));
}

async fn run_agent_job(
    state: Arc<AppState>,
    slot_id: i64,
    request_body: String,
    attachment_id: Option<i64>,
) {
    let slot = {
        let db = state.db.lock().unwrap();
        get_agent_slot(&db, slot_id).unwrap_or(None)
    };
    let Some(slot) = slot else {
        state.agent_jobs.lock().unwrap().remove(&slot_id);
        return;
    };
    append_agent_assistant(
        &state,
        slot_id,
        &format!("{} started in `{}`.", slot.name, slot.workdir),
    );
    let attachment = attachment_id.and_then(|id| {
        let db = state.db.lock().unwrap();
        agent_attachment_for_prompt(&db, id).unwrap_or(None)
    });
    let prompt = build_agent_prompt(&slot, &request_body, attachment.as_ref());
    let session = {
        let db = state.db.lock().unwrap();
        agent_session(&db, slot_id).unwrap_or(None)
    };
    let use_resume = session
        .as_ref()
        .is_some_and(|(_, workdir)| workdir == &slot.workdir);
    let out_path = env::temp_dir().join(format!(
        "plugdeck-agent-{}-{}.txt",
        slot_id,
        Uuid::new_v4().simple()
    ));
    let mut command = TokioCommand::new(&state.config.agent_codex_bin);
    command.arg("exec");
    if use_resume {
        command.arg("resume").arg("--json");
    } else {
        command.arg("--json");
    }
    command.args(&state.config.agent_codex_args);
    if use_resume {
        if let Some((thread_id, _)) = session {
            command
                .arg("--output-last-message")
                .arg(&out_path)
                .arg(thread_id)
                .arg(prompt);
        }
    } else {
        command
            .arg("--cd")
            .arg(&slot.workdir)
            .arg("--output-last-message")
            .arg(&out_path)
            .arg(prompt);
    }
    command
        .current_dir(&slot.workdir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) => {
            append_agent_assistant(
                &state,
                slot_id,
                &format!("Could not start `{}`: {err}", state.config.agent_codex_bin),
            );
            state.agent_jobs.lock().unwrap().remove(&slot_id);
            return;
        }
    };
    let (cancel_tx, mut cancel_rx) = oneshot::channel();
    state
        .agent_cancels
        .lock()
        .unwrap()
        .insert(slot_id, cancel_tx);
    let stdout_task = child.stdout.take().map(|stdout| {
        tokio::spawn(read_agent_stdout(
            state.clone(),
            slot_id,
            slot.workdir.clone(),
            stdout,
        ))
    });
    let stderr_tail = Arc::new(Mutex::new(Vec::<String>::new()));
    let stderr_task = child
        .stderr
        .take()
        .map(|stderr| tokio::spawn(read_agent_stderr(stderr_tail.clone(), stderr)));
    let started = Utc::now();
    let stopped;
    let status = tokio::select! {
        result = child.wait() => {
            stopped = false;
            result
        }
        _ = &mut cancel_rx => {
            stopped = true;
            let _ = child.start_kill();
            child.wait().await
        }
    };
    if let Some(task) = stdout_task {
        let _ = task.await;
    }
    if let Some(task) = stderr_task {
        let _ = task.await;
    }
    state.agent_cancels.lock().unwrap().remove(&slot_id);
    state.agent_jobs.lock().unwrap().remove(&slot_id);
    let elapsed = (Utc::now() - started).num_seconds().max(0);
    if stopped {
        append_agent_assistant(
            &state,
            slot_id,
            &format!("{} stopped after {elapsed}s.", slot.name),
        );
        let _ = tokio::fs::remove_file(&out_path).await;
        return;
    }
    match status {
        Ok(status) if status.success() => {
            let final_text = tokio::fs::read_to_string(&out_path)
                .await
                .unwrap_or_default()
                .trim()
                .to_string();
            append_agent_assistant(
                &state,
                slot_id,
                &format!(
                    "{} done in {elapsed}s.\n\n{}",
                    slot.name,
                    if final_text.is_empty() {
                        "(Agent completed without a final message.)"
                    } else {
                        &final_text
                    }
                ),
            );
        }
        Ok(status) => {
            let tail = stderr_tail.lock().unwrap().join("\n");
            append_agent_assistant(
                &state,
                slot_id,
                &format!(
                    "{} failed with exit code {} after {elapsed}s.\n\n```text\n{}\n```",
                    slot.name,
                    status.code().unwrap_or(-1),
                    truncate_text(&tail, 2400)
                ),
            );
        }
        Err(err) => {
            append_agent_assistant(
                &state,
                slot_id,
                &format!("{} wait failed after {elapsed}s: {err}", slot.name),
            );
        }
    }
    let _ = tokio::fs::remove_file(&out_path).await;
}

async fn read_agent_stdout(
    state: Arc<AppState>,
    slot_id: i64,
    workdir: String,
    stdout: tokio::process::ChildStdout,
) {
    let mut lines = BufReader::new(stdout).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let Ok(event) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        let event_type = event
            .get("type")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        if event_type == "thread.started"
            && let Some(thread_id) = event.get("thread_id").and_then(|value| value.as_str())
        {
            let db = state.db.lock().unwrap();
            let _ = set_agent_session(&db, slot_id, thread_id, &workdir);
            continue;
        }
        if !matches!(event_type, "item.started" | "item.completed") {
            continue;
        }
        let item = event.get("item").unwrap_or(&serde_json::Value::Null);
        if item.get("type").and_then(|value| value.as_str()) != Some("command_execution") {
            continue;
        }
        let command = item
            .get("command")
            .and_then(|value| value.as_str())
            .unwrap_or("(unknown command)");
        if event_type == "item.started" {
            state
                .agent_jobs
                .lock()
                .unwrap()
                .entry(slot_id)
                .and_modify(|run| {
                    run.status = "running".into();
                    run.current = truncate_text(command, 160);
                });
            append_agent_assistant(
                &state,
                slot_id,
                &format!("running: `{}`", truncate_text(command, 700)),
            );
        } else {
            state
                .agent_jobs
                .lock()
                .unwrap()
                .entry(slot_id)
                .and_modify(|run| {
                    run.current.clear();
                });
            let exit_code = item.get("exit_code").and_then(|value| value.as_i64());
            if exit_code.is_some_and(|code| code != 0) {
                let output = item
                    .get("aggregated_output")
                    .and_then(|value| value.as_str())
                    .unwrap_or("");
                append_agent_assistant(
                    &state,
                    slot_id,
                    &format!(
                        "command exit {}: `{}`\n```text\n{}\n```",
                        exit_code.unwrap_or(-1),
                        truncate_text(command, 500),
                        truncate_text(output, 1200)
                    ),
                );
            }
        }
    }
}

async fn read_agent_stderr(tail: Arc<Mutex<Vec<String>>>, stderr: tokio::process::ChildStderr) {
    let mut lines = BufReader::new(stderr).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut tail = tail.lock().unwrap();
        tail.push(line.to_string());
        if tail.len() > 80 {
            let extra = tail.len() - 80;
            tail.drain(0..extra);
        }
    }
}

async fn downloads_page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(response) = page_guard(&state, &headers) {
        return response;
    }
    let jobs = state
        .jobs
        .lock()
        .unwrap()
        .values()
        .cloned()
        .collect::<Vec<_>>();
    let jobs_html = jobs
        .iter()
        .rev()
        .take(12)
        .map(|job| {
            format!(
                r#"<a class="job" href="/downloads/jobs/{}"><strong>{}</strong><span>{}</span></a>"#,
                html_escape(&job.id),
                html_escape(job.filename.as_deref().unwrap_or(&job.status)),
                html_escape(&job.progress)
            )
        })
        .collect::<Vec<_>>()
        .join("");
    page(
        "YTP Downloader",
        &format!(
            r#"
<nav><a href="/">Plugdeck</a><strong>YTP Downloader</strong></nav>
<main class="download">
  <form action="/downloads" method="post" class="download-form">
    <input name="url" type="url" inputmode="url" placeholder="https://youtu.be/..." required autofocus>
    <button type="submit">Download Video</button>
  </form>
  <section class="jobs">{jobs_html}</section>
</main>
"#
        ),
    )
}

#[derive(Deserialize)]
struct DownloadForm {
    url: String,
}

async fn download_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<DownloadForm>,
) -> Response {
    if let Some(response) = page_guard(&state, &headers) {
        return response;
    }
    let Ok(url) = normalize_youtube_url(&form.url) else {
        return page(
            "YTP Downloader",
            r#"<nav><a href="/">Plugdeck</a><strong>YTP Downloader</strong></nav><main class="download"><p class="error">Only YouTube links are accepted.</p><form action="/downloads" method="post" class="download-form"><input name="url" type="url" inputmode="url" required autofocus><button type="submit">Download Video</button></form></main>"#,
        );
    };
    cleanup_downloads(&state);
    let cache_key = cache_key_for_url(&url);
    let cached = {
        let db = state.db.lock().unwrap();
        cached_file_for_key(&db, &state.config.download_dir, &cache_key).unwrap_or(None)
    };
    let job = if let Some((path, filename)) = cached {
        Job::with_cached(url, cache_key, path, filename)
    } else {
        Job::new(url, cache_key)
    };
    let id = job.id.clone();
    let complete = job.status == "complete";
    state.jobs.lock().unwrap().insert(id.clone(), job);
    if !complete {
        tokio::spawn(run_download_job(state.clone(), id.clone()));
    }
    Redirect::to(&format!("/downloads/jobs/{id}")).into_response()
}

async fn download_job_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    if let Some(response) = page_guard(&state, &headers) {
        return response;
    }
    if !state.jobs.lock().unwrap().contains_key(&id) {
        return (StatusCode::NOT_FOUND, "unknown job").into_response();
    }
    page(
        "YTP Downloader",
        &format!(
            r#"
<nav><a href="/">Plugdeck</a><a href="/downloads">YTP Downloader</a></nav>
<main class="download">
  <h1 id="state">Preparing</h1>
  <div class="bar"><div id="fill"></div></div>
  <p id="error" class="error"></p>
  <p id="ready" hidden><a class="button" id="file" href="/downloads/jobs/{}/file">Save</a></p>
  <pre id="log"></pre>
</main>
<script>
const statusUrl = "/downloads/jobs/{}/status";
function width(progress) {{
  const match = String(progress || "").match(/([0-9.]+)%/);
  if (!match) return "8%";
  return Math.max(4, Math.min(100, Number(match[1]))) + "%";
}}
async function poll() {{
  const response = await fetch(statusUrl, {{cache: "no-store"}});
  if (!response.ok) return;
  const job = await response.json();
  document.getElementById("state").textContent = job.status + (job.progress ? " · " + job.progress : "");
  document.getElementById("fill").style.width = width(job.progress);
  document.getElementById("log").textContent = (job.log || []).join("\n");
  if (job.status === "error") {{
    document.getElementById("error").textContent = job.error || "Download failed.";
    return;
  }}
  if (job.status === "complete") {{
    document.getElementById("ready").hidden = false;
    document.getElementById("fill").style.width = "100%";
    return;
  }}
  setTimeout(poll, 1500);
}}
poll();
</script>
"#,
            html_escape(&id),
            html_escape(&id)
        ),
    )
}

async fn download_job_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    if let Some(response) = raw_guard(&state, &headers) {
        return response;
    }
    let job = state.jobs.lock().unwrap().get(&id).cloned();
    match job {
        Some(job) => Json(job).into_response(),
        None => (StatusCode::NOT_FOUND, "unknown job").into_response(),
    }
}

async fn download_file(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    if let Some(response) = raw_guard(&state, &headers) {
        return response;
    }
    let job = state.jobs.lock().unwrap().get(&id).cloned();
    let Some(job) = job else {
        return (StatusCode::NOT_FOUND, "unknown job").into_response();
    };
    if job.status != "complete" {
        return (StatusCode::CONFLICT, "not ready").into_response();
    }
    let Some(path) = job.file_path else {
        return (StatusCode::NOT_FOUND, "missing file").into_response();
    };
    let Ok(path) = path.canonicalize() else {
        return (StatusCode::NOT_FOUND, "missing file").into_response();
    };
    let Ok(root) = state.config.download_dir.canonicalize() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "bad download dir").into_response();
    };
    if !path.starts_with(root) || !path.is_file() {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }
    let Ok(file) = tokio::fs::File::open(&path).await else {
        return (StatusCode::NOT_FOUND, "missing file").into_response();
    };
    let filename = job.filename.unwrap_or_else(|| {
        path.file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into()
    });
    let ascii_name = sanitize_filename(&filename)
        .chars()
        .filter(|ch| ch.is_ascii() && !ch.is_ascii_control() && *ch != '"')
        .collect::<String>();
    let disposition = format!(
        "attachment; filename=\"{}\"",
        if ascii_name.is_empty() {
            "download.mp4"
        } else {
            &ascii_name
        }
    );
    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_str(
                    mime_guess::from_path(&path)
                        .first_or_octet_stream()
                        .essence_str(),
                )
                .unwrap(),
            ),
            (
                header::CONTENT_DISPOSITION,
                HeaderValue::from_str(&disposition).unwrap(),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        body,
    )
        .into_response()
}

async fn run_download_job(state: Arc<AppState>, id: String) {
    {
        let mut jobs = state.jobs.lock().unwrap();
        if let Some(job) = jobs.get_mut(&id) {
            job.status = "queued".into();
            job.progress.clear();
        }
    }
    let _permit = match state.download_slots.acquire().await {
        Ok(permit) => permit,
        Err(_) => return,
    };
    update_job(&state, &id, |job| {
        job.status = "downloading".into();
        job.progress = "starting".into();
        push_log(job, "Starting download");
    });

    let job = state.jobs.lock().unwrap().get(&id).cloned();
    let Some(job) = job else {
        return;
    };
    let job_dir = state.config.download_dir.join(&job.id);
    if let Err(err) = tokio::fs::create_dir_all(&job_dir).await {
        fail_job(
            &state,
            &id,
            format!("Could not create download directory: {err}"),
        );
        return;
    }

    let output_template = job_dir.join("%(title).180B [%(id)s].%(ext)s");
    let mut command = TokioCommand::new(&state.config.ytdlp);
    command
        .arg("--no-playlist")
        .arg("--newline")
        .arg("--no-part")
        .arg("--restrict-filenames")
        .arg("--windows-filenames")
        .arg("--no-mtime")
        .arg("--socket-timeout")
        .arg("30")
        .arg("--retries")
        .arg("3")
        .arg("--fragment-retries")
        .arg("3")
        .arg("-f")
        .arg("bv*[ext=mp4][vcodec^=avc1][height<=1080]+ba[ext=m4a]/bv*[ext=mp4][height<=1080]+ba[ext=m4a]/b[ext=mp4][vcodec^=avc1][height<=720]/b[ext=mp4][height<=720]/b[ext=mp4]")
        .arg("--merge-output-format")
        .arg("mp4");
    if let Some(runtime) = &state.config.js_runtime {
        command
            .arg("--js-runtimes")
            .arg(format!("node:{}", runtime.display()));
    }
    command.arg("-o").arg(output_template).arg(&job.url);
    command
        .current_dir(&job_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) => {
            fail_job(&state, &id, format!("Could not start yt-dlp: {err}"));
            return;
        }
    };
    if let Some(stdout) = child.stdout.take() {
        let mut lines = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let progress = progress_from_line(&line);
            update_job(&state, &id, |job| {
                if let Some(progress) = progress {
                    job.progress = progress;
                }
                push_log(job, &line);
            });
        }
    }
    let status = match child.wait().await {
        Ok(status) => status,
        Err(err) => {
            fail_job(&state, &id, format!("yt-dlp wait failed: {err}"));
            return;
        }
    };
    if !status.success() {
        fail_job(
            &state,
            &id,
            format!("yt-dlp exited with code {}", status.code().unwrap_or(-1)),
        );
        return;
    }
    let Some(file) = find_downloaded_file(&job_dir) else {
        fail_job(
            &state,
            &id,
            "Download finished but no file was found.".into(),
        );
        return;
    };
    let filename = file
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    {
        let db = state.db.lock().unwrap();
        let _ = db.execute(
            "INSERT OR REPLACE INTO download_cache (cache_key, file_path, filename, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![job.cache_key, file.to_string_lossy(), filename, Utc::now().to_rfc3339()],
        );
    }
    update_job(&state, &id, |job| {
        job.status = "complete".into();
        job.progress = "100%".into();
        job.file_path = Some(file);
        job.filename = Some(filename);
        push_log(job, "Download ready");
    });
}

fn update_job(state: &AppState, id: &str, edit: impl FnOnce(&mut Job)) {
    let mut jobs = state.jobs.lock().unwrap();
    if let Some(job) = jobs.get_mut(id) {
        edit(job);
    }
}

fn fail_job(state: &AppState, id: &str, error: String) {
    update_job(state, id, |job| {
        job.status = "error".into();
        job.error = Some(error);
    });
}

fn push_log(job: &mut Job, line: &str) {
    let line = line.trim();
    if line.is_empty() {
        return;
    }
    job.log.push(line.to_string());
    if job.log.len() > 80 {
        let extra = job.log.len() - 80;
        job.log.drain(0..extra);
    }
}

fn progress_from_line(line: &str) -> Option<String> {
    let marker = "[download]";
    let index = line.find(marker)?;
    let tail = &line[index + marker.len()..];
    let pct = tail.find('%')?;
    let number = tail[..pct]
        .split_whitespace()
        .last()
        .filter(|value| value.chars().all(|ch| ch.is_ascii_digit() || ch == '.'))?;
    Some(format!("{number}%"))
}

fn normalize_youtube_url(raw: &str) -> Result<String, ()> {
    let mut value = raw.trim().to_string();
    if value.is_empty() {
        return Err(());
    }
    if !value.contains("://") {
        value = format!("https://{value}");
    }
    let url = Url::parse(&value).map_err(|_| ())?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(());
    }
    let host = url
        .host_str()
        .unwrap_or("")
        .trim_end_matches('.')
        .to_lowercase();
    let ok = host == "youtu.be"
        || host == "youtube.com"
        || host == "youtube-nocookie.com"
        || host.ends_with(".youtube.com");
    if ok { Ok(value) } else { Err(()) }
}

fn cache_key_for_url(url: &str) -> String {
    if let Ok(parsed) = Url::parse(url) {
        let host = parsed.host_str().unwrap_or("").to_lowercase();
        if host == "youtu.be"
            && let Some(id) = parsed.path_segments().and_then(|mut parts| parts.next())
        {
            return format!("youtube:{id}");
        }
        if (host == "youtube.com" || host.ends_with(".youtube.com"))
            && let Some((_, value)) = parsed.query_pairs().find(|(key, _)| key == "v")
        {
            return format!("youtube:{value}");
        }
    }
    format!("url:{url}")
}

fn allowed_image_type(value: &str) -> bool {
    matches!(
        value,
        "image/gif" | "image/jpeg" | "image/png" | "image/webp"
    )
}

fn find_downloaded_file(dir: &Path) -> Option<PathBuf> {
    let ignored = ["json", "part", "ytdl", "temp", "tmp"];
    fs::read_dir(dir)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .is_none_or(|ext| !ignored.contains(&ext))
                && !path.to_string_lossy().ends_with(".part")
        })
        .max_by_key(|path| {
            path.metadata()
                .map(|meta| (meta.len(), meta.modified().ok()))
                .unwrap_or((0, None))
        })
}

fn cached_file_for_key(
    db: &Connection,
    download_dir: &Path,
    cache_key: &str,
) -> rusqlite::Result<Option<(PathBuf, String)>> {
    let row = db
        .query_row(
            "SELECT file_path, filename FROM download_cache WHERE cache_key = ?1",
            params![cache_key],
            |row| {
                Ok((
                    PathBuf::from(row.get::<_, String>(0)?),
                    row.get::<_, String>(1)?,
                ))
            },
        )
        .optional()?;
    let Some((path, filename)) = row else {
        return Ok(None);
    };
    let Ok(canon) = path.canonicalize() else {
        return Ok(None);
    };
    let Ok(root) = download_dir.canonicalize() else {
        return Ok(None);
    };
    if canon.starts_with(root) && canon.is_file() {
        Ok(Some((canon, filename)))
    } else {
        Ok(None)
    }
}

fn cleanup_downloads(state: &AppState) {
    let cutoff = Utc::now() - state.config.job_ttl;
    state.jobs.lock().unwrap().retain(|_, job| {
        job.created_at >= cutoff || !matches!(job.status.as_str(), "complete" | "error")
    });
    let db = state.db.lock().unwrap();
    let stale = db
        .prepare("SELECT cache_key, file_path, created_at FROM download_cache")
        .and_then(|mut stmt| {
            stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    PathBuf::from(row.get::<_, String>(1)?),
                    row.get::<_, String>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
        })
        .unwrap_or_default();
    for (key, path, created) in stale {
        let parsed = DateTime::parse_from_rfc3339(&created)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());
        if parsed < cutoff {
            let _ = db.execute(
                "DELETE FROM download_cache WHERE cache_key = ?1",
                params![key],
            );
            if let Some(parent) = path.parent() {
                let _ = fs::remove_dir_all(parent);
            }
        }
    }
}

#[derive(Debug)]
struct ChannelRow {
    id: i64,
    name: String,
}

#[derive(Debug)]
struct NoteRow {
    id: i64,
    channel: String,
    body: String,
    has_image: bool,
}

fn list_channels(db: &Connection) -> rusqlite::Result<Vec<ChannelRow>> {
    let mut stmt = db.prepare("SELECT id, name FROM channels ORDER BY id ASC")?;
    stmt.query_map([], |row| {
        Ok(ChannelRow {
            id: row.get(0)?,
            name: row.get(1)?,
        })
    })?
    .collect()
}

fn list_notes(db: &Connection, channel: Option<i64>) -> rusqlite::Result<Vec<NoteRow>> {
    let sql = if channel.is_some() {
        "SELECT n.id, c.name, n.body, n.image_data IS NOT NULL FROM notes n JOIN channels c ON c.id = n.channel_id WHERE n.channel_id = ?1 ORDER BY n.id DESC LIMIT 200"
    } else {
        "SELECT n.id, c.name, n.body, n.image_data IS NOT NULL FROM notes n JOIN channels c ON c.id = n.channel_id ORDER BY n.id DESC LIMIT 200"
    };
    let mut stmt = db.prepare(sql)?;
    let rows = if let Some(channel) = channel {
        stmt.query_map(params![channel], note_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?
    } else {
        stmt.query_map([], note_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    Ok(rows)
}

fn note_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<NoteRow> {
    Ok(NoteRow {
        id: row.get(0)?,
        channel: row.get(1)?,
        body: row.get(2)?,
        has_image: row.get::<_, i64>(3)? != 0,
    })
}

#[derive(Debug, Clone)]
struct AgentPromptAttachment {
    filename: String,
    content_type: String,
    file_path: String,
    size_bytes: i64,
}

fn agent_attachment_for_prompt(
    db: &Connection,
    id: i64,
) -> rusqlite::Result<Option<AgentPromptAttachment>> {
    db.query_row(
        "SELECT original_name, content_type, file_path, size_bytes FROM agent_attachments WHERE id = ?1",
        params![id],
        |row| {
            Ok(AgentPromptAttachment {
                filename: row.get(0)?,
                content_type: row.get(1)?,
                file_path: row.get(2)?,
                size_bytes: row.get(3)?,
            })
        },
    )
    .optional()
}

fn agent_session(db: &Connection, slot_id: i64) -> rusqlite::Result<Option<(String, String)>> {
    db.query_row(
        "SELECT thread_id, workdir FROM agent_sessions WHERE slot_id = ?1",
        params![slot_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .optional()
}

fn set_agent_session(
    db: &Connection,
    slot_id: i64,
    thread_id: &str,
    workdir: &str,
) -> rusqlite::Result<()> {
    db.execute(
        "INSERT INTO agent_sessions (slot_id, thread_id, workdir, updated_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(slot_id) DO UPDATE SET
           thread_id = excluded.thread_id,
           workdir = excluded.workdir,
           updated_at = excluded.updated_at",
        params![slot_id, thread_id, workdir, Utc::now().to_rfc3339()],
    )?;
    Ok(())
}

fn build_agent_prompt(
    slot: &AgentSlotRow,
    request_body: &str,
    attachment: Option<&AgentPromptAttachment>,
) -> String {
    let mut prompt = format!(
        "You are running from Plugdeck agent slot {}.\nCurrent working folder: {}\nKeep the final reply concise and include what changed plus any verification run.\n\nUser request:\n{}",
        slot.name, slot.workdir, request_body
    );
    if let Some(attachment) = attachment {
        prompt.push_str(&format!(
            "\n\nAttached file:\n- name: {}\n- path: {}\n- type: {}\n- bytes: {}\nUse the file path directly if you need to inspect the upload.",
            attachment.filename,
            attachment.file_path,
            attachment.content_type,
            attachment.size_bytes
        ));
    }
    prompt
}

fn agent_location(slot_id: Option<i64>) -> String {
    slot_id
        .filter(|id| *id > 0)
        .map(|id| format!("/agents?slot={id}"))
        .unwrap_or_else(|| "/agents".into())
}

fn command_arg<'a>(text: &'a str, command: &str) -> Option<&'a str> {
    let trimmed = text.trim();
    if trimmed.eq_ignore_ascii_case(command) {
        return Some("");
    }
    if trimmed.len() > command.len()
        && trimmed[..command.len()].eq_ignore_ascii_case(command)
        && trimmed[command.len()..]
            .chars()
            .next()
            .is_some_and(char::is_whitespace)
    {
        return Some(trimmed[command.len()..].trim());
    }
    None
}

fn resolve_agent_path(raw: &str, base: &str) -> PathBuf {
    let expanded = expand_local_path(raw.trim());
    if expanded.is_absolute() {
        expanded
    } else {
        Path::new(base).join(expanded)
    }
}

fn default_home_dir() -> PathBuf {
    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}

fn expand_local_path(value: &str) -> PathBuf {
    let trimmed = value.trim();
    if trimmed == "~" {
        return default_home_dir();
    }
    if let Some(rest) = trimmed.strip_prefix("~/") {
        return default_home_dir().join(rest);
    }
    if let Some(rest) = trimmed.strip_prefix("$HOME/") {
        return default_home_dir().join(rest);
    }
    PathBuf::from(trimmed)
}

fn split_env_args(value: &str) -> Vec<String> {
    value
        .split_whitespace()
        .filter(|part| !part.trim().is_empty())
        .map(str::to_string)
        .collect()
}

fn parse_agent_slot_seeds(raw: Option<String>, default_workdir: &Path) -> Vec<AgentSlotSeed> {
    let raw = raw.unwrap_or_else(|| DEFAULT_AGENT_SLOT.into());
    raw.split(',')
        .filter_map(|item| {
            let item = item.trim();
            if item.is_empty() {
                return None;
            }
            let (name, workdir) = item
                .split_once(':')
                .map(|(name, workdir)| (name, expand_local_path(workdir)))
                .unwrap_or_else(|| (item, default_workdir.to_path_buf()));
            let name = normalize_agent_slot_name(name);
            if name.is_empty() || name.chars().count() > MAX_AGENT_SLOT_CHARS {
                None
            } else {
                Some(AgentSlotSeed { name, workdir })
            }
        })
        .collect()
}

fn normalize_agent_slot_name(value: &str) -> String {
    value
        .trim()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
        .flat_map(char::to_lowercase)
        .collect()
}

fn sanitize_filename(value: &str) -> String {
    let sanitized = value
        .trim()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string();
    if sanitized.is_empty() {
        "attachment".into()
    } else {
        sanitized.chars().take(120).collect()
    }
}

fn truncate_text(value: &str, max_chars: usize) -> String {
    let value = value.trim();
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let keep = max_chars.saturating_sub(20);
    value.chars().take(keep).collect::<String>() + "\n...[truncated]"
}

fn import_motehold(target: &Connection, source_path: &Path) -> io::Result<usize> {
    let source = Connection::open(source_path).map_err(io_other)?;
    let mut imported = 0usize;
    let channels = source
        .prepare("SELECT id, name, created_at FROM channels ORDER BY id ASC")
        .and_then(|mut stmt| {
            stmt.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
        })
        .map_err(io_other)?;
    let mut channel_map = HashMap::new();
    for (old_id, name, created_at) in channels {
        let existing = target
            .query_row(
                "SELECT id FROM channels WHERE name = ?1",
                params![name],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(io_other)?;
        let new_id = if let Some(id) = existing {
            id
        } else {
            target
                .execute(
                    "INSERT INTO channels (name, created_at) VALUES (?1, ?2)",
                    params![name, created_at],
                )
                .map_err(io_other)?;
            target.last_insert_rowid()
        };
        channel_map.insert(old_id, new_id);
    }
    let default_id = ensure_channel(target, DEFAULT_CHANNEL).map_err(io_other)?;
    let mut stmt = source
        .prepare(
            "SELECT id, channel_id, body, image_type, image_data, created_at FROM messages ORDER BY id ASC",
        )
        .map_err(io_other)?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<Vec<u8>>>(4)?,
                row.get::<_, String>(5)?,
            ))
        })
        .map_err(io_other)?;
    for row in rows {
        let (old_id, old_channel, body, image_type, image_data, created_at) =
            row.map_err(io_other)?;
        let source_key = format!("motehold:{}", old_id);
        let already = target
            .query_row(
                "SELECT 1 FROM notes WHERE import_source = ?1",
                params![source_key],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(io_other)?
            .is_some();
        if already {
            continue;
        }
        let channel_id = old_channel
            .and_then(|id| channel_map.get(&id).copied())
            .unwrap_or(default_id);
        target
            .execute(
                "INSERT INTO notes (channel_id, body, image_type, image_data, created_at, import_source) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![channel_id, body, image_type, image_data, created_at, source_key],
            )
            .map_err(io_other)?;
        imported += 1;
    }
    Ok(imported)
}

fn render_links(links: &[Link]) -> String {
    if links.is_empty() {
        return String::new();
    }
    links
        .iter()
        .map(|link| {
            let detail = if link.description.trim().is_empty() {
                html_escape(&link.category)
            } else {
                html_escape(&link.description)
            };
            format!(
                r#"<a class="tile" href="{}"><strong>{}</strong><span>{}</span></a>"#,
                html_escape(&link.url),
                html_escape(&link.name),
                detail
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn notes_location(channel_id: Option<i64>) -> String {
    channel_id
        .filter(|id| *id > 0)
        .map(|id| format!("/notes?channel={id}"))
        .unwrap_or_else(|| "/notes".into())
}

fn page(title: &str, body: &str) -> Response {
    Html(format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover, interactive-widget=resizes-content">
<title>{}</title>
<style>
{PAGE_CSS}
</style>
</head>
<body>{}</body>
</html>"#,
        html_escape(title),
        body
    ))
    .into_response()
}

fn page_guard(state: &AppState, headers: &HeaderMap) -> Option<Response> {
    if authorized(&state.config, headers) {
        None
    } else {
        Some(Redirect::to("/login").into_response())
    }
}

fn raw_guard(state: &AppState, headers: &HeaderMap) -> Option<Response> {
    if authorized(&state.config, headers) {
        None
    } else {
        Some((StatusCode::UNAUTHORIZED, "authentication required").into_response())
    }
}

fn authorized(config: &Config, headers: &HeaderMap) -> bool {
    if config.auth_disabled {
        return true;
    }
    if let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        && let Some(raw) = value.strip_prefix("Basic ")
        && let Ok(decoded) = BASE64.decode(raw.trim())
        && let Ok(pair) = String::from_utf8(decoded)
        && let Some((user, password)) = pair.split_once(':')
    {
        return user == config.user && verify_password(config, password);
    }
    let Some(cookie) = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    cookie
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find(|(name, _)| *name == SESSION_COOKIE)
        .is_some_and(|(_, value)| verify_session_cookie(config, value))
}

fn verify_password(config: &Config, password: &str) -> bool {
    if config.auth_disabled {
        return true;
    }
    let Some(hash) = &config.password_hash else {
        return false;
    };
    if hash.starts_with("$argon2") {
        let Ok(parsed) = PasswordHash::new(hash) else {
            return false;
        };
        return Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok();
    }
    let Some((prefix, rest)) = hash.split_once(':') else {
        return false;
    };
    if prefix != "sha256" {
        return false;
    }
    let Some((salt_hex, expected_hex)) = rest.split_once(':') else {
        return false;
    };
    let Ok(salt) = hex::decode(salt_hex) else {
        return false;
    };
    let Ok(expected) = hex::decode(expected_hex) else {
        return false;
    };
    let actual = password_digest(&salt, password);
    actual.as_slice().ct_eq(expected.as_slice()).into()
}

fn password_digest(salt: &[u8], password: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(password.as_bytes());
    hasher.finalize().to_vec()
}

fn make_session_cookie(config: &Config) -> String {
    let expires = (Utc::now() + Duration::days(SESSION_DAYS)).timestamp();
    let signature = session_signature(config, expires);
    format!(
        "{SESSION_COOKIE}={expires}:{signature}; Max-Age={}; Path=/; HttpOnly; SameSite=Lax",
        SESSION_DAYS * 24 * 60 * 60
    )
}

fn verify_session_cookie(config: &Config, value: &str) -> bool {
    let Some((raw_expires, signature)) = value.split_once(':') else {
        return false;
    };
    let Ok(expires) = raw_expires.parse::<i64>() else {
        return false;
    };
    if expires < Utc::now().timestamp() {
        return false;
    }
    let expected = session_signature(config, expires);
    expected.as_bytes().ct_eq(signature.as_bytes()).into()
}

fn session_signature(config: &Config, expires: i64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(&config.cookie_secret);
    hasher.update(expires.to_string().as_bytes());
    hex::encode(hasher.finalize())
}

fn audit_public_cmd(args: &[String]) -> io::Result<u8> {
    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        println!(
            r#"Usage:
  plugdeck audit-public
  plugdeck audit-public --install-hook

Checks tracked files for local/private paths, common secret markers,
private-network IP leaks, and host-specific denylist terms.
"#
        );
        return Ok(0);
    }

    let root = git_root()?;
    if args.iter().any(|arg| arg == "--install-hook") {
        install_audit_hooks(&root)?;
        println!("installed .git/hooks/pre-commit and .git/hooks/pre-push");
    }

    let findings = audit_public(&root)?;
    if findings.is_empty() {
        println!("audit-public: ok");
        return Ok(0);
    }

    eprintln!("audit-public: found {} issue(s)", findings.len());
    for finding in &findings {
        match finding.line {
            Some(line) => eprintln!("{}:{}: {}", finding.path, line, finding.message),
            None => eprintln!("{}: {}", finding.path, finding.message),
        }
    }
    Ok(1)
}

fn git_root() -> io::Result<PathBuf> {
    let output = StdCommand::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other("not inside a Git repository"));
    }
    Ok(PathBuf::from(
        String::from_utf8_lossy(&output.stdout).trim().to_string(),
    ))
}

fn install_audit_hooks(root: &Path) -> io::Result<()> {
    let hooks = root.join(".git/hooks");
    fs::create_dir_all(&hooks)?;
    for name in ["pre-commit", "pre-push"] {
        let hook = hooks.join(name);
        fs::write(
            &hook,
            r#"#!/bin/sh
set -eu
repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"
cargo run --quiet -- audit-public
"#,
        )?;
        let mut permissions = fs::metadata(&hook)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&hook, permissions)?;
    }
    Ok(())
}

fn audit_public(root: &Path) -> io::Result<Vec<AuditFinding>> {
    let files = git_tracked_files(root)?;
    let private_terms = load_audit_denylist(root);
    let mut findings = Vec::new();

    for path in files {
        if let Some(message) = audit_path(&path) {
            findings.push(AuditFinding {
                path,
                line: None,
                message,
            });
            continue;
        }

        let full_path = root.join(&path);
        if fs::metadata(&full_path)
            .map(|metadata| metadata.len() > 1_000_000)
            .unwrap_or(false)
        {
            continue;
        }
        let Ok(text) = fs::read_to_string(&full_path) else {
            continue;
        };
        for (index, line) in text.lines().enumerate() {
            for message in audit_line(line, &private_terms) {
                findings.push(AuditFinding {
                    path: path.clone(),
                    line: Some(index + 1),
                    message,
                });
            }
        }
    }

    Ok(findings)
}

fn git_tracked_files(root: &Path) -> io::Result<Vec<String>> {
    let output = StdCommand::new("git")
        .args(["ls-files", "-z"])
        .current_dir(root)
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .split('\0')
        .filter(|path| !path.is_empty())
        .map(str::to_string)
        .collect())
}

fn audit_path(path: &str) -> Option<String> {
    let normalized = path.replace('\\', "/");
    let name = normalized.rsplit('/').next().unwrap_or(&normalized);
    let denied_exact = [
        "AGENTS.md",
        "plugdeck.local.toml",
        ".env",
        ".env.local",
        "id_rsa",
        "id_ed25519",
    ];
    if denied_exact.contains(&normalized.as_str()) || denied_exact.contains(&name) {
        return Some("private file path is tracked".into());
    }
    if name.starts_with(".env.") && name != ".env.example" {
        return Some("private env file is tracked".into());
    }
    if normalized.starts_with("docs/private/")
        || normalized.starts_with(".plugdeck/")
        || normalized.starts_with("backups/")
        || normalized.starts_with("data/")
        || normalized.starts_with("downloads/")
    {
        return Some("ignored private/runtime path is tracked".into());
    }
    if normalized.contains("/data/")
        || normalized.contains("/cache/")
        || normalized.contains("/config/")
        || normalized.contains("/downloads/")
        || normalized.contains("/secrets/")
    {
        return Some("runtime or secret data path is tracked".into());
    }
    if matches!(
        Path::new(name).extension().and_then(|ext| ext.to_str()),
        Some("db" | "sqlite" | "sqlite3" | "log" | "pid" | "pem" | "key" | "p12" | "pfx")
    ) {
        return Some("private state or key-like file is tracked".into());
    }
    None
}

fn load_audit_denylist(root: &Path) -> Vec<String> {
    let mut paths = vec![
        root.join("docs/private/audit-denylist.txt"),
        root.join(".plugdeck/audit-denylist.txt"),
    ];
    if let Ok(path) = env::var("PLUGDECK_AUDIT_DENYLIST") {
        paths.push(PathBuf::from(path));
    }

    let mut terms = Vec::new();
    for path in paths {
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        for line in text.lines() {
            let term = line.trim();
            if term.is_empty() || term.starts_with('#') {
                continue;
            }
            terms.push(term.to_ascii_lowercase());
        }
    }
    terms
}

fn audit_line(line: &str, private_terms: &[String]) -> Vec<String> {
    let mut findings = Vec::new();
    let lower = line.to_ascii_lowercase();
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') {
        return findings;
    }

    if line.contains("-----BEGIN ") && line.contains(&["PRIVATE", " KEY"].concat()) {
        findings.push("private key material".into());
    }
    for marker in token_markers() {
        if line.contains(&marker) {
            findings.push(format!("token marker `{marker}`"));
        }
    }
    if contains_tailscale_ipv4(line) {
        findings.push("Tailscale/CGNAT private IP address".into());
    }
    if suspicious_secret_assignment(line) {
        findings.push("non-placeholder secret-looking assignment".into());
    }
    for term in private_terms {
        if !term.is_empty() && lower.contains(term) {
            findings.push("local denylist term".into());
        }
    }

    findings
}

fn token_markers() -> Vec<String> {
    vec![
        ["github", "_pat_"].concat(),
        ["gh", "p_"].concat(),
        ["gh", "o_"].concat(),
        ["gh", "s_"].concat(),
        ["gh", "u_"].concat(),
        ["s", "k-"].concat(),
        ["xo", "xb-"].concat(),
        ["xo", "xp-"].concat(),
    ]
}

fn suspicious_secret_assignment(line: &str) -> bool {
    if line.contains("::") {
        return false;
    }
    let Some((key, value)) = line.split_once('=').or_else(|| line.split_once(':')) else {
        return false;
    };
    let key = key.trim().to_ascii_lowercase();
    if key.is_empty()
        || key.len() > 80
        || !key
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
    {
        return false;
    }
    let secret_keys = [
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "access_key",
        "client_secret",
        "private_key",
    ];
    if !secret_keys.iter().any(|needle| key.contains(needle)) {
        return false;
    }

    let value = value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim_end_matches(',')
        .trim();
    let allowed = [
        "",
        "example",
        "placeholder",
        "changeme",
        "change-me",
        "redacted",
        "dummy",
        "none",
        "null",
        "false",
        "true",
    ];
    if allowed.contains(&value.to_ascii_lowercase().as_str()) {
        return false;
    }
    if value == "String" || value.starts_with("Option<") || value.starts_with("Vec<") {
        return false;
    }
    if value.starts_with("${")
        || value.starts_with('<')
        || value.starts_with("your-")
        || value.contains("...")
        || value.starts_with("Some(")
        || value.starts_with("vec!")
    {
        return false;
    }
    true
}

fn contains_tailscale_ipv4(line: &str) -> bool {
    line.split(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .filter(|token| token.matches('.').count() == 3)
        .any(|token| {
            let octets: Vec<u16> = token
                .split('.')
                .filter_map(|part| part.parse::<u16>().ok())
                .collect();
            octets.len() == 4
                && octets[0] == 100
                && (64..=127).contains(&octets[1])
                && octets.iter().all(|octet| *octet <= 255)
        })
}

fn hash_password_cmd(args: &[String]) -> io::Result<()> {
    if !args.iter().any(|arg| arg == "--stdin") {
        eprintln!("usage: plugdeck hash-password --stdin");
        return Ok(());
    }
    let mut password = String::new();
    io::stdin().read_to_string(&mut password)?;
    let password = password.trim_end_matches(['\r', '\n']);
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let salt = SaltString::encode_b64(&salt).map_err(io_other)?;
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(io_other)?;
    println!("{hash}");
    Ok(())
}

fn random_secret() -> Vec<u8> {
    let mut secret = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);
    secret.to_vec()
}

fn env_flag(name: &str, default: bool) -> bool {
    env::var(name)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(default)
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn io_other(err: impl std::fmt::Display) -> io::Error {
    io::Error::other(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_youtube_domains() {
        assert!(normalize_youtube_url("https://youtu.be/abc123").is_ok());
        assert!(normalize_youtube_url("youtube.com/watch?v=abc123").is_ok());
        assert!(normalize_youtube_url("https://example.com/watch?v=abc123").is_err());
    }

    #[test]
    fn password_hash_round_trips() {
        let salt = [1u8; 16];
        let hash = format!(
            "sha256:{}:{}",
            hex::encode(salt),
            hex::encode(password_digest(&salt, "secret"))
        );
        let config = Config {
            bind: "127.0.0.1:0".into(),
            db_path: PathBuf::new(),
            download_dir: PathBuf::new(),
            agent_default_workdir: PathBuf::new(),
            agent_upload_dir: PathBuf::new(),
            agent_codex_bin: "codex".into(),
            agent_codex_args: Vec::new(),
            agent_slots: Vec::new(),
            ytdlp: "yt-dlp".into(),
            js_runtime: None,
            max_active: 1,
            job_ttl: Duration::hours(24),
            user: "plugdeck".into(),
            password_hash: Some(hash),
            cookie_secret: vec![2u8; 32],
            auth_disabled: false,
            links: Vec::new(),
        };
        assert!(verify_password(&config, "secret"));
        assert!(!verify_password(&config, "wrong"));
    }

    #[test]
    fn audit_rejects_private_paths() {
        assert!(audit_path("plugdeck.local.toml").is_some());
        assert!(audit_path("data/plugdeck.sqlite").is_some());
        assert!(audit_path("docs/private/notes.md").is_some());
    }

    #[test]
    fn audit_detects_cgnat_private_address() {
        let line = format!("service=http://100.{}.10.5:8789", 80);
        assert!(contains_tailscale_ipv4(&line));
        assert!(!contains_tailscale_ipv4("service=http://127.0.0.1:8789"));
    }

    #[test]
    fn audit_secret_assignment_allows_placeholders() {
        assert!(!suspicious_secret_assignment(
            "PLUGDECK_PASSWORD_HASH=<hash>"
        ));
        assert!(!suspicious_secret_assignment(
            "PLUGDECK_COOKIE_SECRET=${SECRET}"
        ));
        assert!(suspicious_secret_assignment(
            "PLUGDECK_COOKIE_SECRET=abc123"
        ));
    }
}
