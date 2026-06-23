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
    cmp::Reverse,
    collections::HashMap,
    env, fs,
    io::{self, BufRead, Read, Write},
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command as StdCommand, Stdio},
    sync::{Arc, Mutex},
    time::{Duration as StdDuration, Instant, SystemTime},
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

mod codex_reset_ledger;
mod db_migrations;
mod modules;

const DEFAULT_CHANNEL: &str = "general";
const DEFAULT_AGENT_SLOTS: &str = "codex";
const CODEX_UNSAFE_ARG: &str = "--dangerously-bypass-approvals-and-sandbox";
const DEFAULT_AGENT_CODEX_ARGS: &str = CODEX_UNSAFE_ARG;
const DEFAULT_MBX_LEGACY_SLOTS: &str = "a,b,c,d,e";
const MAX_NOTE_CHARS: usize = 256 * 1024;
const MAX_IMAGE_BYTES: usize = 5 * 1024 * 1024;
const MAX_AGENT_MESSAGE_CHARS: usize = 128 * 1024;
const MAX_AGENT_UPLOAD_BYTES: usize = 25 * 1024 * 1024;
const MAX_CHANNEL_CHARS: usize = 40;
const MAX_AGENT_SLOT_CHARS: usize = 32;
const MAX_CODEX_CONVERSATIONS: usize = 120;
const MAX_CODEX_TRANSCRIPT_MESSAGES: usize = 80;
const CODEX_SESSION_SCAN_LIMIT: usize = 180;
const CODEX_PROJECT_DRAWER_LIMIT: usize = 48;
const CODEX_PROJECT_VISIBLE_CONVERSATIONS: usize = 3;
const CODEX_PROJECT_CONVERSATION_LIMIT: usize = 24;
const CODEX_INDEX_REFRESH_AFTER: StdDuration = StdDuration::from_secs(30);
const CODEX_APP_SERVER_TIMEOUT: StdDuration = StdDuration::from_secs(12);
const CODEX_APP_SERVER_WRITE_SETTLE: StdDuration = StdDuration::from_secs(5);
const SESSION_COOKIE: &str = "plugdeck_session";
const SESSION_DAYS: i64 = 30;
const PAGE_CSS: &str = include_str!("page.css");

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
        "mbx" => {
            mbx_cmd(&args[1..])?;
            Ok(())
        }
        _ => {
            eprintln!("usage: plugdeck [serve|hash-password --stdin|audit-public|mbx]");
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
        agent_edit_drafts: Mutex::new(HashMap::new()),
        codex_index: Mutex::new(CodexIndexCache::default()),
    });

    state.set_download_slots();
    refresh_codex_index(state.clone());

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
    codex_home: PathBuf,
    codex_reset_command: Option<Vec<String>>,
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

#[derive(Clone, Debug, Serialize)]
struct AgentEditDraft {
    message_id: i64,
    body: String,
}

#[derive(Clone, Debug)]
struct SlotRuntime {
    label: String,
}

#[derive(Clone, Debug)]
struct CodexConversation {
    id: String,
    title: String,
    cwd: String,
    updated_at: String,
    path: PathBuf,
    preview: String,
    message_count: usize,
}

#[derive(Clone, Debug)]
struct CodexProject {
    path: String,
    name: String,
    trusted: bool,
    conversation_count: usize,
}

#[derive(Clone, Debug)]
struct CodexIndex {
    conversations: Vec<CodexConversation>,
    projects: Vec<CodexProject>,
    usage: Option<CodexUsageSnapshot>,
}

impl CodexIndex {
    fn empty() -> Self {
        Self {
            conversations: Vec::new(),
            projects: Vec::new(),
            usage: None,
        }
    }
}

#[derive(Clone, Debug)]
struct CodexUsageSnapshot {
    observed_at: String,
    plan_type: String,
    total_units: i64,
    last_units: i64,
    cached_input_units: i64,
    context_window: i64,
    primary: Option<CodexRateWindow>,
    secondary: Option<CodexRateWindow>,
    credits: Option<String>,
    reset_credits: Option<CodexResetCreditsSummary>,
}

#[derive(Clone, Debug)]
struct CodexRateWindow {
    label: String,
    used_percent: f64,
    remaining_percent: f64,
    window_minutes: i64,
    resets_at: Option<i64>,
}

#[derive(Clone, Debug)]
struct CodexResetCreditsSummary {
    available_count: i64,
    estimate: Option<codex_reset_ledger::ResetCreditEstimate>,
}

#[derive(Default)]
struct CodexIndexCache {
    snapshot: Option<CodexIndex>,
    refreshed_at: Option<Instant>,
    refreshing: bool,
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
            env::var("PLUGDECK_AGENT_CODEX_BIN").unwrap_or_else(|_| default_codex_bin());
        let agent_codex_args = env::var("PLUGDECK_AGENT_CODEX_ARGS")
            .ok()
            .map(|value| split_env_args(&value))
            .unwrap_or_else(default_codex_args);
        let codex_home = env::var("CODEX_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| default_home_dir().join(".codex"));
        let codex_reset_command = env::var("PLUGDECK_CODEX_RESET_COMMAND")
            .ok()
            .map(|value| split_env_args(&value))
            .filter(|parts| !parts.is_empty());
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
            codex_home,
            codex_reset_command,
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
    agent_edit_drafts: Mutex<HashMap<i64, AgentEditDraft>>,
    codex_index: Mutex<CodexIndexCache>,
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

fn codex_index_snapshot(state: &Arc<AppState>) -> Option<CodexIndex> {
    let (snapshot, should_refresh) = {
        let mut cache = state.codex_index.lock().unwrap();
        let stale = cache
            .refreshed_at
            .is_none_or(|refreshed_at| refreshed_at.elapsed() >= CODEX_INDEX_REFRESH_AFTER);
        let should_refresh = stale && !cache.refreshing;
        if should_refresh {
            cache.refreshing = true;
        }
        (cache.snapshot.clone(), should_refresh)
    };
    if should_refresh {
        refresh_codex_index(state.clone());
    }
    snapshot
}

fn refresh_codex_index(state: Arc<AppState>) {
    {
        let mut cache = state.codex_index.lock().unwrap();
        cache.refreshing = true;
    }
    tokio::task::spawn_blocking(move || {
        let index = load_codex_index_for_state(&state);
        let mut cache = state.codex_index.lock().unwrap();
        cache.snapshot = Some(index);
        cache.refreshed_at = Some(Instant::now());
        cache.refreshing = false;
    });
}

fn refresh_codex_index_blocking(state: &Arc<AppState>) -> CodexIndex {
    let index = load_codex_index_for_state(state);
    let mut cache = state.codex_index.lock().unwrap();
    cache.snapshot = Some(index.clone());
    cache.refreshed_at = Some(Instant::now());
    cache.refreshing = false;
    index
}

fn load_codex_index_for_state(state: &Arc<AppState>) -> CodexIndex {
    let mut index = load_codex_index(&state.config);
    attach_codex_reset_credit_estimate(state, &mut index);
    index
}

fn attach_codex_reset_credit_estimate(state: &Arc<AppState>, index: &mut CodexIndex) {
    let Some(summary) = index
        .usage
        .as_mut()
        .and_then(|usage| usage.reset_credits.as_mut())
    else {
        return;
    };
    let db = state.db.lock().unwrap();
    if let Ok(estimate) = codex_reset_ledger::reconcile(&db, summary.available_count, Utc::now()) {
        summary.estimate = Some(estimate);
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
    db_migrations::migrate(&conn).map_err(io_other)?;
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
    thread: Option<String>,
}

#[derive(Deserialize)]
struct AgentConversationForm {
    thread_id: String,
    workdir: String,
}

#[derive(Deserialize)]
struct AgentProjectStartForm {
    workdir: String,
}

#[derive(Deserialize)]
struct CodexResetForm {
    confirm: String,
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

#[derive(Debug, Clone)]
struct MbxSlot {
    id: Option<i64>,
    name: String,
    workdir: String,
    thread_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MbxAction {
    Start,
    New,
    Resume,
}

struct MbxRunOptions {
    workdir: Option<PathBuf>,
    prompt: Vec<String>,
    attach: bool,
    restart: bool,
    dry_run: bool,
    unsafe_mode: bool,
    safe_mode: bool,
}

#[derive(Serialize)]
struct AgentSlotPoll {
    running: bool,
    current: String,
    message_count: usize,
    messages_html: String,
    active_status: String,
    edit_draft: Option<AgentEditDraft>,
}

#[derive(Serialize)]
struct AgentCancelPoll {
    stopped: bool,
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
    let mut codex_snapshot = codex_index_snapshot(&state);
    let selected_thread = query.thread.clone();
    if selected_thread.as_ref().is_some_and(|thread_id| {
        codex_snapshot
            .as_ref()
            .is_none_or(|index| codex_conversation_by_id(index, thread_id).is_none())
    }) {
        codex_snapshot = Some(refresh_codex_index_blocking(&state));
    }
    let codex_loaded = codex_snapshot.is_some();
    let codex = codex_snapshot.unwrap_or_else(CodexIndex::empty);
    let messages = {
        let db = state.db.lock().unwrap();
        list_agent_messages(&db, active_slot.id).unwrap_or_default()
    };
    let runtime = agent_slot_runtime(&state, active_slot);
    let browser_drawer = codex_browser_drawer_html(
        &codex.projects,
        &codex.conversations,
        active_slot.id,
        selected_thread.as_deref(),
        codex_loaded,
    );
    let messages_html = selected_thread
        .as_deref()
        .and_then(|thread_id| codex_transcript_html(&codex, thread_id).ok())
        .unwrap_or_else(|| agent_messages_html(&messages));
    let active_title = selected_thread
        .as_deref()
        .and_then(|thread_id| codex_conversation_by_id(&codex, thread_id))
        .map(|conversation| conversation.title.clone())
        .unwrap_or_else(|| "Codex".into());
    let active_title = html_escape(&active_title);
    let active_slot_workdir = html_escape(&active_slot.workdir);
    let message_count = if selected_thread.is_some() {
        codex_transcript_count(&messages_html).unwrap_or(messages.len())
    } else {
        messages.len()
    };
    let usage_dialog = codex_usage_dialog(&state.config, codex.usage.as_ref(), codex_loaded);
    let viewing_transcript = selected_thread.is_some();
    let edit_draft = state
        .agent_edit_drafts
        .lock()
        .unwrap()
        .get(&active_slot.id)
        .cloned();
    let edit_draft_json = serde_json::to_string(&edit_draft)
        .unwrap_or_else(|_| "null".into())
        .replace("</", "<\\/");
    let running = state
        .agent_jobs
        .lock()
        .unwrap()
        .contains_key(&active_slot.id);
    let cancel_hidden = if running { "" } else { " hidden" };
    page(
        "Agents",
        &format!(
            r##"
<nav><a href="/">Plugdeck</a><div class="nav-actions"><button type="button" class="ghost" data-browser-open>Browse</button><button type="button" class="ghost" data-codex-open>Usage</button><strong>Agents</strong></div></nav>
<main class="chat-shell agent-shell agent-single">
  <section class="chat-pane agent-pane">
    <header class="chat-head">
      <div class="chat-title"><strong>{active_title}</strong><span>{active_slot_workdir}</span></div>
      <div class="chat-stats"><span data-agent-count>{message_count} messages</span><span class="agent-status" data-agent-status>{}</span></div>
    </header>
    <div class="message-list" data-agent-messages>{messages_html}</div>
    <section class="agent-compose-wrap">
      <form action="/agents" method="post" enctype="multipart/form-data" class="agent-composer">
        <input name="slot_id" type="hidden" value="{}">
        <input name="edit_message_id" type="hidden" value="" data-edit-message-id>
        <div class="agent-edit-bar" data-edit-bar hidden><span>Last send was canceled.</span><button type="button" class="ghost" data-edit-draft>Edit canceled send</button></div>
        <textarea id="agentBody" name="body" maxlength="{MAX_AGENT_MESSAGE_CHARS}" placeholder="Message Codex"></textarea>
        <label class="file-pill"><input name="attachment" type="file" accept="image/*,.pdf,.txt,.md,.csv,.json,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.zip,application/pdf,text/*"><span>Attach</span></label>
        <button type="button" class="ghost agent-cancel"{cancel_hidden} data-agent-cancel>Cancel</button>
        <button type="submit" data-agent-send>Send</button>
      </form>
    </section>
  </section>
</main>
{browser_drawer}
{usage_dialog}
<script>
(() => {{
  const list = document.querySelector("[data-agent-messages]");
  const status = document.querySelector("[data-agent-status]");
  const count = document.querySelector("[data-agent-count]");
  const input = document.getElementById("agentBody");
  const editId = document.querySelector("[data-edit-message-id]");
  const editBar = document.querySelector("[data-edit-bar]");
  const editButton = document.querySelector("[data-edit-draft]");
  const cancelButton = document.querySelector("[data-agent-cancel]");
  const sendButton = document.querySelector("[data-agent-send]");
  let editDraft = {edit_draft_json};
  const viewingTranscript = {viewing_transcript};
  function setRunning(running) {{
    if (cancelButton) cancelButton.hidden = !running;
    if (sendButton) sendButton.disabled = !!running;
  }}
  function setEditDraft(draft) {{
    editDraft = draft || null;
    if (editBar) editBar.hidden = !editDraft;
  }}
  function startEditingDraft() {{
    if (!editDraft || !input || !editId) return;
    input.value = editDraft.body || "";
    editId.value = String(editDraft.message_id || "");
    dirty = true;
    if (sendButton) sendButton.textContent = "Resend";
    input.focus();
  }}
  setRunning({running});
  setEditDraft(editDraft);
  editButton?.addEventListener("click", startEditingDraft);
  cancelButton?.addEventListener("click", async () => {{
    cancelButton.disabled = true;
    status.textContent = "canceling";
    try {{
      await fetch("/agents/slots/{}/cancel", {{method:"POST", cache:"no-store"}});
    }} catch (_) {{}}
    setTimeout(() => {{
      cancelButton.disabled = false;
      poll(true);
    }}, 700);
  }});
  const codexPanel = document.getElementById("codexPanel");
  document.querySelector("[data-codex-open]")?.addEventListener("click", () => {{
    if (codexPanel && typeof codexPanel.showModal === "function") codexPanel.showModal();
  }});
  document.querySelector("[data-codex-close]")?.addEventListener("click", () => codexPanel?.close());
  const browserPanel = document.getElementById("conversationDrawer");
  const setBrowserOpen = (open) => document.body.classList.toggle("browser-open", open);
  document.querySelector("[data-browser-open]")?.addEventListener("click", () => {{
    if (browserPanel && typeof browserPanel.showModal === "function") {{
      browserPanel.showModal();
      setBrowserOpen(true);
    }}
  }});
  document.querySelector("[data-browser-close]")?.addEventListener("click", () => browserPanel?.close());
  browserPanel?.addEventListener("close", () => setBrowserOpen(false));
  browserPanel?.addEventListener("cancel", () => setBrowserOpen(false));
  const browserSearch = document.querySelector("[data-browser-search]");
  function filterBrowserConversations() {{
    const query = (browserSearch?.value || "").trim().toLowerCase();
    document.querySelectorAll("[data-project-group]").forEach((group) => {{
      const rows = Array.from(group.querySelectorAll("[data-conversation-row]"));
      const more = group.querySelector("[data-load-more]");
      if (!query) {{
        const expanded = group.dataset.expanded === "true";
        rows.forEach((row) => {{
          row.hidden = row.hasAttribute("data-extra-conversation") && !expanded;
        }});
        if (more) more.hidden = expanded;
        group.hidden = false;
        return;
      }}
      const projectMatches = (group.dataset.searchText || group.textContent || "").toLowerCase().includes(query);
      let matchedRows = 0;
      rows.forEach((row) => {{
        const matches = (row.dataset.searchText || row.textContent || "").toLowerCase().includes(query);
        row.hidden = !matches;
        if (matches) matchedRows += 1;
      }});
      if (more) more.hidden = true;
      group.hidden = !(projectMatches || matchedRows > 0);
    }});
  }}
  browserSearch?.addEventListener("input", filterBrowserConversations);
  list?.addEventListener("click", async (event) => {{
    const button = event.target.closest("[data-copy-message]");
    if (!button) return;
    const text = button.closest(".message")?.querySelector(".message-text")?.innerText || "";
    if (!text) return;
    try {{
      await navigator.clipboard.writeText(text);
    }} catch (_) {{
      const fallback = document.createElement("textarea");
      fallback.value = text;
      fallback.style.position = "fixed";
      fallback.style.left = "-9999px";
      document.body.appendChild(fallback);
      fallback.focus();
      fallback.select();
      document.execCommand("copy");
      fallback.remove();
    }}
    const previous = button.textContent;
    button.textContent = "Copied";
    setTimeout(() => button.textContent = previous, 1200);
  }});
  document.querySelectorAll("[data-load-more]").forEach((button) => {{
    button.addEventListener("click", () => {{
      const group = button.closest("[data-project-group]");
      if (!group) return;
      group.dataset.expanded = "true";
      group.querySelectorAll("[data-extra-conversation]").forEach((row) => row.hidden = false);
      button.hidden = true;
    }});
  }});
  document.querySelector("[data-reset-form]")?.addEventListener("submit", (event) => {{
    const ok = window.confirm("Use a Codex reset now? This cannot be undone.");
    if (!ok) event.preventDefault();
  }});
  let dirty = false;
  input.addEventListener("input", () => {{ dirty = input.value.length > 0; }});
  input.form?.addEventListener("submit", () => {{
    if (sendButton) sendButton.disabled = true;
    dirty = false;
    input.blur();
    setRunning(true);
    status.textContent = "starting";
    setTimeout(() => poll(true), 700);
  }});
  input.addEventListener("focus", () => setTimeout(() => input.scrollIntoView({{block:"nearest"}}), 80));
  async function poll(force = false) {{
    if (!list || (!force && (dirty || document.activeElement === input))) {{
      setTimeout(poll, 1800);
      return;
    }}
    const nearBottom = list.scrollTop + list.clientHeight >= list.scrollHeight - 90;
    try {{
      const response = await fetch("/agents/slots/{}/state", {{cache:"no-store"}});
      if (response.ok) {{
        const data = await response.json();
        list.innerHTML = data.messages_html;
        status.textContent = data.active_status || (data.running ? (data.current || "running") : "idle");
        count.textContent = data.message_count + " messages";
        setRunning(data.running);
        setEditDraft(data.edit_draft);
        if (nearBottom) list.scrollTop = list.scrollHeight;
        setTimeout(poll, data.running ? 1200 : 4000);
        return;
      }}
    }} catch (_) {{}}
    setTimeout(poll, 4000);
  }}
  if (list) list.scrollTop = list.scrollHeight;
  if (!viewingTranscript) setTimeout(poll, 1200);
}})();
</script>
"##,
            html_escape(&runtime.label),
            active_slot.id,
            active_slot.id,
            active_slot.id
        ),
    )
}

async fn agent_conversation_load(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<i64>,
    Form(form): Form<AgentConversationForm>,
) -> Response {
    if let Some(response) = page_guard(&state, &headers) {
        return response;
    }
    let mut codex = codex_index_snapshot(&state);
    if codex
        .as_ref()
        .is_none_or(|index| codex_conversation_by_id(index, &form.thread_id).is_none())
    {
        codex = Some(refresh_codex_index_blocking(&state));
    }
    let codex_loaded = codex.is_some();
    let conversation = codex
        .as_ref()
        .and_then(|index| codex_conversation_by_id(index, &form.thread_id));
    if codex_loaded && conversation.is_none() {
        return Redirect::to(&agent_location(Some(id))).into_response();
    }
    let requested_workdir = expand_local_path(&form.workdir);
    let workdir = if requested_workdir.is_dir() {
        requested_workdir
            .canonicalize()
            .unwrap_or_else(|_| requested_workdir.clone())
    } else if let Some(conversation) = conversation {
        expand_local_path(&conversation.cwd)
    } else {
        return Redirect::to(&agent_location(Some(id))).into_response();
    };
    if !workdir.is_dir() {
        return Redirect::to(&agent_location(Some(id))).into_response();
    }
    {
        let db = state.db.lock().unwrap();
        let _ = db.execute(
            "UPDATE agent_slots SET workdir = ?1 WHERE id = ?2",
            params![workdir.to_string_lossy(), id],
        );
        let _ = set_agent_session(&db, id, &form.thread_id, &workdir.to_string_lossy());
    }
    state.agent_edit_drafts.lock().unwrap().remove(&id);
    Redirect::to(&format!(
        "{}&thread={}",
        agent_location(Some(id)),
        url_encode(&form.thread_id)
    ))
    .into_response()
}

async fn agent_project_start(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<i64>,
    Form(form): Form<AgentProjectStartForm>,
) -> Response {
    if let Some(response) = page_guard(&state, &headers) {
        return response;
    }
    let slot = {
        let db = state.db.lock().unwrap();
        get_agent_slot(&db, id).unwrap_or(None)
    };
    let Some(slot) = slot else {
        return Redirect::to("/agents").into_response();
    };
    let requested_workdir = expand_local_path(&form.workdir);
    let workdir = if requested_workdir.is_dir() {
        requested_workdir
            .canonicalize()
            .unwrap_or_else(|_| requested_workdir.clone())
    } else {
        return Redirect::to(&agent_location(Some(slot.id))).into_response();
    };
    let stopped = stop_agent_job(&state, slot.id);
    let workdir_text = workdir.to_string_lossy().to_string();
    let stop_text = if stopped {
        " Stopped the current job."
    } else {
        ""
    };
    {
        let db = state.db.lock().unwrap();
        let _ = db.execute(
            "UPDATE agent_slots SET workdir = ?1 WHERE id = ?2",
            params![workdir_text, slot.id],
        );
        let _ = db.execute(
            "DELETE FROM agent_sessions WHERE slot_id = ?1",
            params![slot.id],
        );
        let _ = db.execute(
            "DELETE FROM agent_messages WHERE slot_id = ?1",
            params![slot.id],
        );
        let _ = append_agent_message(
            &db,
            slot.id,
            "assistant",
            &format!(
                "{} ready in `{}`.{stop_text} Your next message starts a new agent chat.",
                slot.name,
                workdir.display()
            ),
            None,
        );
    }
    state.agent_edit_drafts.lock().unwrap().remove(&slot.id);
    Redirect::to(&agent_location(Some(slot.id))).into_response()
}

async fn codex_reset_post(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<CodexResetForm>,
) -> Response {
    if let Some(response) = page_guard(&state, &headers) {
        return response;
    }
    if form.confirm.trim() != "USE_RESET" {
        return (StatusCode::BAD_REQUEST, "confirmation required").into_response();
    }
    if let Some(command) = &state.config.codex_reset_command {
        let Some((program, args)) = command.split_first() else {
            return (StatusCode::CONFLICT, "no reset command configured").into_response();
        };
        let output = StdCommand::new(program).args(args).output();
        return match output {
            Ok(output) if output.status.success() => {
                refresh_codex_index(state.clone());
                Redirect::to("/agents").into_response()
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("reset command failed: {}", truncate_text(&stderr, 1000)),
                )
                    .into_response()
            }
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("could not start reset command: {err}"),
            )
                .into_response(),
        };
    }
    match consume_codex_rate_limit_reset_credit(&state.config) {
        Some(outcome) if outcome == "reset" || outcome == "alreadyRedeemed" => {
            refresh_codex_index(state.clone());
            Redirect::to("/agents").into_response()
        }
        Some(outcome) if outcome == "nothingToReset" => (
            StatusCode::CONFLICT,
            "no current Codex limit window is eligible for reset",
        )
            .into_response(),
        Some(outcome) if outcome == "noCredit" => (
            StatusCode::CONFLICT,
            "Codex reports no reset credits available",
        )
            .into_response(),
        Some(outcome) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("unexpected Codex reset outcome: {outcome}"),
        )
            .into_response(),
        None => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not ask Codex to use a reset credit",
        )
            .into_response(),
    }
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
    let mut edit_message_id = None;
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
            "edit_message_id" => {
                if let Ok(text) = field.text().await {
                    edit_message_id = text.trim().parse::<i64>().ok();
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
    if state.agent_jobs.lock().unwrap().contains_key(&slot.id) {
        let db = state.db.lock().unwrap();
        let _ = append_agent_message(
            &db,
            slot.id,
            "assistant",
            &format!(
                "{} is already running. Use Cancel before editing or sending again.",
                slot.name
            ),
            None,
        );
        return Redirect::to(&agent_location(Some(slot.id))).into_response();
    }
    let edit_draft = state
        .agent_edit_drafts
        .lock()
        .unwrap()
        .get(&slot.id)
        .cloned();
    let editing_message_id = edit_message_id.filter(|message_id| {
        edit_draft
            .as_ref()
            .is_some_and(|draft| draft.message_id == *message_id)
    });
    let existing_attachment_id = if let Some(message_id) = editing_message_id {
        let db = state.db.lock().unwrap();
        agent_message_attachment_id(&db, slot.id, message_id).unwrap_or(None)
    } else {
        None
    };
    let attachment_id = if let Some(upload) = upload {
        save_agent_upload(&state, &slot, upload).await.ok()
    } else {
        existing_attachment_id
    };
    if body.is_empty() && attachment_id.is_none() {
        return Redirect::to(&agent_location(Some(slot.id))).into_response();
    }
    let user_message_id = if let Some(message_id) = editing_message_id {
        let db = state.db.lock().unwrap();
        let _ = update_agent_message_for_edit(&db, slot.id, message_id, &body, attachment_id);
        let _ = delete_agent_messages_after(&db, slot.id, message_id);
        state.agent_edit_drafts.lock().unwrap().remove(&slot.id);
        message_id
    } else {
        let db = state.db.lock().unwrap();
        state.agent_edit_drafts.lock().unwrap().remove(&slot.id);
        append_agent_message(&db, slot.id, "user", &body, attachment_id).unwrap_or(0)
    };
    if handle_agent_control(&state, &slot, &body) {
        return Redirect::to(&agent_location(Some(slot.id))).into_response();
    }
    if user_message_id <= 0 {
        let db = state.db.lock().unwrap();
        let _ = append_agent_message(
            &db,
            slot.id,
            "assistant",
            "Could not save the user message before starting Codex.",
            None,
        );
        return Redirect::to(&agent_location(Some(slot.id))).into_response();
    }
    let request_body = if body.is_empty() {
        "Please inspect the attached file.".to_string()
    } else {
        body.clone()
    };
    start_agent_job(
        state.clone(),
        slot.id,
        request_body,
        body,
        attachment_id,
        user_message_id,
    );
    Redirect::to(&agent_location(Some(slot.id))).into_response()
}

async fn agent_cancel(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<i64>,
) -> Response {
    if let Some(response) = raw_guard(&state, &headers) {
        return response;
    }
    Json(AgentCancelPoll {
        stopped: stop_agent_job(&state, id),
    })
    .into_response()
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
    let active_status = {
        let db = state.db.lock().unwrap();
        get_agent_slot(&db, id)
            .unwrap_or(None)
            .map(|slot| agent_slot_runtime(&state, &slot).label)
            .unwrap_or_else(|| "idle".into())
    };
    Json(AgentSlotPoll {
        running: run.is_some(),
        current: run.map(|run| run.current).unwrap_or_default(),
        message_count: messages.len(),
        messages_html: agent_messages_html(&messages),
        active_status,
        edit_draft: state.agent_edit_drafts.lock().unwrap().get(&id).cloned(),
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

fn agent_slot_runtime(state: &AppState, slot: &AgentSlotRow) -> SlotRuntime {
    if let Some(run) = agent_run_for(state, slot.id) {
        let label = if run.current.trim().is_empty() {
            run.status
        } else {
            run.current
        };
        return SlotRuntime { label };
    }
    SlotRuntime {
        label: "idle".into(),
    }
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
                    r#"<p class="message-text">{}</p>"#,
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
    <div class="message-meta"><strong>{}</strong><div class="message-actions"><button type="button" class="ghost message-copy" data-copy-message>Copy</button><span class="message-log">{}</span></div></div>
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

fn codex_browser_drawer_html(
    projects: &[CodexProject],
    conversations: &[CodexConversation],
    slot_id: i64,
    active_thread: Option<&str>,
    loaded: bool,
) -> String {
    let mut groups = Vec::new();
    for project in projects
        .iter()
        .filter(|project| project.conversation_count > 0)
        .take(CODEX_PROJECT_DRAWER_LIMIT)
    {
        let project_conversations = conversations
            .iter()
            .filter(|conversation| conversation.cwd == project.path)
            .take(CODEX_PROJECT_CONVERSATION_LIMIT)
            .collect::<Vec<_>>();
        if project_conversations.is_empty() {
            continue;
        }
        let rows = project_conversations
            .iter()
            .enumerate()
            .map(|(index, conversation)| {
                let active_class = if Some(conversation.id.as_str()) == active_thread {
                    " active"
                } else {
                    ""
                };
                let extra_attr = if index >= CODEX_PROJECT_VISIBLE_CONVERSATIONS {
                    " data-extra-conversation hidden"
                } else {
                    ""
                };
                let title = html_escape(&conversation.title);
                let preview = html_escape(&truncate_text(&conversation.preview, 92));
                let updated = html_escape(&short_time(&conversation.updated_at));
                let workdir = html_escape(&conversation.cwd);
                let thread_id = html_escape(&conversation.id);
                let search_text = html_escape(&format!(
                    "{} {} {}",
                    conversation.title, conversation.preview, conversation.cwd
                ));
                format!(
                    r#"<form class="browser-conversation-row{active_class}" data-conversation-row data-search-text="{search_text}"{extra_attr} action="/agents/slots/{slot_id}/conversation" method="post">
  <input type="hidden" name="thread_id" value="{thread_id}">
  <input type="hidden" name="workdir" value="{workdir}">
  <button type="submit"><strong>{title}</strong><span>{updated} · {} msgs · {preview}</span></button>
</form>"#,
                    conversation.message_count
                )
            })
            .collect::<Vec<_>>()
            .join("");
        let hidden = project_conversations
            .len()
            .saturating_sub(CODEX_PROJECT_VISIBLE_CONVERSATIONS);
        let more = if hidden > 0 {
            format!(
                r#"<button type="button" class="ghost browser-more" data-load-more>Load more ({hidden})</button>"#
            )
        } else {
            String::new()
        };
        let trust = if project.trusted {
            "trusted"
        } else {
            "project"
        };
        let project_path = html_escape(&project.path);
        let project_name = html_escape(&project.name);
        let project_search = html_escape(&format!("{} {}", project.name, project.path));
        groups.push(format!(
            r#"<section class="browser-project" data-project-group data-search-text="{project_search}">
  <div class="browser-project-head" title="{project_path}">
    <strong>{project_name}</strong><span>{} chats · {trust}</span>
  </div>
  <form class="browser-project-start" action="/agents/slots/{slot_id}/project" method="post">
    <input type="hidden" name="workdir" value="{project_path}">
    <button type="submit" class="ghost">New chat in this folder</button>
  </form>
  <div class="browser-conversations">{rows}</div>
  {more}
</section>"#,
            project.conversation_count
        ));
    }
    let body = if !loaded {
        r#"<p class="empty">Loading saved Codex conversations...</p>"#.into()
    } else if groups.is_empty() {
        r#"<p class="empty">No saved Codex conversations found yet.</p>"#.into()
    } else {
        groups.join("")
    };
    format!(
        r#"<dialog class="browser-drawer" id="conversationDrawer">
  <header><div><strong>Conversations</strong><br><span>Projects with saved Codex sessions</span></div><button type="button" class="icon" data-browser-close aria-label="Close">x</button></header>
  <section class="browser-search"><input type="search" data-browser-search placeholder="Search projects or conversations" autocomplete="off" aria-label="Search projects or conversations"></section>
  <main class="browser-scroll">{body}</main>
</dialog>"#
    )
}

fn codex_usage_dialog(config: &Config, usage: Option<&CodexUsageSnapshot>, loaded: bool) -> String {
    let command = html_escape(&agent_command_label(config));
    let reset_available = usage
        .and_then(|usage| usage.reset_credits.as_ref())
        .is_some_and(|credits| credits.available_count > 0);
    let reset = if config.codex_reset_command.is_some() || reset_available {
        r#"<form class="reset-form" action="/agents/codex/reset" method="post" data-reset-form>
  <input type="hidden" name="confirm" value="USE_RESET">
  <button type="submit" class="danger-icon ghost">Use reset</button>
</form>"#
            .to_string()
    } else {
        r#"<button type="button" class="ghost" disabled title="No Codex reset credits are currently reported.">Use reset</button>"#.to_string()
    };
    let body = if let Some(usage) = usage {
        let primary = usage_window_card("Primary", usage.primary.as_ref());
        let secondary = usage_window_card("Secondary", usage.secondary.as_ref());
        let reset_credit_text = codex_reset_credit_text(usage.reset_credits.as_ref());
        let reset_lines = [
            usage_reset_line("Primary", usage.primary.as_ref()),
            usage_reset_line("Secondary", usage.secondary.as_ref()),
        ]
        .join("");
        format!(
            r#"<p class="muted">Launcher: <strong>{command}</strong></p>
<section class="usage-total">
  <strong>Total usage</strong>
  <span>Plan: {}</span>
  <span>Total tokens recorded: {}</span>
  <span>Last turn: {} · cached input: {}</span>
  <span>Context window: {}</span>
  <span>Add-on credits: {}</span>
  <span>Usage reset credits: {reset_credit_text}</span>
</section>
<div class="usage-grid">{primary}{secondary}</div>
<section class="usage-total"><strong>Reset windows</strong>{reset_lines}</section>
<p class="muted">Observed {}</p>
            {reset}"#,
            html_escape(&usage.plan_type),
            format_number(usage.total_units),
            format_number(usage.last_units),
            format_number(usage.cached_input_units),
            format_number(usage.context_window),
            html_escape(usage.credits.as_deref().unwrap_or("not reported")),
            html_escape(&short_time(&usage.observed_at)),
        )
    } else if loaded {
        format!(
            r#"<p class="muted">No Codex usage event has been recorded yet. Open `/status` in Codex once and Plugdeck will show the saved rate-limit data here.</p><p>Launcher: <strong>{command}</strong></p>{reset}"#
        )
    } else {
        format!(
            r#"<p class="muted">Loading Codex usage from saved sessions...</p><p>Launcher: <strong>{command}</strong></p>{reset}"#
        )
    };
    format!(
        r#"<dialog class="codex-panel" id="codexPanel">
  <header><strong>Codex Usage</strong><button type="button" class="icon" data-codex-close aria-label="Close">x</button></header>
  <main>{body}</main>
</dialog>"#
    )
}

fn usage_window_card(fallback_label: &str, window: Option<&CodexRateWindow>) -> String {
    let Some(window) = window else {
        return format!(
            r#"<section class="usage-card"><strong>{fallback_label}</strong><span class="muted">not reported</span></section>"#
        );
    };
    let used = window.used_percent.clamp(0.0, 100.0);
    let remaining = window.remaining_percent.clamp(0.0, 100.0);
    let reset = window
        .resets_at
        .and_then(epoch_to_rfc3339)
        .map(|value| short_time(&value))
        .unwrap_or_else(|| "unknown".into());
    format!(
        r#"<section class="usage-card"><strong>{}</strong><span>{:.0}% remaining · {:.0}% used</span><div class="meter" title="{:.0}% remaining"><span style="width:{:.0}%"></span></div><span class="muted">{} window · resets {}</span></section>"#,
        html_escape(&window.label),
        remaining,
        used,
        remaining,
        remaining,
        html_escape(&usage_window_duration(window.window_minutes)),
        html_escape(&reset)
    )
}

fn usage_reset_line(fallback_label: &str, window: Option<&CodexRateWindow>) -> String {
    let Some(window) = window else {
        return format!(r#"<span>{fallback_label}: not reported</span>"#);
    };
    let reset = window
        .resets_at
        .and_then(epoch_to_rfc3339)
        .map(|value| short_time(&value))
        .unwrap_or_else(|| "unknown".into());
    format!(
        r#"<span>{}: {} window resets {}</span>"#,
        html_escape(&window.label),
        html_escape(&usage_window_duration(window.window_minutes)),
        html_escape(&reset)
    )
}

fn codex_reset_credit_text(credits: Option<&CodexResetCreditsSummary>) -> String {
    let Some(credits) = credits else {
        return "not reported by Codex".into();
    };
    let count = credits.available_count;
    let label = if count == 1 { "credit" } else { "credits" };
    let Some(estimate) = &credits.estimate else {
        return format!("{count} {label} available · local expiry tracking not initialized yet");
    };
    let mut parts = vec![format!("{count} {label} available")];
    if estimate.tracked_available_count > 0 {
        let tracked_label = if estimate.tracked_available_count == 1 {
            "tracked credit"
        } else {
            "tracked credits"
        };
        let mut tracked = format!("{} {tracked_label}", estimate.tracked_available_count);
        if let Some(next_expires_at) = &estimate.next_expires_at {
            tracked.push_str(&format!(" · next expires {}", short_time(next_expires_at)));
        }
        parts.push(tracked);
    }
    if estimate.untracked_available_count > 0 {
        let untracked_label = if estimate.untracked_available_count == 1 {
            "existing credit"
        } else {
            "existing credits"
        };
        parts.push(format!(
            "{} {untracked_label} from before tracking; expiry unknown",
            estimate.untracked_available_count
        ));
    }
    if estimate.tracked_available_count == 0 && estimate.untracked_available_count == 0 {
        parts.push("tracking future grants".into());
    }
    parts.join(" · ")
}

fn usage_window_duration(minutes: i64) -> String {
    if minutes >= 1440 && minutes % 1440 == 0 {
        return format!("{}d", minutes / 1440);
    }
    if minutes >= 60 && minutes % 60 == 0 {
        return format!("{}h", minutes / 60);
    }
    format!("{minutes}m")
}

fn codex_usage_text(usage: Option<&CodexUsageSnapshot>) -> String {
    let Some(usage) = usage else {
        return "Codex usage: no saved `/status` data found yet.".into();
    };
    let mut lines = vec![
        "Codex usage:".to_string(),
        format!("- observed: {}", short_time(&usage.observed_at)),
        format!("- plan: {}", usage.plan_type),
        format!("- total tokens: {}", format_number(usage.total_units)),
        format!("- last turn: {}", format_number(usage.last_units)),
        format!(
            "- cached input: {}",
            format_number(usage.cached_input_units)
        ),
        format!("- context window: {}", format_number(usage.context_window)),
        format!(
            "- add-on credits: {}",
            usage.credits.as_deref().unwrap_or("not reported")
        ),
        format!(
            "- usage reset credits: {}",
            codex_reset_credit_text(usage.reset_credits.as_ref())
        ),
    ];
    if let Some(primary) = &usage.primary {
        lines.push(format!(
            "- primary: {:.0}% left, {:.0}% used, resets {}",
            primary.remaining_percent,
            primary.used_percent,
            primary
                .resets_at
                .and_then(epoch_to_rfc3339)
                .map(|value| short_time(&value))
                .unwrap_or_else(|| "unknown".into())
        ));
    }
    if let Some(secondary) = &usage.secondary {
        lines.push(format!(
            "- secondary: {:.0}% left, {:.0}% used, resets {}",
            secondary.remaining_percent,
            secondary.used_percent,
            secondary
                .resets_at
                .and_then(epoch_to_rfc3339)
                .map(|value| short_time(&value))
                .unwrap_or_else(|| "unknown".into())
        ));
    }
    lines.join("\n")
}

fn codex_transcript_html(index: &CodexIndex, thread_id: &str) -> io::Result<String> {
    let Some(conversation) = codex_conversation_by_id(&index, thread_id) else {
        return Ok(r#"<p class="empty">Conversation not found.</p>"#.into());
    };
    let messages = codex_transcript_messages(&conversation.path)?;
    if messages.is_empty() {
        return Ok(r#"<p class="empty">This Codex conversation has no visible user or assistant messages yet.</p>"#.into());
    }
    Ok(agent_messages_html(&messages))
}

fn codex_transcript_count(html: &str) -> Option<usize> {
    let count = html.matches("<article class=\"message\">").count();
    (count > 0).then_some(count)
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
        for name in DEFAULT_AGENT_SLOTS.split(',') {
            ensure_agent_slot(db, name, default_workdir)?;
        }
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

fn agent_message_attachment_id(
    db: &Connection,
    slot_id: i64,
    message_id: i64,
) -> rusqlite::Result<Option<i64>> {
    db.query_row(
        "SELECT attachment_id FROM agent_messages WHERE id = ?1 AND slot_id = ?2 AND role = 'user'",
        params![message_id, slot_id],
        |row| row.get(0),
    )
    .optional()
    .map(|value| value.flatten())
}

fn update_agent_message_for_edit(
    db: &Connection,
    slot_id: i64,
    message_id: i64,
    body: &str,
    attachment_id: Option<i64>,
) -> rusqlite::Result<()> {
    db.execute(
        "UPDATE agent_messages
            SET body = ?1, attachment_id = ?2, created_at = ?3
          WHERE id = ?4 AND slot_id = ?5 AND role = 'user'",
        params![
            body,
            attachment_id,
            Utc::now().to_rfc3339(),
            message_id,
            slot_id
        ],
    )?;
    Ok(())
}

fn delete_agent_messages_after(
    db: &Connection,
    slot_id: i64,
    message_id: i64,
) -> rusqlite::Result<()> {
    db.execute(
        "DELETE FROM agent_messages WHERE slot_id = ?1 AND id > ?2",
        params![slot_id, message_id],
    )?;
    Ok(())
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
        let runtime = agent_slot_runtime(state, slot);
        let usage = codex_index_snapshot(state).and_then(|index| index.usage);
        append_agent_assistant(
            state,
            slot.id,
            &format!(
                "{} is {}. Folder: `{}`\n{}",
                slot.name,
                runtime.label,
                slot.workdir,
                codex_usage_text(usage.as_ref())
            ),
        );
        return true;
    }
    if lower == "usage" || lower == "limits" {
        let usage = codex_index_snapshot(state).and_then(|index| index.usage);
        append_agent_assistant(state, slot.id, &codex_usage_text(usage.as_ref()));
        return true;
    }
    if lower == "model" || lower == "settings" {
        append_agent_assistant(
            state,
            slot.id,
            &format!("Agent command: `{}`", agent_command_label(&state.config)),
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
        state.agent_edit_drafts.lock().unwrap().remove(&slot.id);
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
            state.agent_edit_drafts.lock().unwrap().remove(&slot.id);
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
            "- `!usage`",
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

fn load_codex_index(config: &Config) -> CodexIndex {
    let thread_names = load_codex_thread_names(&config.codex_home);
    let mut files = collect_codex_session_files(&config.codex_home);
    files.sort_by_key(|path| Reverse(file_modified(path)));
    files.truncate(CODEX_SESSION_SCAN_LIMIT);

    let mut conversations = files
        .iter()
        .filter_map(|path| codex_conversation_from_file(path, &thread_names))
        .collect::<Vec<_>>();
    conversations.sort_by(|left, right| right.updated_at.cmp(&left.updated_at));
    conversations.truncate(MAX_CODEX_CONVERSATIONS);

    let mut projects = configured_codex_projects(&config.codex_home);
    for conversation in &conversations {
        projects
            .entry(conversation.cwd.clone())
            .and_modify(|project| project.conversation_count += 1)
            .or_insert_with(|| CodexProject {
                path: conversation.cwd.clone(),
                name: project_display_name(&conversation.cwd),
                trusted: false,
                conversation_count: 1,
            });
    }
    for project in projects.values_mut() {
        if project.conversation_count == 0 {
            project.conversation_count = conversations
                .iter()
                .filter(|conversation| conversation.cwd == project.path)
                .count();
        }
    }
    let mut projects = projects.into_values().collect::<Vec<_>>();
    projects.sort_by(|left, right| {
        right
            .conversation_count
            .cmp(&left.conversation_count)
            .then_with(|| {
                left.name
                    .to_ascii_lowercase()
                    .cmp(&right.name.to_ascii_lowercase())
            })
    });

    let usage = merge_codex_rate_limit_status(latest_codex_usage(&files), &config);

    CodexIndex {
        usage,
        conversations,
        projects,
    }
}

fn load_codex_thread_names(codex_home: &Path) -> HashMap<String, (String, String)> {
    let path = codex_home.join("session_index.jsonl");
    let Ok(file) = fs::File::open(path) else {
        return HashMap::new();
    };
    let reader = io::BufReader::new(file);
    let mut names = HashMap::new();
    for line in reader.lines().map_while(Result::ok) {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        let Some(id) = value.get("id").and_then(|value| value.as_str()) else {
            continue;
        };
        let title = value
            .get("thread_name")
            .and_then(|value| value.as_str())
            .unwrap_or("Untitled")
            .to_string();
        let updated_at = value
            .get("updated_at")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_string();
        names.insert(id.to_string(), (title, updated_at));
    }
    names
}

fn collect_codex_session_files(codex_home: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_jsonl_files(&codex_home.join("sessions"), 5, &mut files);
    let index = codex_home.join("history.jsonl");
    if index.exists() {
        files.push(index);
    }
    files
}

fn collect_jsonl_files(dir: &Path, depth: usize, files: &mut Vec<PathBuf>) {
    if depth == 0 || dir.to_string_lossy().contains("/.tmp/") {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.is_dir() {
            collect_jsonl_files(&path, depth - 1, files);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("jsonl") {
            files.push(path);
        }
    }
}

fn codex_conversation_from_file(
    path: &Path,
    thread_names: &HashMap<String, (String, String)>,
) -> Option<CodexConversation> {
    if path.file_name().and_then(|name| name.to_str()) == Some("history.jsonl") {
        return None;
    }
    let file = fs::File::open(path).ok()?;
    let reader = io::BufReader::new(file);
    let mut id = None::<String>;
    let mut cwd = None::<String>;
    let mut started_at = None::<String>;
    let mut updated_at = None::<String>;
    let mut first_user = None::<String>;
    let mut last_message = None::<String>;
    let mut message_count = 0usize;

    for line in reader.lines().map_while(Result::ok) {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        if let Some(timestamp) = value.get("timestamp").and_then(|value| value.as_str()) {
            updated_at = Some(timestamp.to_string());
        }
        if value.get("type").and_then(|value| value.as_str()) == Some("session_meta") {
            let payload = value.get("payload").unwrap_or(&serde_json::Value::Null);
            id = payload
                .get("id")
                .and_then(|value| value.as_str())
                .map(str::to_string);
            cwd = payload
                .get("cwd")
                .and_then(|value| value.as_str())
                .map(str::to_string);
            started_at = payload
                .get("timestamp")
                .and_then(|value| value.as_str())
                .map(str::to_string);
            continue;
        }
        let Some((role, text)) = codex_visible_message(&value) else {
            continue;
        };
        if text.trim().is_empty() {
            continue;
        }
        message_count += 1;
        if role == "user" && first_user.is_none() {
            first_user = Some(text.clone());
        }
        last_message = Some(text);
    }

    let id = id?;
    let cwd = cwd.unwrap_or_else(|| default_home_dir().to_string_lossy().into_owned());
    let (indexed_title, indexed_updated) = thread_names
        .get(&id)
        .cloned()
        .unwrap_or_else(|| (String::new(), String::new()));
    let indexed_title = indexed_title.trim();
    let title = if indexed_title.is_empty() || is_codex_synthetic_user_text(indexed_title) {
        first_user
            .as_deref()
            .map(|value| truncate_text(value, 56))
            .unwrap_or_else(|| "Untitled Codex conversation".into())
    } else {
        indexed_title.to_string()
    };
    let updated_at = if !indexed_updated.trim().is_empty() {
        indexed_updated
    } else {
        updated_at
            .or_else(|| started_at.clone())
            .unwrap_or_else(|| system_time_to_rfc3339(file_modified(path)))
    };
    Some(CodexConversation {
        id,
        title,
        cwd,
        updated_at,
        path: path.to_path_buf(),
        preview: first_user.or(last_message).unwrap_or_default(),
        message_count,
    })
}

fn codex_transcript_messages(path: &Path) -> io::Result<Vec<AgentMessageRow>> {
    let file = fs::File::open(path)?;
    let reader = io::BufReader::new(file);
    let mut rows = Vec::new();
    for line in reader.lines().map_while(Result::ok) {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        let timestamp = value
            .get("timestamp")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_string();
        let Some((role, text)) = codex_visible_message(&value) else {
            continue;
        };
        if text.trim().is_empty() {
            continue;
        }
        rows.push(AgentMessageRow {
            role,
            body: text,
            created_at: timestamp,
            attachment: None,
        });
    }
    if rows.len() > MAX_CODEX_TRANSCRIPT_MESSAGES {
        let start = rows.len() - MAX_CODEX_TRANSCRIPT_MESSAGES;
        rows = rows.split_off(start);
    }
    rows.reverse();
    Ok(rows)
}

fn codex_visible_message(value: &serde_json::Value) -> Option<(String, String)> {
    if value.get("type").and_then(|value| value.as_str()) != Some("response_item") {
        return None;
    }
    let payload = value.get("payload")?;
    if payload.get("type").and_then(|value| value.as_str()) != Some("message") {
        return None;
    }
    let role = payload.get("role").and_then(|value| value.as_str())?;
    if !matches!(role, "user" | "assistant") {
        return None;
    }
    let text = codex_content_text(payload.get("content")?);
    if role == "user" && is_codex_synthetic_user_text(&text) {
        return None;
    }
    Some((role.to_string(), text))
}

fn is_codex_synthetic_user_text(text: &str) -> bool {
    let trimmed = text.trim_start();
    trimmed.starts_with("# AGENTS.md instructions for")
        || trimmed.starts_with("<environment_context>")
        || trimmed.starts_with("<INSTRUCTIONS>")
        || trimmed.starts_with("<permissions instructions>")
        || trimmed.starts_with("<collaboration_mode>")
        || trimmed.starts_with("<apps_instructions>")
        || trimmed.starts_with("<skills_instructions>")
        || trimmed.starts_with("<plugins_instructions>")
        || (trimmed.contains("<environment_context>") && trimmed.contains("<cwd>"))
}

fn codex_content_text(content: &serde_json::Value) -> String {
    if let Some(text) = content.as_str() {
        return text.to_string();
    }
    let Some(items) = content.as_array() else {
        return String::new();
    };
    items
        .iter()
        .filter_map(|item| {
            item.get("text")
                .or_else(|| item.get("content"))
                .and_then(|value| value.as_str())
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn latest_codex_usage(files: &[PathBuf]) -> Option<CodexUsageSnapshot> {
    let mut latest = None::<(String, CodexUsageSnapshot)>;
    for path in files.iter().take(CODEX_SESSION_SCAN_LIMIT) {
        let Ok(file) = fs::File::open(path) else {
            continue;
        };
        let reader = io::BufReader::new(file);
        for line in reader.lines().map_while(Result::ok) {
            let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
                continue;
            };
            if value.get("type").and_then(|value| value.as_str()) != Some("event_msg") {
                continue;
            }
            let payload = value.get("payload").unwrap_or(&serde_json::Value::Null);
            if payload.get("type").and_then(|value| value.as_str()) != Some("token_count") {
                continue;
            }
            let observed_at = value
                .get("timestamp")
                .and_then(|value| value.as_str())
                .unwrap_or("")
                .to_string();
            let snapshot = codex_usage_from_payload(&observed_at, payload);
            if latest
                .as_ref()
                .is_none_or(|(timestamp, _)| observed_at.as_str() > timestamp.as_str())
            {
                latest = Some((observed_at, snapshot));
            }
        }
    }
    latest.map(|(_, snapshot)| snapshot)
}

fn merge_codex_rate_limit_status(
    usage: Option<CodexUsageSnapshot>,
    config: &Config,
) -> Option<CodexUsageSnapshot> {
    let Some(result) = fetch_codex_rate_limits(config) else {
        return usage;
    };
    let rate_limits = result
        .get("rateLimits")
        .or_else(|| result.get("rate_limits"))
        .unwrap_or(&serde_json::Value::Null);
    let mut usage = usage.unwrap_or_else(|| CodexUsageSnapshot {
        observed_at: Utc::now().to_rfc3339(),
        plan_type: "unknown".into(),
        total_units: 0,
        last_units: 0,
        cached_input_units: 0,
        context_window: 0,
        primary: None,
        secondary: None,
        credits: None,
        reset_credits: None,
    });
    usage.observed_at = Utc::now().to_rfc3339();
    if let Some(plan_type) = rate_limits
        .get("planType")
        .or_else(|| rate_limits.get("plan_type"))
        .and_then(|value| value.as_str())
    {
        usage.plan_type = plan_type.to_string();
    }
    usage.primary = codex_rate_window("Primary", rate_limits.get("primary")).or(usage.primary);
    usage.secondary =
        codex_rate_window("Secondary", rate_limits.get("secondary")).or(usage.secondary);
    usage.credits = codex_credits_text(rate_limits.get("credits")).or(usage.credits);
    usage.reset_credits = codex_reset_credits_summary(
        result
            .get("rateLimitResetCredits")
            .or_else(|| result.get("rate_limit_reset_credits")),
    )
    .or(usage.reset_credits);
    Some(usage)
}

fn fetch_codex_rate_limits(config: &Config) -> Option<serde_json::Value> {
    let initialize = serde_json::json!({
        "id": 0,
        "method": "initialize",
        "params": {
            "clientInfo": {"name": "plugdeck", "version": env!("CARGO_PKG_VERSION")},
            "capabilities": {"experimentalApi": true}
        }
    });
    let read_limits = serde_json::json!({
        "id": 1,
        "method": "account/rateLimits/read",
        "params": null
    });
    let input = format!("{initialize}\n{{\"method\":\"initialized\"}}\n{read_limits}\n");
    let output = codex_app_server_request(config, &input)?;
    output
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|value| value.get("id").and_then(|value| value.as_i64()) == Some(1))
        .and_then(|value| value.get("result").cloned())
}

fn consume_codex_rate_limit_reset_credit(config: &Config) -> Option<String> {
    let initialize = serde_json::json!({
        "id": 0,
        "method": "initialize",
        "params": {
            "clientInfo": {"name": "plugdeck", "version": env!("CARGO_PKG_VERSION")},
            "capabilities": {"experimentalApi": true}
        }
    });
    let consume = serde_json::json!({
        "id": 1,
        "method": "account/rateLimitResetCredit/consume",
        "params": {"idempotencyKey": Uuid::new_v4().to_string()}
    });
    let input = format!("{initialize}\n{{\"method\":\"initialized\"}}\n{consume}\n");
    let output = codex_app_server_request(config, &input)?;
    output
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|value| value.get("id").and_then(|value| value.as_i64()) == Some(1))
        .and_then(|value| {
            value
                .get("result")
                .and_then(|result| result.get("outcome"))
                .and_then(|outcome| outcome.as_str())
                .map(str::to_string)
        })
}

fn codex_app_server_request(config: &Config, input: &str) -> Option<String> {
    let mut command = StdCommand::new(&config.agent_codex_bin);
    if let Some(path) = agent_command_path(&config.agent_codex_bin) {
        command.env("PATH", path);
    }
    command
        .args(&config.agent_codex_args)
        .arg("app-server")
        .arg("--stdio")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn().ok()?;
    {
        let mut stdin = child.stdin.take()?;
        stdin.write_all(input.as_bytes()).ok()?;
        stdin.flush().ok()?;
        std::thread::sleep(CODEX_APP_SERVER_WRITE_SETTLE);
    }
    let started = Instant::now();
    loop {
        if child.try_wait().ok()?.is_some() {
            break;
        }
        if started.elapsed() >= CODEX_APP_SERVER_TIMEOUT {
            let _ = child.kill();
            break;
        }
        std::thread::sleep(StdDuration::from_millis(100));
    }
    let output = child.wait_with_output().ok()?;
    if !output.status.success() && output.stdout.is_empty() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

fn codex_usage_from_payload(observed_at: &str, payload: &serde_json::Value) -> CodexUsageSnapshot {
    let info = payload.get("info").unwrap_or(&serde_json::Value::Null);
    let rate_limits = payload
        .get("rate_limits")
        .unwrap_or(&serde_json::Value::Null);
    let total = info
        .get("total_token_usage")
        .unwrap_or(&serde_json::Value::Null);
    let last = info
        .get("last_token_usage")
        .unwrap_or(&serde_json::Value::Null);
    CodexUsageSnapshot {
        observed_at: observed_at.to_string(),
        plan_type: rate_limits
            .get("plan_type")
            .and_then(|value| value.as_str())
            .unwrap_or("unknown")
            .to_string(),
        total_units: total
            .get("total_tokens")
            .and_then(|value| value.as_i64())
            .unwrap_or(0),
        last_units: last
            .get("total_tokens")
            .and_then(|value| value.as_i64())
            .unwrap_or(0),
        cached_input_units: total
            .get("cached_input_tokens")
            .and_then(|value| value.as_i64())
            .unwrap_or(0),
        context_window: info
            .get("model_context_window")
            .and_then(|value| value.as_i64())
            .unwrap_or(0),
        primary: codex_rate_window("Primary", rate_limits.get("primary")),
        secondary: codex_rate_window("Secondary", rate_limits.get("secondary")),
        credits: codex_credits_text(rate_limits.get("credits")),
        reset_credits: codex_reset_credits_summary(
            rate_limits
                .get("rate_limit_reset_credits")
                .or_else(|| rate_limits.get("rateLimitResetCredits"))
                .or_else(|| payload.get("rate_limit_reset_credits"))
                .or_else(|| payload.get("rateLimitResetCredits")),
        ),
    }
}

fn codex_rate_window(label: &str, value: Option<&serde_json::Value>) -> Option<CodexRateWindow> {
    let value = value?;
    let used = value
        .get("used_percent")
        .or_else(|| value.get("usedPercent"))
        .and_then(|value| value.as_f64())
        .unwrap_or(0.0);
    Some(CodexRateWindow {
        label: label.into(),
        used_percent: used,
        remaining_percent: (100.0 - used).max(0.0),
        window_minutes: value
            .get("window_minutes")
            .or_else(|| value.get("windowDurationMins"))
            .and_then(|value| value.as_i64())
            .unwrap_or(0),
        resets_at: value
            .get("resets_at")
            .or_else(|| value.get("resetsAt"))
            .and_then(|value| value.as_i64()),
    })
}

fn codex_credits_text(value: Option<&serde_json::Value>) -> Option<String> {
    let value = value?;
    if value.is_null() {
        None
    } else if let Some(text) = value.as_str() {
        Some(text.to_string())
    } else if let Some(balance) = value.get("balance").and_then(|value| value.as_str()) {
        let unlimited = value
            .get("unlimited")
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        if unlimited {
            Some("unlimited".into())
        } else {
            Some(balance.to_string())
        }
    } else {
        Some(value.to_string())
    }
}

fn codex_reset_credits_summary(
    value: Option<&serde_json::Value>,
) -> Option<CodexResetCreditsSummary> {
    let value = value?;
    if value.is_null() {
        return None;
    }
    let available_count = value
        .get("available_count")
        .or_else(|| value.get("availableCount"))
        .and_then(|value| value.as_i64())?;
    Some(CodexResetCreditsSummary {
        available_count,
        estimate: None,
    })
}

fn configured_codex_projects(codex_home: &Path) -> HashMap<String, CodexProject> {
    let mut projects = HashMap::new();
    let Ok(raw) = fs::read_to_string(codex_home.join("config.toml")) else {
        return projects;
    };
    let Ok(value) = toml::from_str::<toml::Value>(&raw) else {
        return projects;
    };
    let Some(table) = value.get("projects").and_then(|value| value.as_table()) else {
        return projects;
    };
    for (path, details) in table {
        let trusted = details
            .get("trust_level")
            .and_then(|value| value.as_str())
            .is_some_and(|value| value.eq_ignore_ascii_case("trusted"));
        projects.insert(
            path.to_string(),
            CodexProject {
                path: path.to_string(),
                name: project_display_name(path),
                trusted,
                conversation_count: 0,
            },
        );
    }
    projects
}

fn codex_conversation_by_id<'a>(
    index: &'a CodexIndex,
    thread_id: &str,
) -> Option<&'a CodexConversation> {
    index
        .conversations
        .iter()
        .find(|conversation| conversation.id == thread_id)
}

fn mbx_cmd(args: &[String]) -> io::Result<()> {
    let command = args.first().map(String::as_str).unwrap_or("");
    match command {
        "" | "-h" | "--help" | "help" | "commands" => {
            print!("{}", mbx_usage());
            Ok(())
        }
        "slots" | "sessions" | "status" => mbx_status(args.get(1).map(String::as_str)),
        "list" | "ls" => mbx_list_sessions(),
        "stop" => {
            let Some(slot) = args.get(1) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "usage: plugdeck mbx stop <slot|all>",
                ));
            };
            mbx_stop(slot)
        }
        "start" | "s" | "new" | "n" | "resume" | "r" => {
            let Some(slot_name) = args.get(1) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("usage: plugdeck mbx {command} <slot>"),
                ));
            };
            let action = match command {
                "new" | "n" => MbxAction::New,
                "resume" | "r" => MbxAction::Resume,
                _ => MbxAction::Start,
            };
            let options = mbx_parse_run_options(action, &args[2..])?;
            mbx_run_slot(action, slot_name, options)
        }
        slot_name if !normalize_agent_slot_name(slot_name).is_empty() => {
            let options = mbx_parse_run_options(MbxAction::Resume, &args[1..])?;
            mbx_run_slot(MbxAction::Resume, slot_name, options)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unknown mbx command; run `plugdeck mbx help`",
        )),
    }
}

fn mbx_usage() -> &'static str {
    r#"Usage:
  mbx r <slot> [prompt...]
  mbx s <slot> [prompt...]
  mbx n <slot> [prompt...]
  mbx stop <slot|all>
  mbx slots [slot]
  mbx list

Shortcuts:
  mbx a          same as mbx r a
  mbx r a        resume slot a's saved /agents thread when present
  mbx s b        start Codex in slot b's /agents folder
  mbx n c        restart slot c's tmux session fresh

Options:
  -C, --cd <dir>     Override the slot folder.
  --unsafe           Add Codex's bypass approvals/sandbox flag.
  --safe             Remove Codex's bypass approvals/sandbox flag.
  --restart          Replace an existing tmux session.
  --no-attach        Start or send without attaching.
  --dry-run          Print what would run.
"#
}

fn mbx_parse_run_options(action: MbxAction, args: &[String]) -> io::Result<MbxRunOptions> {
    let mut options = MbxRunOptions {
        workdir: None,
        prompt: Vec::new(),
        attach: true,
        restart: action == MbxAction::New,
        dry_run: false,
        unsafe_mode: env_flag("PLUGDECK_MBX_UNSAFE", false),
        safe_mode: false,
    };
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "-h" | "--help" => {
                print!("{}", mbx_usage());
                std::process::exit(0);
            }
            "-C" | "--cd" | "--dir" => {
                let Some(path) = args.get(index + 1) else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("{} requires a directory", args[index]),
                    ));
                };
                options.workdir = Some(expand_local_path(path));
                index += 2;
            }
            "--safe" => {
                options.unsafe_mode = false;
                options.safe_mode = true;
                index += 1;
            }
            "--unsafe" => {
                options.unsafe_mode = true;
                options.safe_mode = false;
                index += 1;
            }
            "--restart" => {
                options.restart = true;
                index += 1;
            }
            "--no-attach" => {
                options.attach = false;
                index += 1;
            }
            "--dry-run" => {
                options.dry_run = true;
                index += 1;
            }
            "--" => {
                options.prompt.extend(args[index + 1..].iter().cloned());
                break;
            }
            value if value.starts_with('-') => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown mbx option: {value}"),
                ));
            }
            value => {
                let candidate = expand_local_path(value);
                if options.workdir.is_none() && candidate.is_dir() {
                    options.workdir = Some(candidate);
                } else {
                    options.prompt.push(value.to_string());
                }
                index += 1;
            }
        }
    }
    Ok(options)
}

fn mbx_run_slot(action: MbxAction, slot_name: &str, options: MbxRunOptions) -> io::Result<()> {
    mbx_need_tmux()?;
    let slot = mbx_find_slot(slot_name)?;
    let workdir = mbx_resolve_workdir(options.workdir, &slot.workdir)?;
    let session = mbx_session_name(&slot.name);
    let codex_bin = env::var("PLUGDECK_AGENT_CODEX_BIN").unwrap_or_else(|_| default_codex_bin());
    let mut codex_args = env::var("PLUGDECK_AGENT_CODEX_ARGS")
        .ok()
        .map(|value| split_env_args(&value))
        .unwrap_or_else(default_codex_args);
    if options.safe_mode {
        codex_args.retain(|arg| arg != CODEX_UNSAFE_ARG);
    }
    let codex_words = mbx_codex_words(
        action,
        &slot,
        &workdir,
        &options.prompt,
        &codex_bin,
        &codex_args,
        options.unsafe_mode,
    );
    let cmdline = mbx_shell_join(&codex_words);
    let resumes_saved = action == MbxAction::Resume && slot.thread_id.is_some();

    if options.dry_run {
        println!("slot:    {}", slot.name);
        println!("session: {session}");
        println!("workdir: {}", workdir.display());
        println!("thread:  {}", if resumes_saved { "saved" } else { "fresh" });
        println!("command: {cmdline}");
        return Ok(());
    }

    if action == MbxAction::Resume && slot.thread_id.is_none() {
        eprintln!(
            "mbx: slot {} has no saved /agents thread yet; starting a fresh Codex session",
            slot.name
        );
    }

    if mbx_has_session(&session) {
        if action == MbxAction::New || options.restart {
            mbx_kill_session(&session)?;
        } else {
            if mbx_session_is_idle_shell(&session) {
                mbx_send_keys(&session, &cmdline)?;
            }
            if options.attach {
                return mbx_attach_session(&session);
            }
            println!("Sent to {} ({session})", slot.name);
            return Ok(());
        }
    }

    mbx_new_session(&session, &workdir)?;
    mbx_send_keys(&session, &cmdline)?;
    if options.attach {
        mbx_attach_session(&session)?;
    } else {
        println!("Started {} ({session})", slot.name);
    }
    Ok(())
}

fn mbx_find_slot(raw_name: &str) -> io::Result<MbxSlot> {
    let name = normalize_agent_slot_name(raw_name);
    if name.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid slot name: {raw_name}"),
        ));
    }
    let slots = mbx_load_slots()?;
    slots
        .iter()
        .find(|slot| slot.name.eq_ignore_ascii_case(&name))
        .cloned()
        .ok_or_else(|| {
            let names = slots
                .iter()
                .map(|slot| slot.name.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("unknown /agents slot `{name}`; available: {names}"),
            )
        })
}

fn mbx_load_slots() -> io::Result<Vec<MbxSlot>> {
    let db_path = mbx_db_path();
    let mut slots = if db_path.exists() {
        let db = Connection::open(&db_path).map_err(io_other)?;
        let mut stmt = db
            .prepare(
                "SELECT s.id, s.name, s.workdir, sessions.thread_id
                 FROM agent_slots s
                 LEFT JOIN agent_sessions sessions ON sessions.slot_id = s.id
                 ORDER BY s.id ASC",
            )
            .map_err(io_other)?;
        stmt.query_map([], |row| {
            Ok(MbxSlot {
                id: Some(row.get(0)?),
                name: row.get(1)?,
                workdir: row.get(2)?,
                thread_id: row.get(3)?,
            })
        })
        .map_err(io_other)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(io_other)?
    } else {
        Vec::new()
    };
    if slots.is_empty() {
        slots = mbx_default_slots();
    }
    mbx_append_legacy_slots(&mut slots);
    Ok(slots)
}

fn mbx_default_slots() -> Vec<MbxSlot> {
    parse_agent_slot_seeds(
        env::var("PLUGDECK_AGENT_SLOTS").ok(),
        &mbx_default_workdir(),
    )
    .into_iter()
    .map(|seed| MbxSlot {
        id: None,
        name: seed.name,
        workdir: seed.workdir.to_string_lossy().into_owned(),
        thread_id: None,
    })
    .collect()
}

fn mbx_append_legacy_slots(slots: &mut Vec<MbxSlot>) {
    let default_workdir = mbx_legacy_workdir(slots);
    let seeds = parse_agent_slot_seeds(
        Some(
            env::var("PLUGDECK_MBX_LEGACY_SLOTS")
                .unwrap_or_else(|_| DEFAULT_MBX_LEGACY_SLOTS.into()),
        ),
        &default_workdir,
    );
    for seed in seeds {
        if slots
            .iter()
            .any(|slot| slot.name.eq_ignore_ascii_case(&seed.name))
        {
            continue;
        }
        slots.push(MbxSlot {
            id: None,
            name: seed.name,
            workdir: seed.workdir.to_string_lossy().into_owned(),
            thread_id: None,
        });
    }
}

fn mbx_legacy_workdir(slots: &[MbxSlot]) -> PathBuf {
    if let Ok(value) = env::var("PLUGDECK_AGENT_DEFAULT_WORKDIR") {
        return expand_local_path(&value);
    }
    slots
        .first()
        .map(|slot| expand_local_path(&slot.workdir))
        .filter(|path| path.is_dir())
        .unwrap_or_else(default_home_dir)
}

fn mbx_default_workdir() -> PathBuf {
    env::var("PLUGDECK_AGENT_DEFAULT_WORKDIR")
        .map(|value| expand_local_path(&value))
        .unwrap_or_else(|_| default_home_dir())
}

fn mbx_db_path() -> PathBuf {
    env::var("PLUGDECK_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("data/plugdeck.sqlite"))
}

fn mbx_resolve_workdir(override_path: Option<PathBuf>, slot_workdir: &str) -> io::Result<PathBuf> {
    let path = override_path.unwrap_or_else(|| expand_local_path(slot_workdir));
    if !path.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("slot folder does not exist: {}", path.display()),
        ));
    }
    path.canonicalize()
}

fn mbx_codex_words(
    action: MbxAction,
    slot: &MbxSlot,
    workdir: &Path,
    prompt: &[String],
    codex_bin: &str,
    codex_args: &[String],
    unsafe_mode: bool,
) -> Vec<String> {
    let mut words = vec![codex_bin.to_string()];
    if unsafe_mode && !codex_args.iter().any(|arg| arg == CODEX_UNSAFE_ARG) {
        words.push(CODEX_UNSAFE_ARG.into());
    }
    words.extend(codex_args.iter().cloned());
    words.push("--cd".into());
    words.push(workdir.to_string_lossy().into_owned());
    if action == MbxAction::Resume
        && let Some(thread_id) = &slot.thread_id
    {
        words.push("resume".into());
        words.push(thread_id.clone());
    }
    if !prompt.is_empty() {
        words.push(prompt.join(" "));
    }
    words
}

fn mbx_status(requested: Option<&str>) -> io::Result<()> {
    let mut slots = mbx_load_slots()?;
    if let Some(name) = requested {
        let normalized = normalize_agent_slot_name(name);
        slots.retain(|slot| slot.name.eq_ignore_ascii_case(&normalized));
    }
    if slots.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no matching /agents slots",
        ));
    }
    println!(
        "{:<6} {:<5} {:<10} {:<13} {:<14} path",
        "slot", "id", "thread", "tmux", "session"
    );
    for slot in slots {
        let session = mbx_session_name(&slot.name);
        let tmux = mbx_tmux_state(&session).unwrap_or_else(|| "available".into());
        println!(
            "{:<6} {:<5} {:<10} {:<13} {:<14} {}",
            slot.name,
            slot.id
                .map(|id| id.to_string())
                .unwrap_or_else(|| "-".into()),
            if slot.thread_id.is_some() {
                "saved"
            } else {
                "-"
            },
            tmux,
            session,
            slot.workdir
        );
    }
    Ok(())
}

fn mbx_list_sessions() -> io::Result<()> {
    mbx_need_tmux()?;
    let prefix = mbx_session_prefix();
    let output = StdCommand::new("tmux")
        .args(["list-sessions", "-F", "#{session_name}|#{session_attached}"])
        .output();
    let Ok(output) = output else {
        println!("No mbx sessions are running.");
        return Ok(());
    };
    let lines = String::from_utf8_lossy(&output.stdout);
    let mut found = false;
    for line in lines.lines() {
        let Some((session, attached)) = line.split_once('|') else {
            continue;
        };
        if !session.starts_with(&format!("{prefix}-")) {
            continue;
        }
        found = true;
        let state = if attached == "1" {
            "attached"
        } else {
            "detached"
        };
        println!("{session}\t{state}");
    }
    if !found {
        println!("No mbx sessions are running.");
    }
    Ok(())
}

fn mbx_stop(slot_name: &str) -> io::Result<()> {
    mbx_need_tmux()?;
    if slot_name == "all" {
        let prefix = mbx_session_prefix();
        let output = StdCommand::new("tmux")
            .args(["list-sessions", "-F", "#{session_name}"])
            .output();
        let Ok(output) = output else {
            println!("No mbx sessions are running.");
            return Ok(());
        };
        let mut found = false;
        for session in String::from_utf8_lossy(&output.stdout).lines() {
            if session.starts_with(&format!("{prefix}-")) {
                mbx_kill_session(session)?;
                println!("Stopped {session}");
                found = true;
            }
        }
        if !found {
            println!("No mbx sessions are running.");
        }
        return Ok(());
    }
    let slot = mbx_find_slot(slot_name)?;
    let session = mbx_session_name(&slot.name);
    if mbx_has_session(&session) {
        mbx_kill_session(&session)?;
        println!("Stopped {} ({session})", slot.name);
    } else {
        println!("{} is not running.", slot.name);
    }
    Ok(())
}

fn mbx_need_tmux() -> io::Result<()> {
    let status = StdCommand::new("tmux")
        .arg("-V")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match status {
        Ok(status) if status.success() => Ok(()),
        _ => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "tmux is not installed or not on PATH",
        )),
    }
}

fn mbx_session_name(slot_name: &str) -> String {
    format!("{}-{}", mbx_session_prefix(), slot_name)
}

fn mbx_session_prefix() -> String {
    env::var("PLUGDECK_MBX_SESSION_PREFIX").unwrap_or_else(|_| "plugdeck".into())
}

fn mbx_has_session(session: &str) -> bool {
    matches!(
        StdCommand::new("tmux")
            .args(["has-session", "-t", session])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status(),
        Ok(status) if status.success()
    )
}

fn mbx_new_session(session: &str, workdir: &Path) -> io::Result<()> {
    let status = StdCommand::new("tmux")
        .args(["new-session", "-d", "-s", session, "-n", session, "-c"])
        .arg(workdir)
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "could not create tmux session {session}"
        )));
    }
    let _ = StdCommand::new("tmux")
        .args(["set-option", "-t", session, "remain-on-exit", "on"])
        .status();
    Ok(())
}

fn mbx_kill_session(session: &str) -> io::Result<()> {
    let status = StdCommand::new("tmux")
        .args(["kill-session", "-t", session])
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "could not stop tmux session {session}"
        )))
    }
}

fn mbx_send_keys(session: &str, cmdline: &str) -> io::Result<()> {
    let status = StdCommand::new("tmux")
        .args(["send-keys", "-t", session])
        .arg(cmdline)
        .arg("C-m")
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "could not send command to tmux session {session}"
        )))
    }
}

fn mbx_attach_session(session: &str) -> io::Result<()> {
    let mut command = StdCommand::new("tmux");
    if env::var_os("TMUX").is_some() {
        command.args(["switch-client", "-t", session]);
    } else {
        command.args(["attach-session", "-t", session]);
    }
    let status = command.status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "could not attach tmux session {session}"
        )))
    }
}

fn mbx_session_is_idle_shell(session: &str) -> bool {
    let Some(command) = mbx_pane_current_command(session) else {
        return false;
    };
    matches!(command.as_str(), "bash" | "zsh" | "fish" | "sh")
}

fn mbx_tmux_state(session: &str) -> Option<String> {
    if !mbx_has_session(session) {
        return None;
    }
    let attached = mbx_tmux_format(session, "#{session_attached}")?;
    Some(if attached.trim() == "1" {
        "attached".into()
    } else {
        "detached".into()
    })
}

fn mbx_pane_current_command(session: &str) -> Option<String> {
    mbx_tmux_format(session, "#{pane_current_command}")
}

fn mbx_tmux_format(session: &str, format: &str) -> Option<String> {
    let output = StdCommand::new("tmux")
        .args(["display-message", "-p", "-t", session, format])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn mbx_shell_join(words: &[String]) -> String {
    words
        .iter()
        .map(|word| mbx_shell_quote(word))
        .collect::<Vec<_>>()
        .join(" ")
}

fn mbx_shell_quote(value: &str) -> String {
    if !value.is_empty()
        && value.chars().all(|ch| {
            ch.is_ascii_alphanumeric()
                || matches!(ch, '/' | '.' | '_' | '-' | ':' | '=' | ',' | '@' | '%')
        })
    {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn start_agent_job(
    state: Arc<AppState>,
    slot_id: i64,
    request_body: String,
    draft_body: String,
    attachment_id: Option<i64>,
    user_message_id: i64,
) {
    state.agent_jobs.lock().unwrap().insert(
        slot_id,
        AgentRun {
            status: "starting".into(),
            current: "starting".into(),
            started_at: Utc::now().to_rfc3339(),
        },
    );
    tokio::spawn(run_agent_job(
        state,
        slot_id,
        request_body,
        draft_body,
        attachment_id,
        user_message_id,
    ));
}

async fn run_agent_job(
    state: Arc<AppState>,
    slot_id: i64,
    request_body: String,
    draft_body: String,
    attachment_id: Option<i64>,
    user_message_id: i64,
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
    if let Some(path) = agent_command_path(&state.config.agent_codex_bin) {
        command.env("PATH", path);
    }
    command.args(&state.config.agent_codex_args);
    command.arg("exec");
    if use_resume {
        command.arg("resume").arg("--json");
    } else {
        command.arg("--json");
    }
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
        if !use_resume {
            let db = state.db.lock().unwrap();
            let _ = db.execute(
                "DELETE FROM agent_sessions WHERE slot_id = ?1",
                params![slot_id],
            );
        }
        state.agent_edit_drafts.lock().unwrap().insert(
            slot_id,
            AgentEditDraft {
                message_id: user_message_id,
                body: draft_body,
            },
        );
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
            state.agent_edit_drafts.lock().unwrap().remove(&slot_id);
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
            state.agent_edit_drafts.lock().unwrap().remove(&slot_id);
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
            state.agent_edit_drafts.lock().unwrap().remove(&slot_id);
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

fn default_codex_bin() -> String {
    if let Some(path) = command_path("codex") {
        path.to_string_lossy().into_owned()
    } else {
        let user_bin = default_home_dir().join(".local/bin/codex");
        if user_bin.is_file() {
            user_bin.to_string_lossy().into_owned()
        } else {
            "codex".into()
        }
    }
}

fn default_codex_args() -> Vec<String> {
    split_env_args(DEFAULT_AGENT_CODEX_ARGS)
}

fn command_path(command: &str) -> Option<PathBuf> {
    if command.contains('/') {
        let path = PathBuf::from(command);
        return path.is_file().then_some(path);
    }
    env::var_os("PATH").and_then(|paths| {
        env::split_paths(&paths)
            .map(|path| path.join(command))
            .find(|path| path.is_file())
    })
}

fn agent_command_path(command: &str) -> Option<String> {
    let command_path = command_path(command)?;
    let mut paths = Vec::<PathBuf>::new();
    if let Some(parent) = command_path.parent() {
        paths.push(parent.to_path_buf());
    }
    let mut current = command_path.clone();
    for _ in 0..8 {
        let Ok(target) = fs::read_link(&current) else {
            break;
        };
        current = if target.is_absolute() {
            target
        } else {
            current.parent().unwrap_or(Path::new(".")).join(target)
        };
        if let Some(parent) = current.parent() {
            paths.push(parent.to_path_buf());
        }
    }
    if let Ok(canonical) = current.canonicalize() {
        if let Some(parent) = canonical.parent() {
            paths.push(parent.to_path_buf());
        }
    }
    if let Some(existing) = env::var_os("PATH") {
        paths.extend(env::split_paths(&existing));
    }
    env::join_paths(paths)
        .ok()
        .map(|value| value.to_string_lossy().into_owned())
}

fn agent_command_label(config: &Config) -> String {
    let mut parts = vec![config.agent_codex_bin.clone()];
    parts.extend(config.agent_codex_args.iter().cloned());
    parts.join(" ")
}

fn split_env_args(value: &str) -> Vec<String> {
    value
        .split_whitespace()
        .filter(|part| !part.trim().is_empty())
        .map(str::to_string)
        .collect()
}

fn parse_agent_slot_seeds(raw: Option<String>, default_workdir: &Path) -> Vec<AgentSlotSeed> {
    let raw = raw.unwrap_or_else(|| DEFAULT_AGENT_SLOTS.into());
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

fn project_display_name(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return "/".into();
    }
    Path::new(trimmed)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or(trimmed)
        .to_string()
}

fn url_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn file_modified(path: &Path) -> SystemTime {
    fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .unwrap_or(std::time::UNIX_EPOCH)
}

fn system_time_to_rfc3339(value: SystemTime) -> String {
    DateTime::<Utc>::from(value).to_rfc3339()
}

fn epoch_to_rfc3339(epoch: i64) -> Option<String> {
    DateTime::<Utc>::from_timestamp(epoch, 0).map(|value| value.to_rfc3339())
}

fn short_time(value: &str) -> String {
    let Ok(parsed) = DateTime::parse_from_rfc3339(value) else {
        return if value.trim().is_empty() {
            "unknown".into()
        } else {
            value.to_string()
        };
    };
    let dt = parsed.with_timezone(&Utc);
    let now = Utc::now();
    let delta = dt - now;
    let past = now - dt;
    if delta.num_minutes() > 0 {
        return format_duration(delta.num_seconds(), "in ");
    }
    if past.num_minutes() < 1 {
        return "just now".into();
    }
    if past.num_days() < 2 {
        return format_duration(past.num_seconds(), "") + " ago";
    }
    dt.format("%b %-d %H:%M").to_string()
}

fn format_duration(seconds: i64, prefix: &str) -> String {
    let seconds = seconds.max(0);
    let minutes = seconds / 60;
    if minutes < 60 {
        return format!("{prefix}{minutes}m");
    }
    let hours = minutes / 60;
    if hours < 48 {
        return format!("{prefix}{hours}h");
    }
    format!("{prefix}{}d", hours / 24)
}

fn format_number(value: i64) -> String {
    let mut digits = value.abs().to_string();
    let mut out = String::new();
    while digits.len() > 3 {
        let tail = digits.split_off(digits.len() - 3);
        if out.is_empty() {
            out = tail;
        } else {
            out = format!("{tail},{out}");
        }
    }
    if out.is_empty() {
        out = digits;
    } else {
        out = format!("{digits},{out}");
    }
    if value < 0 { format!("-{out}") } else { out }
}

fn truncate_text(value: &str, max_chars: usize) -> String {
    let value = value.trim();
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let keep = max_chars.saturating_sub(20);
    value.chars().take(keep).collect::<String>() + "\n...[truncated]"
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
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, viewport-fit=cover, interactive-widget=resizes-content">
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
            codex_home: PathBuf::new(),
            codex_reset_command: None,
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

    #[test]
    fn codex_conversation_parser_uses_index_title_and_visible_messages() {
        let dir = env::temp_dir().join(format!("plugdeck-test-{}", Uuid::new_v4().simple()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rollout-2026-06-23T09-24-22-thread-1.jsonl");
        fs::write(
            &path,
            r#"{"timestamp":"2026-06-23T07:24:22Z","type":"session_meta","payload":{"id":"thread-1","cwd":"/work/app","timestamp":"2026-06-23T07:24:22Z"}}
{"timestamp":"2026-06-23T07:24:23Z","type":"response_item","payload":{"type":"message","role":"developer","content":[{"type":"input_text","text":"secret instructions"}]}}
{"timestamp":"2026-06-23T07:24:24Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"load this project"}]}}
{"timestamp":"2026-06-23T07:24:25Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"done"}]}}
"#,
        )
        .unwrap();
        let mut names = HashMap::new();
        names.insert(
            "thread-1".into(),
            ("Indexed title".into(), "2026-06-23T07:30:00Z".into()),
        );
        let conversation = codex_conversation_from_file(&path, &names).unwrap();
        assert_eq!(conversation.title, "Indexed title");
        assert_eq!(conversation.cwd, "/work/app");
        assert_eq!(conversation.message_count, 2);
        assert_eq!(conversation.preview, "load this project");

        let messages = codex_transcript_messages(&path).unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].role, "assistant");
        assert_eq!(messages[1].role, "user");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn codex_conversation_parser_filters_synthetic_codex_context() {
        let dir = env::temp_dir().join(format!("plugdeck-test-{}", Uuid::new_v4().simple()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rollout-2026-06-23T09-24-22-thread-2.jsonl");
        fs::write(
            &path,
            r##"{"timestamp":"2026-06-23T07:24:22Z","type":"session_meta","payload":{"id":"thread-2","cwd":"/work/app","timestamp":"2026-06-23T07:24:22Z"}}
{"timestamp":"2026-06-23T07:24:23Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"# AGENTS.md instructions for /work/app"}]}}
{"timestamp":"2026-06-23T07:24:24Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"fix plugdeck loading"}]}}
{"timestamp":"2026-06-23T07:24:25Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"done"}]}}
"##,
        )
        .unwrap();
        let mut names = HashMap::new();
        names.insert(
            "thread-2".into(),
            (
                "# AGENTS.md instructions for /work/app".into(),
                "2026-06-23T07:30:00Z".into(),
            ),
        );
        let conversation = codex_conversation_from_file(&path, &names).unwrap();
        assert_eq!(conversation.title, "fix plugdeck loading");
        assert_eq!(conversation.preview, "fix plugdeck loading");
        assert_eq!(conversation.message_count, 2);

        let messages = codex_transcript_messages(&path).unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].role, "assistant");
        assert_eq!(messages[1].role, "user");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn codex_browser_drawer_includes_project_start_action() {
        let projects = vec![CodexProject {
            path: "/work/app".into(),
            name: "app".into(),
            trusted: true,
            conversation_count: 1,
        }];
        let conversations = vec![CodexConversation {
            id: "thread-1".into(),
            title: "Existing chat".into(),
            cwd: "/work/app".into(),
            updated_at: "2026-06-23T07:30:00Z".into(),
            path: PathBuf::from("/tmp/thread-1.jsonl"),
            preview: "continue work".into(),
            message_count: 2,
        }];

        let html = codex_browser_drawer_html(&projects, &conversations, 7, None, true);

        assert!(html.contains(r#"action="/agents/slots/7/project""#));
        assert!(html.contains(r#"name="workdir" value="/work/app""#));
        assert!(html.contains(">New chat in this folder</button>"));
        assert!(html.contains(r#"action="/agents/slots/7/conversation""#));
        assert!(html.contains(r#"data-browser-search"#));
        assert!(html.contains(
            r#"data-conversation-row data-search-text="Existing chat continue work /work/app""#
        ));
    }

    #[tokio::test]
    async fn agents_page_defaults_to_live_messages_with_saved_thread() {
        let dir = env::temp_dir().join(format!("plugdeck-test-{}", Uuid::new_v4().simple()));
        fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("plugdeck.sqlite");
        let conn = open_db(&db_path).unwrap();
        let slot_id = ensure_agent_slot(&conn, "codex", Path::new("/work/app")).unwrap();
        append_agent_message(&conn, slot_id, "user", "live request", None).unwrap();
        set_agent_session(&conn, slot_id, "thread-1", "/work/app").unwrap();
        let transcript_path = dir.join("thread-1.jsonl");
        fs::write(
            &transcript_path,
            r#"{"timestamp":"2026-06-23T07:24:22Z","type":"session_meta","payload":{"id":"thread-1","cwd":"/work/app","timestamp":"2026-06-23T07:24:22Z"}}
{"timestamp":"2026-06-23T07:24:23Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"old transcript output"}]}}
"#,
        )
        .unwrap();
        let mut cache = CodexIndexCache::default();
        cache.snapshot = Some(CodexIndex {
            conversations: vec![CodexConversation {
                id: "thread-1".into(),
                title: "Saved thread".into(),
                cwd: "/work/app".into(),
                updated_at: "2026-06-23T07:24:23Z".into(),
                path: transcript_path,
                preview: "old transcript output".into(),
                message_count: 1,
            }],
            projects: Vec::new(),
            usage: None,
        });
        cache.refreshed_at = Some(Instant::now());
        let state = Arc::new(AppState {
            db: Mutex::new(conn),
            config: Config {
                bind: "127.0.0.1:0".into(),
                db_path,
                download_dir: dir.join("downloads"),
                agent_default_workdir: PathBuf::from("/work/app"),
                agent_upload_dir: dir.join("agent-uploads"),
                agent_codex_bin: "codex".into(),
                agent_codex_args: Vec::new(),
                codex_home: dir.join("codex-home"),
                codex_reset_command: None,
                agent_slots: Vec::new(),
                ytdlp: "yt-dlp".into(),
                js_runtime: None,
                max_active: 1,
                job_ttl: Duration::hours(24),
                user: "plugdeck".into(),
                password_hash: None,
                cookie_secret: vec![2u8; 32],
                auth_disabled: true,
                links: Vec::new(),
            },
            jobs: Mutex::new(HashMap::new()),
            download_slots: Semaphore::new(1),
            agent_jobs: Mutex::new(HashMap::new()),
            agent_cancels: Mutex::new(HashMap::new()),
            agent_edit_drafts: Mutex::new(HashMap::new()),
            codex_index: Mutex::new(cache),
        });

        let response = agents_page(
            State(state),
            Query(AgentsQuery {
                slot: Some(slot_id),
                thread: None,
            }),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();

        assert!(body.contains("live request"));
        assert!(!body.contains("old transcript output"));
        assert!(body.contains("const viewingTranscript = false;"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn agent_command_path_includes_symlink_target_parent() {
        let dir = env::temp_dir().join(format!("plugdeck-test-{}", Uuid::new_v4().simple()));
        let local_bin = dir.join("local/bin");
        let node_bin = dir.join("nvm/bin");
        let codex_lib_bin = dir.join("nvm/lib/node_modules/@openai/codex/bin");
        fs::create_dir_all(&local_bin).unwrap();
        fs::create_dir_all(&node_bin).unwrap();
        fs::create_dir_all(&codex_lib_bin).unwrap();
        fs::write(codex_lib_bin.join("codex.js"), "#!/usr/bin/env node\n").unwrap();
        std::os::unix::fs::symlink(node_bin.join("codex"), local_bin.join("codex")).unwrap();
        std::os::unix::fs::symlink(
            "../lib/node_modules/@openai/codex/bin/codex.js",
            node_bin.join("codex"),
        )
        .unwrap();

        let path = agent_command_path(&local_bin.join("codex").to_string_lossy()).unwrap();

        assert!(path.contains(&node_bin.to_string_lossy().to_string()));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn mbx_resume_uses_saved_agent_thread() {
        let slot = MbxSlot {
            id: Some(1),
            name: "a".into(),
            workdir: "/work".into(),
            thread_id: Some("thread-123".into()),
        };
        let words = mbx_codex_words(
            MbxAction::Resume,
            &slot,
            Path::new("/work"),
            &["hello".into()],
            "codex",
            &["--search".into()],
            false,
        );
        assert_eq!(
            words,
            vec![
                "codex",
                "--search",
                "--cd",
                "/work",
                "resume",
                "thread-123",
                "hello"
            ]
        );
    }

    #[test]
    fn mbx_resume_without_thread_starts_fresh() {
        let slot = MbxSlot {
            id: Some(1),
            name: "a".into(),
            workdir: "/work".into(),
            thread_id: None,
        };
        let words = mbx_codex_words(
            MbxAction::Resume,
            &slot,
            Path::new("/work"),
            &[],
            "codex",
            &[],
            true,
        );
        assert_eq!(
            words,
            vec![
                "codex".to_string(),
                CODEX_UNSAFE_ARG.to_string(),
                "--cd".to_string(),
                "/work".to_string()
            ]
        );
    }

    #[test]
    fn mbx_unsafe_arg_is_not_duplicated() {
        let slot = MbxSlot {
            id: None,
            name: "codex".into(),
            workdir: "/work".into(),
            thread_id: None,
        };
        let words = mbx_codex_words(
            MbxAction::Start,
            &slot,
            Path::new("/work"),
            &[],
            "codex",
            &[CODEX_UNSAFE_ARG.into()],
            true,
        );
        assert_eq!(
            words
                .iter()
                .filter(|word| word.as_str() == CODEX_UNSAFE_ARG)
                .count(),
            1
        );
    }

    #[test]
    fn mbx_shell_quote_handles_spaces_and_quotes() {
        assert_eq!(mbx_shell_quote("/tmp/repo"), "/tmp/repo");
        assert_eq!(mbx_shell_quote("hello world"), "'hello world'");
        assert_eq!(mbx_shell_quote("don't"), "'don'\\''t'");
    }

    #[test]
    fn codex_usage_parser_reads_rate_limits() {
        let payload = serde_json::json!({
            "type": "token_count",
            "info": {
                "total_token_usage": {
                    "total_tokens": 619644,
                    "cached_input_tokens": 528640
                },
                "last_token_usage": {"total_tokens": 109315},
                "model_context_window": 258400
            },
            "rate_limits": {
                "primary": {"used_percent": 14.0, "window_minutes": 300, "resets_at": 1782210186},
                "secondary": {"used_percent": 38.0, "window_minutes": 10080, "resets_at": 1782380596},
                "rate_limit_reset_credits": {"available_count": 2},
                "credits": null,
                "plan_type": "prolite"
            }
        });
        let usage = codex_usage_from_payload("2026-06-23T07:29:57Z", &payload);
        assert_eq!(usage.plan_type, "prolite");
        assert_eq!(usage.total_units, 619644);
        assert_eq!(usage.last_units, 109315);
        assert_eq!(usage.primary.unwrap().remaining_percent, 86.0);
        assert_eq!(usage.secondary.unwrap().remaining_percent, 62.0);
        assert_eq!(usage.reset_credits.unwrap().available_count, 2);

        let window = serde_json::json!({
            "usedPercent": 35,
            "windowDurationMins": 300,
            "resetsAt": 1782210186
        });
        let window = codex_rate_window("Primary", Some(&window)).unwrap();
        assert_eq!(window.used_percent, 35.0);
        assert_eq!(window.window_minutes, 300);
        assert_eq!(window.resets_at, Some(1782210186));
    }
}
