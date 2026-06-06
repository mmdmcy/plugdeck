use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use axum::{
    Json, Router,
    body::Body,
    extract::{Form, Multipart, Path as AxumPath, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
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
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
    sync::Semaphore,
};
use tokio_util::io::ReaderStream;
use url::Url;
use uuid::Uuid;

const DEFAULT_CHANNEL: &str = "general";
const MAX_NOTE_CHARS: usize = 256 * 1024;
const MAX_IMAGE_BYTES: usize = 5 * 1024 * 1024;
const MAX_CHANNEL_CHARS: usize = 40;
const SESSION_COOKIE: &str = "plugdeck_session";
const SESSION_DAYS: i64 = 30;

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str).unwrap_or("serve") {
        "serve" => serve().await,
        "hash-password" => {
            hash_password_cmd(&args[1..])?;
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
            eprintln!("usage: plugdeck [serve|hash-password --stdin|import-motehold <db>]");
            Ok(())
        }
    }
}

async fn serve() -> io::Result<()> {
    let config = Config::from_env()?;
    let conn = open_db(&config.db_path)?;
    fs::create_dir_all(&config.download_dir)?;

    let state = Arc::new(AppState {
        db: Mutex::new(conn),
        config,
        jobs: Mutex::new(HashMap::new()),
        download_slots: Semaphore::new(1),
    });

    state.set_download_slots();

    let app = Router::new()
        .route("/", get(home))
        .route("/login", get(login_page).post(login_post))
        .route("/logout", post(logout_post))
        .route("/notes", get(notes_page).post(note_create))
        .route("/notes/channels", post(channel_create))
        .route("/notes/channels/{id}/delete", post(channel_delete))
        .route("/notes/{id}/delete", post(note_delete))
        .route("/notes/images/{id}", get(note_image))
        .route("/downloads", get(downloads_page).post(download_create))
        .route("/downloads/jobs/{id}", get(download_job_page))
        .route("/downloads/jobs/{id}/status", get(download_job_status))
        .route("/downloads/jobs/{id}/file", get(download_file))
        .with_state(state.clone());

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

impl Config {
    fn from_env() -> io::Result<Self> {
        let bind = env::var("PLUGDECK_BIND").unwrap_or_else(|_| "127.0.0.1:8789".into());
        let db_path = env::var("PLUGDECK_DB")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("data/plugdeck.sqlite"));
        let download_dir = env::var("PLUGDECK_DOWNLOAD_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("data/downloads"));
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
    let stats = {
        let db = state.db.lock().unwrap();
        let channels: i64 = db
            .query_row("SELECT COUNT(*) FROM channels", [], |row| row.get(0))
            .unwrap_or(0);
        let notes: i64 = db
            .query_row("SELECT COUNT(*) FROM notes", [], |row| row.get(0))
            .unwrap_or(0);
        (channels, notes)
    };
    let jobs = state.jobs.lock().unwrap().len();
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
  <a class="tile primary" href="/notes"><strong>Notes</strong><span>{} channels · {} notes</span></a>
  <a class="tile primary" href="/downloads"><strong>Downloads</strong><span>{jobs} active jobs</span></a>
  {links}
</main>
"#,
            stats.0, stats.1
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

async fn notes_page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(response) = page_guard(&state, &headers) {
        return response;
    }
    let (channels, notes) = {
        let db = state.db.lock().unwrap();
        (
            list_channels(&db).unwrap_or_default(),
            list_notes(&db, None).unwrap_or_default(),
        )
    };
    let channels_html = channels
        .iter()
        .map(|channel| {
            format!(
                r#"<div class="row"><span>{}</span><form action="/notes/channels/{}/delete" method="post"><button class="icon" type="submit">×</button></form></div>"#,
                html_escape(&channel.name),
                channel.id
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let notes_html = notes
        .iter()
        .map(|note| {
            let image = if note.has_image {
                format!(r#"<img src="/notes/images/{}" alt="">"#, note.id)
            } else {
                String::new()
            };
            format!(
                r#"<article class="note"><div class="note-head"><span>{}</span><form action="/notes/{}/delete" method="post"><button class="icon" type="submit">×</button></form></div><p>{}</p>{}</article>"#,
                html_escape(&note.channel),
                note.id,
                html_escape(&note.body).replace('\n', "<br>"),
                image
            )
        })
        .collect::<Vec<_>>()
        .join("");
    page(
        "Notes",
        &format!(
            r#"
<nav><a href="/">Plugdeck</a><strong>Notes</strong></nav>
<main class="split">
  <aside>
    <form action="/notes/channels" method="post" class="stack">
      <input name="name" maxlength="{MAX_CHANNEL_CHARS}" placeholder="Channel" required>
      <button type="submit">Add</button>
    </form>
    <div class="list">{channels_html}</div>
  </aside>
  <section>
    <form action="/notes" method="post" enctype="multipart/form-data" class="stack">
      <select name="channel_id">{}</select>
      <textarea name="body" maxlength="{MAX_NOTE_CHARS}" placeholder="Note"></textarea>
      <input name="image" type="file" accept="image/png,image/jpeg,image/gif,image/webp">
      <button type="submit">Save</button>
    </form>
    <div class="notes">{notes_html}</div>
  </section>
</main>
"#,
            channel_options(&channels, None)
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
    if !name.is_empty() && name.chars().count() <= MAX_CHANNEL_CHARS {
        let db = state.db.lock().unwrap();
        let _ = ensure_channel(&db, name);
    }
    Redirect::to("/notes").into_response()
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
    Redirect::to("/notes").into_response()
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
                if content_type
                    .as_deref()
                    .is_some_and(|value| allowed_image_type(value))
                {
                    if let Ok(bytes) = field.bytes().await {
                        if !bytes.is_empty() && bytes.len() <= MAX_IMAGE_BYTES {
                            image_type = content_type;
                            image_data = Some(bytes.to_vec());
                        }
                    }
                }
            }
            _ => {}
        }
    }

    let body = body.trim();
    if (!body.is_empty() || image_data.is_some()) && body.len() <= MAX_NOTE_CHARS {
        let channel_id = channel_id.unwrap_or(1);
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
    Redirect::to("/notes").into_response()
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
    let _ = db.execute("DELETE FROM notes WHERE id = ?1", params![id]);
    Redirect::to("/notes").into_response()
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
        "Downloads",
        &format!(
            r#"
<nav><a href="/">Plugdeck</a><strong>Downloads</strong></nav>
<main class="download">
  <form action="/downloads" method="post" class="download-form">
    <input name="url" type="url" inputmode="url" placeholder="https://youtu.be/..." required autofocus>
    <button type="submit">Download</button>
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
            "Downloads",
            r#"<nav><a href="/">Plugdeck</a><strong>Downloads</strong></nav><main class="download"><p class="error">Only YouTube links are accepted.</p><form action="/downloads" method="post" class="download-form"><input name="url" type="url" inputmode="url" required autofocus><button type="submit">Download</button></form></main>"#,
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
        "Download",
        &format!(
            r#"
<nav><a href="/">Plugdeck</a><a href="/downloads">Downloads</a></nav>
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
    let ascii_name = filename
        .chars()
        .filter(|ch| ch.is_ascii() && *ch != '"')
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
    let mut command = Command::new(&state.config.ytdlp);
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
        if host == "youtu.be" {
            if let Some(id) = parsed.path_segments().and_then(|mut parts| parts.next()) {
                return format!("youtube:{id}");
            }
        }
        if host == "youtube.com" || host.ends_with(".youtube.com") {
            if let Some((_, value)) = parsed.query_pairs().find(|(key, _)| key == "v") {
                return format!("youtube:{value}");
            }
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

fn channel_options(channels: &[ChannelRow], selected: Option<i64>) -> String {
    channels
        .iter()
        .map(|channel| {
            let selected_attr = if Some(channel.id) == selected {
                " selected"
            } else {
                ""
            };
            format!(
                r#"<option value="{}"{}>{}</option>"#,
                channel.id,
                selected_attr,
                html_escape(&channel.name)
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn page(title: &str, body: &str) -> Response {
    Html(format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{}</title>
<style>
:root{{color-scheme:light dark;--bg:#f6f7f5;--fg:#161816;--muted:#68706a;--line:#d7dcd5;--panel:#fff;--accent:#0d6b57;--accent2:#315f9f;--danger:#ad2f28}}
@media(prefers-color-scheme:dark){{:root{{--bg:#101211;--fg:#f4f5ef;--muted:#a2aaa4;--line:#323934;--panel:#171b18;--accent:#55b59c;--accent2:#8fb5f2;--danger:#ff8a7d}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);font:15px system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;letter-spacing:0}}a{{color:inherit;text-decoration:none}}button,input,select,textarea{{font:inherit}}button,.button{{min-height:42px;border:0;border-radius:7px;background:var(--accent);color:#fff;padding:0 15px;font-weight:700;cursor:pointer}}.ghost,.icon{{background:transparent;color:var(--fg);border:1px solid var(--line)}}.icon{{width:34px;min-height:34px;padding:0}}input,select,textarea{{width:100%;border:1px solid var(--line);border-radius:7px;background:transparent;color:var(--fg);padding:11px}}textarea{{min-height:110px;resize:vertical}}nav,.hero{{height:64px;display:flex;align-items:center;justify-content:space-between;gap:16px;padding:0 20px;border-bottom:1px solid var(--line)}}nav a{{color:var(--accent2);font-weight:700}}h1{{font-size:28px;line-height:1.1;margin:0}}main{{width:min(1180px,calc(100% - 32px));margin:0 auto;padding:18px 0}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px}}.tile,.note,aside,.download section{{border:1px solid var(--line);background:var(--panel);border-radius:8px;padding:14px}}.tile{{min-height:96px;display:flex;flex-direction:column;justify-content:space-between}}.tile.primary{{border-color:var(--accent)}}.tile strong{{font-size:18px}}.tile span,.muted{{color:var(--muted)}}.split{{display:grid;grid-template-columns:minmax(210px,280px) minmax(0,1fr);gap:14px}}.stack{{display:grid;gap:10px}}.list{{display:grid;gap:8px;margin-top:14px}}.row,.note-head{{display:flex;align-items:center;justify-content:space-between;gap:10px}}.notes{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px;margin-top:14px}}.note p{{white-space:normal;word-break:break-word;line-height:1.45}}.note img{{max-width:100%;border-radius:6px;border:1px solid var(--line)}}.login{{width:min(420px,calc(100% - 32px));padding-top:72px}}.login form,.download-form{{display:grid;gap:10px;margin-top:18px}}.error{{color:var(--danger);font-weight:700}}.download{{max-width:760px}}.jobs{{display:grid;gap:8px;margin-top:14px}}.job{{display:flex;justify-content:space-between;gap:12px;border-bottom:1px solid var(--line);padding:10px 0}}.job span{{color:var(--muted)}}.bar{{height:12px;border:1px solid var(--line);border-radius:999px;overflow:hidden;margin:18px 0}}#fill{{height:100%;width:6%;background:var(--accent)}}pre{{white-space:pre-wrap;word-break:break-word;color:var(--muted);max-height:44vh;overflow:auto;border-top:1px solid var(--line);padding-top:12px}}@media(max-width:760px){{.split{{grid-template-columns:1fr}}nav,.hero{{padding:0 14px}}main{{width:calc(100% - 20px)}}}}
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
    {
        if let Some(raw) = value.strip_prefix("Basic ") {
            if let Ok(decoded) = BASE64.decode(raw.trim()) {
                if let Ok(pair) = String::from_utf8(decoded) {
                    if let Some((user, password)) = pair.split_once(':') {
                        return user == config.user && verify_password(config, password);
                    }
                }
            }
        }
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
    io::Error::new(io::ErrorKind::Other, err.to_string())
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
}
