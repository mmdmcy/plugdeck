use std::sync::Arc;

use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post},
};

use crate::{AppState, MAX_AGENT_UPLOAD_BYTES, MAX_NOTE_CHARS, html_escape};

type AppRouter = Router<Arc<AppState>>;

pub(crate) struct PlugdeckModule {
    name: &'static str,
    href: &'static str,
    primary: bool,
    detail: fn(&AppState) -> String,
    routes: fn(AppRouter) -> AppRouter,
}

pub(crate) fn build_router(state: Arc<AppState>) -> Router {
    let router: AppRouter = Router::new()
        .route("/", get(crate::home))
        .route("/login", get(crate::login_page).post(crate::login_post))
        .route("/logout", post(crate::logout_post));

    builtin_modules()
        .into_iter()
        .fold(router, |router, module| (module.routes)(router))
        .layer(DefaultBodyLimit::max(
            MAX_AGENT_UPLOAD_BYTES + MAX_NOTE_CHARS + 1024 * 1024,
        ))
        .with_state(state)
}

pub(crate) fn module_tiles(state: &Arc<AppState>) -> String {
    builtin_modules()
        .into_iter()
        .map(|module| {
            let class = if module.primary {
                "tile primary"
            } else {
                "tile"
            };
            format!(
                r#"<a class="{class}" href="{}"><strong>{}</strong><span>{}</span></a>"#,
                html_escape(module.href),
                html_escape(module.name),
                html_escape(&(module.detail)(state))
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn builtin_modules() -> Vec<PlugdeckModule> {
    vec![
        PlugdeckModule {
            name: "Notes",
            href: "/notes",
            primary: true,
            detail: notes_detail,
            routes: notes_routes,
        },
        PlugdeckModule {
            name: "Agents",
            href: "/agents",
            primary: true,
            detail: agents_detail,
            routes: agents_routes,
        },
        PlugdeckModule {
            name: "YTP Downloader",
            href: "/downloads",
            primary: true,
            detail: downloads_detail,
            routes: downloads_routes,
        },
    ]
}

fn notes_routes(router: AppRouter) -> AppRouter {
    router
        .route("/notes", get(crate::notes_page).post(crate::note_create))
        .route("/notes/channels", post(crate::channel_create))
        .route("/notes/channels/{id}/delete", post(crate::channel_delete))
        .route("/notes/{id}/delete", post(crate::note_delete))
        .route("/notes/images/{id}", get(crate::note_image))
}

fn agents_routes(router: AppRouter) -> AppRouter {
    router
        .route(
            "/agents",
            get(crate::agents_page).post(crate::agent_message_create),
        )
        .route(
            "/agents/slots/{id}/conversation",
            post(crate::agent_conversation_load),
        )
        .route(
            "/agents/slots/{id}/project",
            post(crate::agent_project_start),
        )
        .route("/agents/slots/{id}/cancel", post(crate::agent_cancel))
        .route("/agents/slots/{id}/state", get(crate::agent_slot_state))
        .route("/agents/attachments/{id}", get(crate::agent_attachment))
        .route("/agents/codex/reset", post(crate::codex_reset_post))
}

fn downloads_routes(router: AppRouter) -> AppRouter {
    router
        .route(
            "/downloads",
            get(crate::downloads_page).post(crate::download_create),
        )
        .route("/downloads/jobs/{id}", get(crate::download_job_page))
        .route(
            "/downloads/jobs/{id}/status",
            get(crate::download_job_status),
        )
        .route("/downloads/jobs/{id}/file", get(crate::download_file))
}

fn notes_detail(state: &AppState) -> String {
    let db = state.db.lock().unwrap();
    let channels: i64 = db
        .query_row("SELECT COUNT(*) FROM channels", [], |row| row.get(0))
        .unwrap_or(0);
    let notes: i64 = db
        .query_row("SELECT COUNT(*) FROM notes", [], |row| row.get(0))
        .unwrap_or(0);
    format!("{channels} channels · {notes} notes")
}

fn agents_detail(state: &AppState) -> String {
    let messages = {
        let db = state.db.lock().unwrap();
        db.query_row("SELECT COUNT(*) FROM agent_messages", [], |row| row.get(0))
            .unwrap_or(0)
    };
    let running = state.agent_jobs.lock().unwrap().len();
    if running == 0 {
        format!("{messages} messages")
    } else {
        format!("{messages} messages · {running} running")
    }
}

fn downloads_detail(state: &AppState) -> String {
    let jobs = state.jobs.lock().unwrap().len();
    format!("{jobs} active jobs")
}
