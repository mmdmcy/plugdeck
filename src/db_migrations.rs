use rusqlite::{Connection, params};

use crate::codex_reset_ledger;

pub const LATEST_SCHEMA_VERSION: i64 = 2;

const BASE_SCHEMA: &str = r#"
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
"#;

pub fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
        PRAGMA foreign_keys = ON;
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        "#,
    )?;

    let current = current_version(conn)?;
    if current < 1 {
        conn.execute_batch(BASE_SCHEMA)?;
        conn.execute_batch(codex_reset_ledger::SCHEMA)?;
        record_migration(conn, 1)?;
    }
    if current < 2 {
        migrate_single_codex_lane(conn)?;
        record_migration(conn, 2)?;
    }
    debug_assert!(current_version(conn)? >= LATEST_SCHEMA_VERSION);
    Ok(())
}

fn current_version(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
        row.get::<_, Option<i64>>(0)
    })
    .map(|version| version.unwrap_or(0))
}

fn record_migration(conn: &Connection, version: i64) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO schema_migrations (version) VALUES (?1)",
        params![version],
    )?;
    Ok(())
}

fn migrate_single_codex_lane(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE agent_slots
         SET name = 'codex'
         WHERE lower(name) = 'a'
           AND NOT EXISTS (SELECT 1 FROM agent_slots WHERE lower(name) = 'codex')",
        [],
    )?;
    conn.execute(
        "DELETE FROM agent_slots
         WHERE lower(name) IN ('a', 'b', 'c', 'd', 'e')
           AND NOT EXISTS (SELECT 1 FROM agent_messages WHERE slot_id = agent_slots.id)
           AND NOT EXISTS (SELECT 1 FROM agent_attachments WHERE slot_id = agent_slots.id)
           AND NOT EXISTS (SELECT 1 FROM agent_sessions WHERE slot_id = agent_slots.id)",
        [],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrate_records_latest_schema_version() {
        let db = Connection::open_in_memory().unwrap();
        migrate(&db).unwrap();
        assert_eq!(current_version(&db).unwrap(), LATEST_SCHEMA_VERSION);
    }

    #[test]
    fn migration_two_renames_a_and_removes_only_empty_legacy_slots() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(BASE_SCHEMA).unwrap();
        db.execute_batch(
            r#"
            CREATE TABLE schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            INSERT INTO schema_migrations (version) VALUES (1);
            INSERT INTO agent_slots (name, workdir, created_at) VALUES
                ('a', '/tmp', 'now'),
                ('b', '/tmp', 'now'),
                ('c', '/tmp', 'now');
            INSERT INTO agent_messages (slot_id, role, body, created_at)
                SELECT id, 'user', 'keep me', 'now' FROM agent_slots WHERE name = 'c';
            "#,
        )
        .unwrap();

        migrate(&db).unwrap();

        let names = db
            .prepare("SELECT name FROM agent_slots ORDER BY id")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(names, vec!["codex", "c"]);
        assert_eq!(current_version(&db).unwrap(), LATEST_SCHEMA_VERSION);
    }
}
