CREATE TABLE IF NOT EXISTS items(
 id BIGSERIAL PRIMARY KEY,
 uid TEXT NOT NULL CHECK (length(uid) BETWEEN 1 AND 128),
 kind TEXT NOT NULL CHECK (kind IN ('task','note')),
 title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 280),
 done BOOLEAN NOT NULL DEFAULT false,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS items_uid_kind ON items(uid,kind,created_at DESC);
-- Visitas agregadas por pagina y dia: no se guarda IP ni datos personales.
CREATE TABLE IF NOT EXISTS visits(
 id BIGSERIAL PRIMARY KEY,
 page TEXT NOT NULL CHECK (length(page) BETWEEN 1 AND 80),
 day DATE NOT NULL DEFAULT current_date,
 n INT NOT NULL DEFAULT 1,
 UNIQUE(page,day));
