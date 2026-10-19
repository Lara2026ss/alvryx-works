import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import pg from "pg";
import { readFileSync } from "node:fs";
import { createRemoteJWKSet, jwtVerify } from "jose";

const E = process.env;
const PID = E.FIREBASE_PROJECT_ID || "alero-company-works";
const list = (v) => (v || "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
const OM = list(E.OWNER_EMAILS);
const OU = list(E.OWNER_UIDS);

const db = new pg.Pool({
  connectionString: E.DATABASE_URL,
  ssl: E.DATABASE_URL && !/localhost|127\.0\.0\.1/.test(E.DATABASE_URL) ? { rejectUnauthorized: false } : false,
  max: 5,
});

// Inicialización de esquemas y migraciones seguras
try {
  await db.query(readFileSync(new URL("./schema.sql", import.meta.url), "utf8"));
  await db.query(`
    ALTER TABLE items ADD COLUMN IF NOT EXISTS done_at TIMESTAMPTZ;
    ALTER TABLE items ADD COLUMN IF NOT EXISTS priority TEXT DEFAULT 'normal';
    ALTER TABLE items ADD COLUMN IF NOT EXISTS category TEXT DEFAULT 'general';
    CREATE TABLE IF NOT EXISTS users (
      uid TEXT PRIMARY KEY CHECK (length(uid) BETWEEN 1 AND 128),
      accepted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      terms_v TEXT NOT NULL DEFAULT '1'
    );
  `);
} catch (err) {
  console.error("Error en migración de BD:", err.message);
}

const jwks = createRemoteJWKSet(
  new URL("https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com")
);

const app = express();
app.set("trust proxy", 1);

// Seguridad con Helmet y CORS granular
app.use(
  helmet({
    crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" },
    referrerPolicy: { policy: "no-referrer" },
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "https://www.gstatic.com", "https://apis.google.com"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc: ["https://fonts.gstatic.com"],
        imgSrc: ["'self'", "data:", "https:", "https://avatars.githubusercontent.com", "https://lh3.googleusercontent.com"],
        connectSrc: ["'self'", "https://*.googleapis.com", "https://api.github.com", "https://api.render.com"],
        frameSrc: ["https://*.firebaseapp.com", "https://accounts.google.com", "https://github.com"],
      },
    },
  })
);

app.use((q, r, n) => {
  r.set("Permissions-Policy", "camera=(),microphone=(),geolocation=(),payment=()");
  n();
});

app.use(express.json({ limit: "8kb" }));

const rl = (limit) => rateLimit({ windowMs: 6e4, limit, standardHeaders: true, legacyHeaders: false });
const wl = rl(40);
app.use("/api", rl(140));

const h = (f) => (q, r, n) => Promise.resolve(f(q, r, n)).catch(n);
const bad = (r, m) => r.status(400).json({ error: m });
const KINDS = ["task", "note"];

// Middleware de autenticación server-side mediante JWT de Firebase
const auth = async (q, r, n) => {
  try {
    const t = (q.get("authorization") || "").replace(/^Bearer /, "");
    const { payload: p } = await jwtVerify(t, jwks, {
      issuer: "https://securetoken.google.com/" + PID,
      audience: PID,
    });
    const m = (p.email || "").toLowerCase();
    q.user = {
      uid: p.sub,
      email: p.email || "",
      name: p.name || "",
      picture: p.picture || "",
      owner: OU.includes(p.sub.toLowerCase()) || (OM.includes(m) && p.email_verified !== false),
    };
    n();
  } catch (e) {
    r.status(401).json({ error: "No autorizado" });
  }
};

// Configuración pública de Firebase para el frontend
app.get("/api/config", (q, r) => {
  r.json({
    apiKey: E.FIREBASE_API_KEY || "",
    appId: E.FIREBASE_APP_ID || "",
    authDomain: E.FIREBASE_AUTH_DOMAIN || PID + ".firebaseapp.com",
    projectId: PID,
  });
});

// Tracker universal para embeber en cualquier HTML externo
app.get("/track.js", (q, r) => {
  r.set("Content-Type", "application/javascript");
  r.set("Access-Control-Allow-Origin", "*");
  r.set("Cache-Control", "public, max-age=1800");
  const host = q.protocol + "://" + q.get("host");
  r.send(`(function(){
    try {
      var s = document.currentScript;
      var p = (s && s.dataset.page) || document.title || location.pathname;
      var url = "${host}/api/visit";
      var body = JSON.stringify({ page: String(p).trim().slice(0, 80) });
      if (navigator.sendBeacon) {
        navigator.sendBeacon(url, new Blob([body], { type: "application/json" }));
      } else {
        fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: body, mode: "cors" }).catch(function(){});
      }
    } catch(e) {}
  })();`);
});

// Opciones preflight CORS para visitas externas
app.options("/api/visit", (q, r) => {
  r.set("Access-Control-Allow-Origin", "*");
  r.set("Access-Control-Allow-Methods", "POST, OPTIONS");
  r.set("Access-Control-Allow-Headers", "Content-Type");
  r.sendStatus(204);
});

// Registro de visitas multi-sitio
app.post(
  "/api/visit",
  (q, r, n) => {
    r.set("Access-Control-Allow-Origin", "*");
    n();
  },
  h(async (q, r) => {
    const p = String(q.body.page || "").trim();
    if (!/^[\w\-./ :áéíóúÁÉÍÓÚñÑ]{1,80}$/.test(p)) return bad(r, "Pagina invalida");
    await db.query("INSERT INTO visits(page) VALUES($1) ON CONFLICT(page,day) DO UPDATE SET n=visits.n+1", [p]);
    r.sendStatus(204);
  })
);

// Visitas acumuladas últimos 14 días
app.get(
  "/api/visits",
  h(async (q, r) => {
    const res = await db.query(
      "SELECT page, sum(n)::int n, max(day) as last_day FROM visits WHERE day > current_date - 14 GROUP BY page ORDER BY n DESC LIMIT 15"
    );
    r.json(res.rows);
  })
);

// Métricas globales de la plataforma
app.get(
  "/api/global",
  h(async (q, r) => {
    r.set("Cache-Control", "public,max-age=30");
    const res = await db.query(
      "SELECT (SELECT count(*) FROM users)::int users, (SELECT count(*) FROM items WHERE kind='task' AND done)::int done, (SELECT count(*) FROM items WHERE kind='note')::int notes, (SELECT coalesce(sum(n),0)::int FROM visits)::int total_visits"
    );
    r.json(res.rows[0]);
  })
);

// Consentimiento de términos
app.post(
  "/api/consent",
  auth,
  wl,
  h(async (q, r) => {
    await db.query("INSERT INTO users(uid) VALUES($1) ON CONFLICT(uid) DO UPDATE SET accepted_at=now()", [q.user.uid]);
    r.sendStatus(204);
  })
);

// Estadísticas de usuario y mapa de actividad
app.get(
  "/api/me/stats",
  auth,
  h(async (q, r) => {
    const u = q.user.uid;
    const [c, d] = await Promise.all([
      db.query(
        "SELECT count(*) FILTER (WHERE kind='task' AND done)::int done, count(*) FILTER (WHERE kind='task' AND NOT done)::int pending, count(*) FILTER (WHERE kind='note')::int notes FROM items WHERE uid=$1",
        [u]
      ),
      db.query(
        "SELECT to_char(d,'YYYY-MM-DD') day, count(i.id)::int n FROM generate_series(current_date-6, current_date, '1 day') d LEFT JOIN items i ON i.uid=$1 AND i.kind='task' AND i.done_at::date=d::date GROUP BY d ORDER BY d",
        [u]
      ),
    ]);
    r.json({ ...c.rows[0], week: d.rows });
  })
);

// Exportación de datos personales
app.get(
  "/api/me/export",
  auth,
  h(async (q, r) => {
    r.set("Content-Disposition", "attachment; filename=alvryx-export.json");
    const res = await db.query(
      "SELECT kind, title, done, priority, category, created_at, done_at FROM items WHERE uid=$1 ORDER BY id",
      [q.user.uid]
    );
    r.json({
      export_version: "2.0",
      company: "Alvryx Co.",
      user: q.user.email,
      exported_at: new Date().toISOString(),
      items: res.rows,
    });
  })
);

// Eliminación de cuenta
app.delete(
  "/api/me",
  auth,
  wl,
  h(async (q, r) => {
    await db.query("DELETE FROM items WHERE uid=$1", [q.user.uid]);
    await db.query("DELETE FROM users WHERE uid=$1", [q.user.uid]);
    r.sendStatus(204);
  })
);

// CRUD de Tareas y Notas
app.get(
  "/api/items/:kind",
  auth,
  h(async (q, r) => {
    if (!KINDS.includes(q.params.kind)) return bad(r, "Tipo invalido");
    const res = await db.query(
      "SELECT id, title, done, coalesce(priority, 'normal') as priority, coalesce(category, 'general') as category, created_at, done_at FROM items WHERE uid=$1 AND kind=$2 ORDER BY created_at DESC LIMIT 300",
      [q.user.uid, q.params.kind]
    );
    r.json(res.rows);
  })
);

app.post(
  "/api/items/:kind",
  auth,
  wl,
  h(async (q, r) => {
    const t = String(q.body.title || "").trim();
    const prio = ["low", "normal", "high"].includes(q.body.priority) ? q.body.priority : "normal";
    const cat = String(q.body.category || "general").slice(0, 30);
    if (!KINDS.includes(q.params.kind) || !t || t.length > 280) return bad(r, "Datos invalidos");
    const res = await db.query(
      "INSERT INTO items(uid, kind, title, priority, category) VALUES($1, $2, $3, $4, $5) RETURNING id, title, done, priority, category, created_at",
      [q.user.uid, q.params.kind, t, prio, cat]
    );
    r.status(201).json(res.rows[0]);
  })
);

const own = (sql, get) =>
  h(async (q, r) => {
    const id = +q.params.id;
    if (!Number.isSafeInteger(id)) return bad(r, "Id invalido");
    const x = await db.query(sql, get(q, id));
    r.sendStatus(x.rowCount ? 204 : 404);
  });

app.patch(
  "/api/items/:id",
  auth,
  wl,
  own(
    "UPDATE items SET done=coalesce($1, done), done_at=CASE WHEN $1 THEN now() ELSE done_at END, priority=coalesce($2, priority), category=coalesce($3, category) WHERE id=$4 AND uid=$5",
    (q, id) => [
      q.body.done !== undefined ? Boolean(q.body.done) : null,
      q.body.priority || null,
      q.body.category || null,
      id,
      q.user.uid,
    ]
  )
);

app.delete(
  "/api/items/:id",
  auth,
  wl,
  own("DELETE FROM items WHERE id=$1 AND uid=$2", (q, id) => [id, q.user.uid])
);

// Cockpit de Infraestructura: Status en vivo de Render, PostgreSQL y GitHub
app.get(
  "/api/status",
  auth,
  h(async (q, r) => {
    if (!q.user.owner) return r.status(403).json({ error: "Acceso exclusivo para administradores de Alvryx Co." });

    const fetchJson = (u, hd) =>
      fetch(u, { headers: hd })
        .then((x) => (x.ok ? x.json() : null))
        .catch(() => null);

    const ghHeaders = {
      "User-Agent": "AlvryxWorks/2.0",
      Accept: "application/vnd.github.v3+json",
      ...(E.GITHUB_TOKEN ? { Authorization: "Bearer " + E.GITHUB_TOKEN } : {}),
    };

    const renderHeaders = E.RENDER_API_KEY
      ? { Authorization: "Bearer " + E.RENDER_API_KEY, Accept: "application/json" }
      : null;

    const ghUser = E.GH_USER || "Lara2026ss";

    const [rnServices, rnPostgres, ghUserInfo, ghRepos] = await Promise.all([
      renderHeaders ? fetchJson("https://api.render.com/v1/services?limit=20", renderHeaders) : null,
      renderHeaders ? fetchJson("https://api.render.com/v1/postgres?limit=10", renderHeaders) : null,
      fetchJson("https://api.github.com/users/" + ghUser, ghHeaders),
      fetchJson("https://api.github.com/users/" + ghUser + "/repos?sort=pushed&per_page=12", ghHeaders),
    ]);

    r.json({
      hasRender: Boolean(rnServices),
      render: (rnServices || []).map(({ service: s }) => ({
        id: s.id,
        name: s.name,
        type: s.type,
        status: s.suspended === "suspended" ? "suspendido" : "activo",
        url: s.serviceDetails?.url || "",
        branch: s.branch || "main",
        region: s.serviceDetails?.region || "oregon",
        updatedAt: s.updatedAt,
      })),
      postgres: (rnPostgres || []).map(({ postgres: p }) => ({
        id: p.id,
        name: p.name,
        databaseName: p.databaseName,
        status: p.status,
        plan: p.plan,
        version: p.version,
        expiresAt: p.expiresAt,
        region: p.region,
      })),
      github: {
        user: ghUserInfo
          ? {
              login: ghUserInfo.login,
              name: ghUserInfo.name,
              avatar: ghUserInfo.avatar_url,
              repos: ghUserInfo.public_repos,
              followers: ghUserInfo.followers,
              url: ghUserInfo.html_url,
            }
          : null,
        repos: (ghRepos || []).map((x) => ({
          name: x.name,
          description: x.description || "Sin descripción",
          stars: x.stargazers_count,
          forks: x.forks_count,
          language: x.language || "HTML/JS",
          updatedAt: x.pushed_at,
          url: x.html_url,
          isPrivate: x.private,
        })),
      },
    });
  })
);

// Acción operativa: Disparar deploy manual en Render
app.post(
  "/api/render/deploy",
  auth,
  wl,
  h(async (q, r) => {
    if (!q.user.owner) return r.status(403).json({ error: "Acceso exclusivo para administradores" });
    if (!E.RENDER_API_KEY) return bad(r, "RENDER_API_KEY no configurada");
    const serviceId = String(q.body.serviceId || "").trim();
    if (!serviceId) return bad(r, "serviceId requerido");

    const res = await fetch(`https://api.render.com/v1/services/${serviceId}/deploys`, {
      method: "POST",
      headers: {
        Authorization: "Bearer " + E.RENDER_API_KEY,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ clearCache: "do_not_clear" }),
    });

    const data = await res.json();
    if (!res.ok) return r.status(res.status).json(data);
    r.json({ ok: true, deploy: data });
  })
);

// Archivos estáticos y health check
app.use(express.static("public", { maxAge: "30m" }));
app.get("/healthz", (q, r) => r.send("ok"));

app.use((e, q, r, n) => {
  console.error("Error no controlado:", e.message);
  r.status(500).json({ error: "Error interno del servidor" });
});

const PORT = E.PORT || 3000;
app.listen(PORT, () => console.log(`Alvryx Works operativo en puerto ${PORT}`));
