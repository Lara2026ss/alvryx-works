import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { readFileSync } from "node:fs";
import { createRemoteJWKSet, jwtVerify } from "jose";

const E = process.env;
let fbCfg = {};
try {
  fbCfg = JSON.parse(readFileSync(new URL("./.fb_config.json", import.meta.url), "utf8"));
} catch (_) {}

const PID = E.FIREBASE_PROJECT_ID || fbCfg.projectId || "alero-company-works";
const DB_URL = (E.FIREBASE_DATABASE_URL || fbCfg.databaseURL || `https://${PID}-default-rtdb.firebaseio.com`).replace(/\/+$/, "");
const list = (v) => (v || "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
const OM = list(E.OWNER_EMAILS || "ml.lara.cmdx@gmail.com");
const OU = list(E.OWNER_UIDS);

// Helpers para Firebase Realtime Database (REST API nativa sin SDK pesado)
const rtdbUrl = (path) => `${DB_URL}/${path.replace(/^\/+/, "")}.json`;

async function rtdbGet(path) {
  const res = await fetch(rtdbUrl(path));
  if (!res.ok) {
    if (res.status === 404) return null;
    throw new Error(`RTDB GET ${path} failed: ${res.status}`);
  }
  return await res.json();
}

async function rtdbPut(path, data) {
  const res = await fetch(rtdbUrl(path), {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error(`RTDB PUT ${path} failed: ${res.status}`);
  return await res.json();
}

async function rtdbPatch(path, data) {
  const res = await fetch(rtdbUrl(path), {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error(`RTDB PATCH ${path} failed: ${res.status}`);
  return await res.json();
}

async function rtdbDelete(path) {
  const res = await fetch(rtdbUrl(path), { method: "DELETE" });
  if (!res.ok) throw new Error(`RTDB DELETE ${path} failed: ${res.status}`);
  return true;
}

// Configuración de verificación JWT con claves públicas de Google
const jwks = createRemoteJWKSet(
  new URL("https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com")
);

const app = express();
app.set("trust proxy", 1);

// Seguridad con Helmet y CSP para Firebase Realtime Database
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
        imgSrc: [
          "'self'",
          "data:",
          "https:",
          "https://avatars.githubusercontent.com",
          "https://lh3.googleusercontent.com",
          "https://ui-avatars.com",
        ],
        connectSrc: [
          "'self'",
          "https://*.googleapis.com",
          "https://*.firebaseio.com",
          "wss://*.firebaseio.com",
          "https://api.github.com",
          "https://api.render.com",
        ],
        frameSrc: ["https://*.firebaseapp.com", "https://accounts.google.com", "https://github.com"],
      },
    },
  })
);

app.use((q, r, n) => {
  r.set("Permissions-Policy", "camera=(),microphone=(),geolocation=(),payment=()");
  n();
});

app.use(express.json({ limit: "16kb" }));

const rl = (limit) => rateLimit({ windowMs: 6e4, limit, standardHeaders: true, legacyHeaders: false });
const wl = rl(60);
app.use("/api", rl(180));

const h = (f) => (q, r, n) => Promise.resolve(f(q, r, n)).catch(n);
const bad = (r, m) => r.status(400).json({ error: m });
const KINDS = ["task", "note"];

// Middleware de autenticación mediante JWT emitido por Firebase Auth
const auth = async (q, r, n) => {
  try {
    const t = (q.get("authorization") || "").replace(/^Bearer /, "");
    if (!t) return r.status(401).json({ error: "Token no proporcionado" });
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

// Configuración pública de Firebase para el cliente
app.get("/api/config", (q, r) => {
  r.json({
    appName: "Alvryx AmberFlow",
    version: "2.0.0",
    apiKey: E.FIREBASE_API_KEY || fbCfg.apiKey || "",
    appId: E.FIREBASE_APP_ID || fbCfg.appId || "",
    authDomain: E.FIREBASE_AUTH_DOMAIN || fbCfg.authDomain || PID + ".firebaseapp.com",
    databaseURL: DB_URL,
    projectId: PID,
    storageBucket: E.FIREBASE_STORAGE_BUCKET || fbCfg.storageBucket || `${PID}.firebasestorage.app`,
  });
});

// Tracker universal en JavaScript para telemetría externa
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

// Registro de visitas multi-sitio persistido directamente en Firebase RTDB
app.post(
  "/api/visit",
  (q, r, n) => {
    r.set("Access-Control-Allow-Origin", "*");
    n();
  },
  h(async (q, r) => {
    const p = String(q.body.page || "").trim();
    if (!/^[\w\-./ :áéíóúÁÉÍÓÚñÑ]{1,80}$/.test(p)) return bad(r, "Pagina invalida");
    const safeKey = Buffer.from(p).toString("hex").slice(0, 48);
    const day = new Date().toISOString().slice(0, 10);

    try {
      const pageData = (await rtdbGet(`telemetry/pages/${safeKey}`)) || { page: p, count: 0, days: {} };
      pageData.page = p;
      pageData.count = (pageData.count || 0) + 1;
      pageData.last_visit = new Date().toISOString();
      pageData.days = pageData.days || {};
      pageData.days[day] = (pageData.days[day] || 0) + 1;

      await Promise.all([
        rtdbPut(`telemetry/pages/${safeKey}`, pageData),
        (async () => {
          const cur = (await rtdbGet("telemetry/global_visits")) || 0;
          await rtdbPut("telemetry/global_visits", Number(cur) + 1);
        })(),
      ]);
    } catch (err) {
      console.warn("Aviso en registro de visita:", err.message);
    }
    r.sendStatus(204);
  })
);

// Visitas acumuladas últimos 14 días
app.get(
  "/api/visits",
  h(async (q, r) => {
    try {
      const pages = (await rtdbGet("telemetry/pages")) || {};
      const list = Object.values(pages)
        .map((p) => ({
          page: p.page || "Desconocida",
          n: Number(p.count) || 0,
          last_day: p.last_visit || new Date().toISOString(),
        }))
        .sort((a, b) => b.n - a.n)
        .slice(0, 15);
      r.json(list);
    } catch (_) {
      r.json([]);
    }
  })
);

// Métricas globales en tiempo real desde Firebase RTDB
app.get(
  "/api/global",
  h(async (q, r) => {
    r.set("Cache-Control", "public,max-age=15");
    try {
      const [users, visits] = await Promise.all([
        rtdbGet("users").catch(() => ({})),
        rtdbGet("telemetry/global_visits").catch(() => 0),
      ]);
      const userList = Object.values(users || {});
      let done = 0;
      let notes = 0;
      userList.forEach((u) => {
        if (u && typeof u === "object") {
          if (u.tasks) {
            Object.values(u.tasks).forEach((t) => {
              if (t && t.done) done++;
            });
          }
          if (u.notes) {
            notes += Object.keys(u.notes).length;
          }
        }
      });
      r.json({
        users: userList.length || 1,
        done,
        notes,
        total_visits: Number(visits) || 0,
      });
    } catch (_) {
      r.json({ users: 1, done: 0, notes: 0, total_visits: 0 });
    }
  })
);

// Consentimiento de términos y registro de usuario
app.post(
  "/api/consent",
  auth,
  wl,
  h(async (q, r) => {
    await rtdbPatch(`users/${q.user.uid}/profile`, {
      uid: q.user.uid,
      email: q.user.email,
      name: q.user.name,
      accepted_at: new Date().toISOString(),
      terms_v: "2",
    });
    r.sendStatus(204);
  })
);

// Estadísticas de usuario y mapa semanal de actividad
app.get(
  "/api/me/stats",
  auth,
  h(async (q, r) => {
    const u = q.user.uid;
    const [tasks, notes, sessions] = await Promise.all([
      rtdbGet(`users/${u}/tasks`).catch(() => ({})),
      rtdbGet(`users/${u}/notes`).catch(() => ({})),
      rtdbGet(`users/${u}/pomodoro_sessions`).catch(() => ({})),
    ]);

    const taskList = Object.values(tasks || {}).filter(Boolean);
    const noteList = Object.values(notes || {}).filter(Boolean);
    const sessionList = Object.values(sessions || {}).filter(Boolean);

    const done = taskList.filter((t) => t.done).length;
    const pending = taskList.filter((t) => !t.done).length;

    // Desglose semanal de tareas completadas (últimos 7 días)
    const week = [];
    const now = new Date();
    for (let i = 6; i >= 0; i--) {
      const d = new Date(now);
      d.setDate(d.getDate() - i);
      const dayStr = d.toISOString().slice(0, 10);
      const count = taskList.filter(
        (t) => t.done && t.done_at && String(t.done_at).slice(0, 10) === dayStr
      ).length;
      week.push({ day: dayStr, n: count });
    }

    r.json({
      done,
      pending,
      notes: noteList.length,
      sessions: sessionList.length,
      week,
    });
  })
);

// Registro de sesión de Modo Enfoque (Pomodoro)
app.post(
  "/api/sessions",
  auth,
  wl,
  h(async (q, r) => {
    const duration = Math.max(1, Math.min(180, Number(q.body.duration) || 25));
    const mode = String(q.body.mode || "focus").slice(0, 30);
    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
    const session = {
      id,
      duration,
      mode,
      created_at: new Date().toISOString(),
    };
    await rtdbPut(`users/${q.user.uid}/pomodoro_sessions/${id}`, session);
    r.status(201).json(session);
  })
);

app.get(
  "/api/sessions",
  auth,
  h(async (q, r) => {
    const data = (await rtdbGet(`users/${q.user.uid}/pomodoro_sessions`)) || {};
    const list = Object.values(data).sort((a, b) => (b.created_at || "").localeCompare(a.created_at || ""));
    r.json(list.slice(0, 50));
  })
);

// Exportación completa de datos de usuario en formato JSON
app.get(
  "/api/me/export",
  auth,
  h(async (q, r) => {
    r.set("Content-Disposition", "attachment; filename=alvryx-amberflow-export.json");
    const [tasks, notes, sessions] = await Promise.all([
      rtdbGet(`users/${q.user.uid}/tasks`).catch(() => ({})),
      rtdbGet(`users/${q.user.uid}/notes`).catch(() => ({})),
      rtdbGet(`users/${q.user.uid}/pomodoro_sessions`).catch(() => ({})),
    ]);

    r.json({
      export_version: "2.0",
      product: "Alvryx AmberFlow",
      company: "Alvryx Co.",
      user: q.user.email,
      exported_at: new Date().toISOString(),
      tasks: Object.values(tasks || {}),
      notes: Object.values(notes || {}),
      sessions: Object.values(sessions || {}),
    });
  })
);

// Eliminación de cuenta y datos personales
app.delete(
  "/api/me",
  auth,
  wl,
  h(async (q, r) => {
    await rtdbDelete(`users/${q.user.uid}`);
    r.sendStatus(204);
  })
);

// CRUD de Tareas y Notas
app.get(
  "/api/items/:kind",
  auth,
  h(async (q, r) => {
    const { kind } = q.params;
    if (!KINDS.includes(kind)) return bad(r, "Tipo invalido");
    const node = kind === "task" ? "tasks" : "notes";
    const data = (await rtdbGet(`users/${q.user.uid}/${node}`)) || {};
    const items = Object.entries(data).map(([id, val]) => ({
      id,
      ...val,
      priority: val.priority || "normal",
      category: val.category || "general",
    }));
    items.sort((a, b) => (b.created_at || "").localeCompare(a.created_at || ""));
    r.json(items);
  })
);

app.post(
  "/api/items/:kind",
  auth,
  wl,
  h(async (q, r) => {
    const { kind } = q.params;
    if (!KINDS.includes(kind)) return bad(r, "Tipo invalido");
    const t = String(q.body.title || "").trim();
    if (!t || t.length > 280) return bad(r, "Datos invalidos");
    const prio = ["low", "normal", "high"].includes(q.body.priority) ? q.body.priority : "normal";
    const cat = String(q.body.category || "general").slice(0, 30);
    const node = kind === "task" ? "tasks" : "notes";
    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
    const item = {
      id,
      title: t,
      done: false,
      priority: prio,
      category: cat,
      created_at: new Date().toISOString(),
      done_at: null,
    };
    await rtdbPut(`users/${q.user.uid}/${node}/${id}`, item);
    r.status(201).json(item);
  })
);

app.patch(
  "/api/items/:id",
  auth,
  wl,
  h(async (q, r) => {
    const id = String(q.params.id || "").trim();
    if (!id) return bad(r, "Id invalido");

    // Verificar en tareas primero
    let existing = await rtdbGet(`users/${q.user.uid}/tasks/${id}`);
    let node = "tasks";
    if (!existing) {
      existing = await rtdbGet(`users/${q.user.uid}/notes/${id}`);
      node = "notes";
    }
    if (!existing) return r.sendStatus(404);

    const updates = {};
    if (q.body.done !== undefined) {
      updates.done = Boolean(q.body.done);
      updates.done_at = updates.done ? new Date().toISOString() : null;
    }
    if (q.body.priority) updates.priority = q.body.priority;
    if (q.body.category) updates.category = q.body.category;
    if (q.body.title) updates.title = String(q.body.title).trim().slice(0, 280);

    await rtdbPatch(`users/${q.user.uid}/${node}/${id}`, updates);
    r.sendStatus(204);
  })
);

app.delete(
  "/api/items/:id",
  auth,
  wl,
  h(async (q, r) => {
    const id = String(q.params.id || "").trim();
    if (!id) return bad(r, "Id invalido");
    await Promise.all([
      rtdbDelete(`users/${q.user.uid}/tasks/${id}`),
      rtdbDelete(`users/${q.user.uid}/notes/${id}`),
    ]);
    r.sendStatus(204);
  })
);

// Cockpit de Infraestructura: Status en vivo de Render, Firebase RTDB y GitHub
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
      "User-Agent": "AlvryxAmberFlow/2.0",
      Accept: "application/vnd.github.v3+json",
      ...(E.GITHUB_TOKEN ? { Authorization: "Bearer " + E.GITHUB_TOKEN } : {}),
    };

    const renderHeaders = E.RENDER_API_KEY
      ? { Authorization: "Bearer " + E.RENDER_API_KEY, Accept: "application/json" }
      : null;

    const ghUser = E.GH_USER || "Lara2026ss";

    // Probar latencia de Firebase Realtime Database
    const t0 = Date.now();
    let rtdbHealth = "conectado";
    let rtdbPingMs = 0;
    try {
      await fetch(rtdbUrl(".json?shallow=true&limitToFirst=1"));
      rtdbPingMs = Date.now() - t0;
    } catch (_) {
      rtdbHealth = "degradado";
    }

    const [rnServices, ghUserInfo, ghRepos] = await Promise.all([
      renderHeaders ? fetchJson("https://api.render.com/v1/services?limit=20", renderHeaders) : null,
      fetchJson("https://api.github.com/users/" + ghUser, ghHeaders),
      fetchJson("https://api.github.com/users/" + ghUser + "/repos?sort=pushed&per_page=12", ghHeaders),
    ]);

    r.json({
      database: {
        engine: "Firebase Realtime Database",
        url: DB_URL,
        status: rtdbHealth,
        pingMs: rtdbPingMs,
        protocol: "WebSocket & REST JSON",
      },
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

// Despliegue manual en Render
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
app.use(express.static("public", { maxAge: "10m" }));
app.get("/healthz", (q, r) => r.send("ok"));

app.use((e, q, r, n) => {
  console.error("Error no controlado:", e.message);
  r.status(500).json({ error: "Error interno del servidor" });
});

const PORT = E.PORT || 3000;
app.listen(PORT, () => console.log(`Alvryx AmberFlow v2.0 operativo en puerto ${PORT}`));
