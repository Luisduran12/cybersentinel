/*
 * Panel SOC — JavaScript sin dependencias ni cadena de compilación.
 *
 * Tres decisiones que conviene justificar antes de leer el código:
 *
 * 1. El token vive en `sessionStorage`, no en `localStorage` ni en una cookie
 *    sin `HttpOnly`. `sessionStorage` muere al cerrar la pestaña, que es el
 *    comportamiento que un analista espera de una consola de seguridad en un
 *    puesto compartido. Sigue siendo accesible desde JavaScript: la defensa
 *    real contra el robo de token es la vida corta (una hora) y la revocación
 *    en `/auth/logout`, no el sitio donde se guarda.
 *
 * 2. Todo lo que viene del servidor se inserta con `textContent`, nunca con
 *    `innerHTML`. La telemetría la escribe el atacante: una línea de comandos
 *    con `<img onerror=...>` ejecutaría su código en el navegador del analista
 *    que la está investigando. Es el mismo razonamiento que ya se aplica a la
 *    inyección de prompt en el explicador, en otra capa.
 *
 * 3. Los botones de escritura se construyen solo si el servidor dice
 *    `can_write`. Eso es comodidad, no seguridad: quien quiera saltárselo edita
 *    el DOM. La autorización de verdad está en la API, y hay pruebas que lo
 *    comprueban llamando directamente con el rol equivocado.
 */
"use strict";

const API = "/api/v1";
const CLAVE_TOKEN = "cs_token";
const CLAVE_QUIEN = "cs_quien";

const $ = (sel) => document.querySelector(sel);
const estado = { quien: null, incidentes: [], seleccionado: null, puedeEscribir: false };

const ETIQUETA_ESTADO = {
  new: "Nuevo", triaged: "Triado", in_progress: "En curso", closed: "Cerrado",
};
const ETIQUETA_SEVERIDAD = {
  critical: "Crítica", high: "Alta", medium: "Media", low: "Baja",
};
const ETIQUETA_RESOLUCION = {
  true_positive: "Verdadero positivo", false_positive: "Falso positivo",
  benign: "Benigno", duplicate: "Duplicado",
};
const ETIQUETA_GOBERNANZA = {
  allowed: "Permitida", requires_approval: "Requiere aprobación", prohibited: "Prohibida",
};
const ETIQUETA_DETECCION = {
  RULE_AND_ANOMALY: "Regla + anomalía", RULE_MATCH: "Regla determinista",
  ANOMALY_ONLY: "Solo anomalía (sin regla)", NO_DETECTION: "Sin detección",
};

/* --- utilidades ------------------------------------------------------- */
function token() { return sessionStorage.getItem(CLAVE_TOKEN); }

function el(tag, clase, texto) {
  const n = document.createElement(tag);
  if (clase) n.className = clase;
  if (texto !== undefined && texto !== null) n.textContent = String(texto);
  return n;
}

function fecha(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleString("es-ES", { dateStyle: "short", timeStyle: "medium" });
}

function opcion(valor, texto) {
  const o = el("option", null, texto);
  o.value = valor;
  return o;
}

function avisar(texto, mal = false) {
  document.querySelectorAll(".toast").forEach((t) => t.remove());
  const t = el("div", "toast" + (mal ? " mal" : ""), texto);
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 4500);
}

async function api(ruta, opciones = {}) {
  const cabeceras = { "content-type": "application/json", ...(opciones.headers || {}) };
  const t = token();
  if (t) cabeceras["Authorization"] = `Bearer ${t}`;

  const r = await fetch(API + ruta, { ...opciones, headers: cabeceras });
  if (r.status === 401) {
    // El token caducó o fue revocado. Se vuelve al acceso en vez de dejar la
    // interfaz medio viva mostrando datos que ya no se pueden refrescar.
    cerrarSesion(true);
    throw new Error("La sesión ha caducado.");
  }
  const cuerpo = r.status === 204 ? null : await r.json().catch(() => null);
  if (!r.ok) {
    const d = cuerpo && cuerpo.detail;
    const motivo = (d && (d.reason || d.error)) || (cuerpo && cuerpo.reason) ||
                   `Error ${r.status}`;
    throw new Error(motivo);
  }
  return cuerpo;
}

/* --- aviso sobre la conexión ------------------------------------------ */
function avisarDelTransporte() {
  /*
   * El aviso se calcula, no se escribe fijo.
   *
   * Un texto estático que dice «comprueba que ponga https» aparece también
   * cuando la conexión ya es segura, y un aviso que sale siempre deja de
   * leerse. Aquí solo se muestra cuando de verdad hay algo que advertir, y con
   * el tono que corresponde: sobre bucle local es una nota, sobre una red es
   * un problema.
   */
  const nodo = $("#aviso-transporte");
  const seguro = location.protocol === "https:";
  const local = ["localhost", "127.0.0.1", "[::1]", "::1"].includes(location.hostname);

  if (seguro) { nodo.hidden = true; return; }

  nodo.hidden = false;
  if (local) {
    nodo.textContent = "Conexión sin cifrar sobre bucle local. Vale para "
      + "desarrollo; la API rechazará credenciales en claro desde cualquier "
      + "otro origen.";
  } else {
    nodo.classList.add("grave");
    nodo.textContent = "Esta conexión NO está cifrada y no viene de tu máquina: "
      + "la contraseña viajaría legible. No la escribas. Accede por https:// o "
      + "avisa a quien administre el servicio.";
    $("#entrar").disabled = true;
    $("#usuario").disabled = true;
    $("#clave").disabled = true;
  }
}

avisarDelTransporte();

/* --- acceso ----------------------------------------------------------- */
$("#login-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const boton = $("#entrar");
  const error = $("#login-error");
  error.hidden = true;
  boton.disabled = true;
  try {
    const datos = await api("/auth/token", {
      method: "POST",
      body: JSON.stringify({ username: $("#usuario").value, password: $("#clave").value }),
    });
    sessionStorage.setItem(CLAVE_TOKEN, datos.access_token);
    $("#clave").value = "";
    await arrancar();
  } catch (exc) {
    error.textContent = exc.message;
    error.hidden = false;
  } finally {
    boton.disabled = false;
  }
});

$("#salir").addEventListener("click", async () => {
  // Se avisa al servidor para que revoque el `jti`: borrar el token del
  // navegador y dejarlo válido una hora más no es cerrar sesión.
  try { await api("/auth/logout", { method: "POST" }); } catch (_) { /* da igual */ }
  cerrarSesion(false);
});

function cerrarSesion(porCaducidad) {
  sessionStorage.removeItem(CLAVE_TOKEN);
  sessionStorage.removeItem(CLAVE_QUIEN);
  estado.quien = null;
  $("#app").hidden = true;
  $("#login").hidden = false;
  if (porCaducidad) {
    $("#login-error").textContent = "La sesión ha caducado. Vuelve a entrar.";
    $("#login-error").hidden = false;
  }
}

/* --- arranque --------------------------------------------------------- */
async function arrancar() {
  estado.quien = await api("/auth/whoami");
  sessionStorage.setItem(CLAVE_QUIEN, JSON.stringify(estado.quien));
  $("#quien-nombre").textContent = estado.quien.display;
  $("#quien-rol").textContent = estado.quien.role;
  estado.puedeEscribir = estado.quien.permissions.includes("incidents:write");
  $("#login").hidden = true;
  $("#app").hidden = false;
  await Promise.all([cargarSalud(), cargarCifras(), cargarLista()]);
}

async function cargarSalud() {
  try {
    const r = await api("/ready");
    const componentes = r.components || {};
    // El pipeline devuelve "OK (7 reglas)", no "OK": compararlo por igualdad
    // marcaba como degradado todo lo que funcionaba y dejaba el panel gritando
    // en rojo con el servicio sano. Se vio en el navegador, no en las pruebas.
    const degradados = Object.entries(componentes)
      .filter(([, v]) => !String(v).startsWith("OK") && !String(v).startsWith("DISABLED"))
      .map(([k, v]) => `${k}: ${String(v).split(" (")[0]}`);
    const nodo = $("#salud");
    nodo.textContent = "";
    // Se muestra lo que NO está funcionando. Un panel que solo dice «todo bien»
    // esconde que el modelo lleva dos horas sin línea base.
    if (!r.ready) {
      nodo.append(el("span", "pill critical", "servicio no listo"));
    } else if (degradados.length) {
      nodo.append(el("span", "pill medium", "degradado: " + degradados.join(", ")));
    } else {
      nodo.append(el("span", "pill low", "servicio operativo"));
    }
    if (r.security && r.security.token_secret_source === "ephemeral") {
      nodo.append(" ", el("span", "badge-fallback", "secreto de token efímero"));
    }
  } catch (_) { /* sin permiso de métricas: el panel funciona igual */ }
}

async function cargarCifras() {
  const s = await api("/incidents/stats");
  const cont = $("#cifras");
  cont.textContent = "";
  const tarjetas = [
    ["Abiertos", s.open, false],
    ["Críticos abiertos", s.critical_open, s.critical_open > 0],
    ["Sin asignar", s.unassigned, false],
    ["Total registrados", s.total, false],
  ];
  for (const [rotulo, valor, grave] of tarjetas) {
    const d = el("div", "cifra" + (grave ? " grave" : ""));
    d.append(el("b", null, valor ?? 0), el("span", null, rotulo));
    cont.append(d);
  }
  if (s.top_techniques && s.top_techniques.length) {
    const d = el("div", "cifra");
    d.append(el("b", null, s.top_techniques[0][0]));
    d.append(el("span", null, `técnica más vista (${s.top_techniques[0][1]})`));
    cont.append(d);
  }
}

function filtros() {
  const p = new URLSearchParams();
  const q = $("#buscar").value.trim();
  if (q) p.set("q", q);
  if ($("#f-estado").value) p.set("state", $("#f-estado").value);
  if ($("#f-severidad").value) p.set("severity", $("#f-severidad").value);
  if ($("#f-mios").checked && estado.quien) p.set("owner", estado.quien.display);
  if ($("#f-sin-duenno").checked) p.set("unassigned", "true");
  p.set("limit", "100");
  return p.toString();
}

async function cargarLista() {
  const datos = await api("/incidents?" + filtros());
  estado.incidentes = datos.incidents;
  estado.puedeEscribir = datos.can_write;
  $("#conteo").textContent = `${datos.incidents.length} de ${datos.total}`;

  const lista = $("#lista");
  lista.textContent = "";
  if (!datos.incidents.length) {
    const v = el("div", "vacio");
    v.append(el("p", null, "Ningún incidente con estos filtros."));
    v.append(el("p", "sub", `El umbral de alerta es ${datos.threshold}: por debajo, los eventos se analizan y se guardan, pero no abren incidente.`));
    lista.append(v);
    return;
  }
  for (const inc of datos.incidents) lista.append(tarjeta(inc));
}

function tarjeta(inc) {
  const n = el("div", `tarjeta ${inc.severity}${inc.state === "closed" ? " cerrado" : ""}`);
  n.setAttribute("role", "button");
  n.setAttribute("tabindex", "0");
  n.setAttribute("aria-selected", String(estado.seleccionado === inc.incident_id));
  n.append(el("h3", null, inc.title));

  const meta = el("div", "meta");
  meta.append(el("span", `pill ${inc.severity}`, ETIQUETA_SEVERIDAD[inc.severity] || inc.severity));
  meta.append(el("span", "pill", ETIQUETA_ESTADO[inc.state] || inc.state));
  meta.append(el("span", null, `${inc.score.toFixed(1)} pts`));
  meta.append(el("span", null, fecha(inc.detected_at)));
  if (inc.owner) meta.append(el("span", null, `· ${inc.owner}`));
  for (const t of (inc.techniques || []).slice(0, 3)) meta.append(el("span", "pill tec", t));
  n.append(meta);

  const abrir = () => abrirIncidente(inc.incident_id);
  n.addEventListener("click", abrir);
  n.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); abrir(); } });
  return n;
}

/* --- detalle ---------------------------------------------------------- */
async function abrirIncidente(id) {
  estado.seleccionado = id;
  document.querySelectorAll(".tarjeta").forEach((t) => t.setAttribute("aria-selected", "false"));
  const inc = await api("/incidents/" + encodeURIComponent(id));
  pintarDetalle(inc);
  await cargarLista();
}

function bloque(titulo) {
  const b = el("section", "bloque");
  b.append(el("h4", null, titulo));
  return b;
}

function pintarDetalle(inc) {
  const d = $("#detalle");
  d.textContent = "";

  d.append(el("h2", null, inc.title));
  const id = el("div", "idref");
  id.append(el("code", "mono", inc.incident_id));
  d.append(id);

  // --- Cifras del veredicto ---
  const b1 = bloque("Veredicto");
  const rej = el("div", "rejilla");
  const datos = [
    ["Puntuación híbrida", inc.score.toFixed(1)],
    ["Severidad", ETIQUETA_SEVERIDAD[inc.severity] || inc.severity],
    ["Estado", ETIQUETA_ESTADO[inc.state] || inc.state],
    ["Propietario", inc.owner || "sin asignar"],
    ["Cómo se detectó", ETIQUETA_DETECCION[inc.detection_status] || inc.detection_status],
    ["Anomalía (0–1)", inc.anomaly_score.toFixed(3)],
    ["Entidad", inc.entity || "—"],
    ["Fuente", inc.source],
    ["Momento del evento", fecha(inc.event_time)],
    ["Detectado", fecha(inc.detected_at)],
  ];
  if (inc.resolution) datos.push(["Resolución", ETIQUETA_RESOLUCION[inc.resolution] || inc.resolution]);
  for (const [rotulo, valor] of datos) {
    const c = el("div", "dato");
    c.append(el("span", null, rotulo), el("b", null, valor));
    rej.append(c);
  }
  b1.append(rej);
  if (inc.detection_status === "ANOMALY_ONLY") {
    b1.append(el("p", "nota-metodo",
      "Ninguna regla disparó: lo señaló solo el modelo. La puntuación híbrida "
      + "concede como máximo 20 puntos al detector de anomalías, así que un "
      + "incidente así no alcanza el umbral por sí solo salvo que otra señal lo empuje."));
  }
  d.append(b1);

  // --- Por qué saltó ---
  const b2 = bloque("Por qué saltó");
  if (inc.rules && inc.rules.length) {
    for (const r of inc.rules) {
      const n = el("div", "regla");
      const cab = el("div", "cab");
      cab.append(el("b", null, r.title || r.rule_id));
      cab.append(el("span", "pill", r.rule_id));
      if (r.severity) cab.append(el("span", `pill ${r.severity}`, r.severity));
      if (r.mitre_technique) cab.append(el("span", "pill tec", r.mitre_technique));
      if (r.mitre_tactic) cab.append(el("span", "pill", r.mitre_tactic));
      n.append(cab);
      const det = el("div", "meta");
      det.append(el("span", null, `confianza ${r.confidence}`));
      if (r.match_count > 1) det.append(el("span", null, `${r.match_count} coincidencias en la ventana`));
      n.append(det);
      b2.append(n);
    }
  } else {
    b2.append(el("p", "nota-metodo", "Ninguna regla determinista coincidió."));
  }
  if (inc.tactics && inc.tactics.length) {
    const t = el("div", "meta");
    t.append(el("span", null, "Tácticas ATT&CK:"));
    for (const x of inc.tactics) t.append(el("span", "pill", x));
    b2.append(t);
  }
  d.append(b2);

  // --- Inteligencia de amenazas ---
  if (inc.cti && inc.cti.length) {
    const b3 = bloque("Coincidencias de inteligencia (CTI)");
    for (const c of inc.cti) {
      const n = el("div", "regla");
      n.append(el("b", null, c.indicator || c.value || "indicador"));
      const m = el("div", "meta");
      for (const k of ["type", "source", "confidence", "valid_until"]) {
        if (c[k] !== undefined && c[k] !== null) m.append(el("span", null, `${k}: ${c[k]}`));
      }
      n.append(m);
      b3.append(n);
    }
    d.append(b3);
  }

  // --- Narrativa ---
  const b4 = bloque("Explicación");
  b4.append(el("div", "narrativa", inc.narrative || "Sin narrativa."));
  const proc = el("p", "nota-metodo");
  // Que el analista sepa de dónde salió el texto que está leyendo. Un párrafo
  // generado por el respaldo determinista y otro escrito por un modelo tienen
  // valor probatorio distinto, y confundirlos es peor que no tener ninguno.
  if (inc.fallback_used) {
    proc.append("Generada por el respaldo determinista (estado del modelo: "
      + (inc.llm_status || "desconocido") + "). ");
    proc.append(el("span", "badge-fallback", "sin modelo"));
  } else {
    proc.textContent = `Generada con el modelo (llm_status: ${inc.llm_status || "desconocido"}).`;
  }
  b4.append(proc);
  d.append(b4);

  // --- Contexto recuperado ---
  if (inc.rag && inc.rag.length) {
    const b5 = bloque("Contexto recuperado (con procedencia)");
    for (const c of inc.rag) {
      const n = el("div", "regla");
      n.append(el("b", null, c.filename || c.source_uri));
      n.append(el("div", "meta", c.source_uri));
      n.append(el("div", "narrativa", c.excerpt));
      b5.append(n);
    }
    d.append(b5);
  }

  // --- Contramedidas ---
  if (inc.recommendations && inc.recommendations.length) {
    const b6 = bloque("Contramedidas propuestas");
    for (const r of inc.recommendations) {
      const n = el("div", "regla");
      const cab = el("div", "cab");
      cab.append(el("b", null, r.action_type || r.action || "acción"));
      if (r.target) cab.append(el("span", "pill", r.target));
      // El veredicto de gobernanza va en color: «requiere aprobación» y
      // «prohibida» no se pueden leer igual que «permitida».
      if (r.decision) {
        const tono = r.decision === "prohibited" ? "critical"
                   : r.decision === "requires_approval" ? "medium" : "low";
        cab.append(el("span", `pill ${tono}`, ETIQUETA_GOBERNANZA[r.decision] || r.decision));
      }
      if (r.priority !== undefined) cab.append(el("span", null, `prioridad ${r.priority}`));
      n.append(cab);
      if (r.reason) n.append(el("div", "narrativa", r.reason));
      if (r.explanation) n.append(el("p", "nota-metodo", r.explanation));
      b6.append(n);
    }
    b6.append(el("p", "nota-metodo",
      "Ninguna se ejecuta desde aquí: el panel propone y clasifica, la ejecución "
      + "exige aprobación humana fuera de esta interfaz."));
    d.append(b6);
  }

  // --- Evento crudo ---
  const b7 = bloque("Evento normalizado");
  b7.append(el("pre", "crudo mono", JSON.stringify(inc.raw_event, null, 2)));
  d.append(b7);

  // --- Acciones ---
  d.append(acciones(inc));

  // --- Cronología ---
  const b9 = bloque("Cronología de la investigación");
  const ul = el("ul", "crono");
  for (const e of inc.timeline || []) {
    const li = el("li", e.kind);
    li.append(el("div", null, e.text));
    li.append(el("div", "cuando", `${fecha(e.at)} · ${e.actor}`));
    ul.append(li);
  }
  b9.append(ul);
  b9.append(el("p", "nota-metodo",
    "Solo se añade; nada se sobrescribe. El estado actual es una comodidad de "
    + "consulta: la verdad está en esta lista."));
  d.append(b9);

  d.scrollTop = 0;
}

function acciones(inc) {
  const b = bloque("Acciones");
  if (!estado.puedeEscribir) {
    b.append(el("div", "solo-lectura",
      `Tu rol (${estado.quien.role}) puede leer incidentes pero no modificarlos. `
      + "Cambiar de estado, asignar o emitir un veredicto exige el permiso "
      + "incidents:write."));
    return b;
  }

  const fila = el("div", "acciones");

  const mio = el("button", null, "Asignármelo");
  mio.addEventListener("click", () => cambiar(inc.incident_id,
    { owner: estado.quien.display, state: inc.state === "new" ? "triaged" : undefined }));
  fila.append(mio);

  const sel = el("select");
  sel.append(opcion("", "Cambiar estado…"));
  for (const s of ["new", "triaged", "in_progress", "closed"]) {
    if (s !== inc.state) sel.append(opcion(s, ETIQUETA_ESTADO[s]));
  }

  // La resolución se pide en la propia página, no con un `prompt()`: un
  // diálogo nativo bloquea la pestaña entera —incluidas las peticiones en
  // vuelo— y deja al analista sin poder ni cancelar si algo va mal.
  const resolucion = el("select");
  resolucion.append(opcion("", "Motivo de cierre…"));
  for (const [v, t] of Object.entries(ETIQUETA_RESOLUCION)) resolucion.append(opcion(v, t));
  resolucion.hidden = true;

  const aplicar = el("button", null, "Aplicar");
  aplicar.hidden = true;

  sel.addEventListener("change", () => {
    const cerrando = sel.value === "closed";
    resolucion.hidden = !cerrando;
    aplicar.hidden = !sel.value;
    if (sel.value && !cerrando) {
      cambiar(inc.incident_id, { state: sel.value });
    }
  });
  aplicar.addEventListener("click", () => {
    if (sel.value !== "closed") return;
    if (!resolucion.value) { avisar("Elige un motivo de cierre.", true); return; }
    cambiar(inc.incident_id, { state: "closed", resolution: resolucion.value });
  });

  fila.append(sel, resolucion, aplicar);
  b.append(fila);

  // Nota
  const nota = el("textarea");
  nota.placeholder = "Anotar lo que has comprobado…";
  const filaNota = el("div", "acciones");
  const enviarNota = el("button", null, "Añadir nota");
  enviarNota.addEventListener("click", async () => {
    if (!nota.value.trim()) return;
    try {
      await api(`/incidents/${encodeURIComponent(inc.incident_id)}/notes`,
                { method: "POST", body: JSON.stringify({ text: nota.value.trim() }) });
      nota.value = "";
      avisar("Nota añadida.");
      abrirIncidente(inc.incident_id);
    } catch (e) { avisar(e.message, true); }
  });
  filaNota.append(nota, enviarNota);
  b.append(filaNota);

  // Veredicto HITL. El motivo se escribe aquí y se sella con la decisión.
  const filaVeredicto = el("div", "acciones");
  const motivo = el("input");
  motivo.placeholder = "Motivo del veredicto (queda sellado con la decisión)";
  motivo.style.flex = "1 1 240px";
  filaVeredicto.append(el("span", null, "Veredicto:"), motivo);
  for (const [clave, rotulo] of [["TRUE_POSITIVE", "Verdadero positivo"],
                                 ["FALSE_POSITIVE", "Falso positivo"],
                                 ["BENIGN", "Benigno"],
                                 ["UNCERTAIN", "Dudoso"]]) {
    const bt = el("button", clave === "TRUE_POSITIVE" ? "primario" : null, rotulo);
    bt.addEventListener("click", () => decidir(inc.incident_id, clave, motivo.value));
    filaVeredicto.append(bt);
  }
  b.append(filaVeredicto);
  b.append(el("p", "nota-metodo",
    "El veredicto se sella con la evidencia que tienes delante y alimenta el "
    + "mismo almacén de decisiones que la CLI. Un cambio posterior en las reglas "
    + "no puede reescribir lo que viste."));
  return b;
}

async function cambiar(id, cambio) {
  try {
    const inc = await api("/incidents/" + encodeURIComponent(id),
                          { method: "PATCH", body: JSON.stringify(cambio) });
    pintarDetalle(inc);
    await Promise.all([cargarCifras(), cargarLista()]);
    avisar("Incidente actualizado.");
  } catch (e) { avisar(e.message, true); }
}

async function decidir(id, decision, motivo) {
  try {
    const r = await api(`/incidents/${encodeURIComponent(id)}/decision`, {
      method: "POST",
      body: JSON.stringify({ decision, reason: (motivo || "").trim(),
                             confidence: 1.0, close: true }),
    });
    avisar(r.close_note || "Veredicto registrado.");
    if (r.incident) pintarDetalle(r.incident);
    await Promise.all([cargarCifras(), cargarLista()]);
  } catch (e) { avisar(e.message, true); }
}

/* --- eventos de la interfaz ------------------------------------------ */
let temporizador;
$("#buscar").addEventListener("input", () => {
  clearTimeout(temporizador);
  temporizador = setTimeout(cargarLista, 250);
});
for (const sel of ["#f-estado", "#f-severidad", "#f-mios", "#f-sin-duenno"]) {
  $(sel).addEventListener("change", cargarLista);
}
$("#refrescar").addEventListener("click", async () => {
  await Promise.all([cargarSalud(), cargarCifras(), cargarLista()]);
  avisar("Actualizado.");
});

/* Si ya hay token en la pestaña, se entra directamente. */
if (token()) {
  arrancar().catch(() => cerrarSesion(false));
}
