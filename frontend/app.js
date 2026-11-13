/**
 * Lógica de Interfaz Reactiva con Control Estricto de Nivel de Acceso (RBAC + RLS)
 * Plataforma de Seguimiento Psicológico y Evaluación Terapéutica (PsychoTrack DB)
 * Materia: Administración de Bases de Datos - CUCEI, Universidad de Guadalajara
 * Autor: Galvez Arceo Miguel Angel (Código: 220537132)
 */

let estadoSesion = {
  autenticado: false,
  id_terapeuta: null,
  nombre_completo: null,
  cedula_profesional: null,
  especialidad_clinica: null,
  rol_activo: null,
  expediente_actual: "EXP-2026-1084",
  paciente_actual: "PAC-2026-042",
  pacientes_asignados_rls: []
};

const TODAS_LAS_SECCIONES = [
  "vista-login",
  "vista-terapeuta",
  "vista-sesion",
  "vista-dba",
  "vista-supervisor",
  "vista-recepcion",
  "vista-auditor",
  "vista-paciente"
];

function mostrarToast(titulo, mensaje, tipo = "info") {
  const container = document.getElementById("toast-container");
  const colores = {
    info: "bg-slate-900 border-blue-500 text-white",
    success: "bg-emerald-950 border-emerald-500 text-emerald-50",
    danger: "bg-red-950 border-red-500 text-red-50"
  };
  container.innerHTML = `
    <div class="p-4 rounded-xl shadow-2xl border-l-4 ${colores[tipo] || colores.info} flex items-start gap-3">
      <i class="fa-solid ${tipo === "danger" ? "fa-triangle-exclamation text-red-400" : "fa-circle-check text-emerald-400"} mt-0.5"></i>
      <div class="text-xs space-y-1">
        <p class="font-bold">${titulo}</p>
        <p class="opacity-90 leading-relaxed">${mensaje}</p>
      </div>
    </div>
  `;
  container.classList.remove("hidden");
  setTimeout(() => {
    container.classList.add("hidden");
  }, 5500);
}

/**
 * Controla qué vista puede mostrarse según el rol autenticado (Principio de Menor Privilegio)
 */
function mostrarVistaSegura(seccionId) {
  if (seccionId !== "vista-login" && !estadoSesion.autenticado) {
    seccionId = "vista-login";
  }

  // Validar que el rol autenticado tenga permiso sobre esa vista
  if (estadoSesion.autenticado && seccionId !== "vista-login") {
    const mapaPermisosVista = {
      rol_terapeuta: ["vista-terapeuta", "vista-sesion"],
      rol_paciente: ["vista-paciente"],
      rol_dba_admin: ["vista-dba"],
      rol_supervisor: ["vista-supervisor"],
      rol_recepcion: ["vista-recepcion"],
      rol_auditor: ["vista-auditor"]
    };
    const permitidas = mapaPermisosVista[estadoSesion.rol_activo] || [];
    if (!permitidas.includes(seccionId)) {
      mostrarToast(
        "Acceso Denegado por RBAC",
        `El rol activo (${estadoSesion.rol_activo}) no tiene privilegios para acceder a esta vista.`,
        "danger"
      );
      return;
    }
  }

  TODAS_LAS_SECCIONES.forEach((id) => {
    const el = document.getElementById(id);
    if (el) {
      if (id === seccionId) {
        el.classList.remove("hidden");
      } else {
        el.classList.add("hidden");
      }
    }
  });
}

function cerrarSesionRBAC() {
  estadoSesion = {
    autenticado: false,
    id_terapeuta: null,
    nombre_completo: null,
    cedula_profesional: null,
    especialidad_clinica: null,
    rol_activo: null,
    expediente_actual: "EXP-2026-1084",
    paciente_actual: "PAC-2026-042",
    pacientes_asignados_rls: []
  };
  const feedback = document.getElementById("login-hash-feedback");
  if (feedback) feedback.classList.add("hidden");
  mostrarVistaSegura("vista-login");
  mostrarToast("Sesión Cerrada", "Se han liberado los permisos RBAC de la sesión activa.", "info");
}

async function ejecutarLoginRBAC(event) {
  event.preventDefault();
  const identificador = document.getElementById("login-identificador").value.trim();
  const password = document.getElementById("login-password").value;

  try {
    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ identificador, password })
    });
    const data = await res.json();
    if (!res.ok) {
      mostrarToast("Error de Autenticación RBAC", data.detail || "Credenciales inválidas", "danger");
      return;
    }

    estadoSesion.autenticado = true;
    estadoSesion.id_terapeuta = data.id_terapeuta;
    estadoSesion.nombre_completo = data.nombre_completo;
    estadoSesion.cedula_profesional = data.cedula_profesional;
    estadoSesion.especialidad_clinica = data.especialidad_clinica;
    estadoSesion.rol_activo = data.rol_activo_sesion;

    const feedback = document.getElementById("login-hash-feedback");
    feedback.innerHTML = `
      <div><strong>✓ Hash SHA-256 Verificado:</strong> ${data.hash_sha256_verificado}</div>
      <div><strong>✓ Salt Aplicado:</strong> ${data.salt_aplicado} | <strong>Rol RBAC:</strong> ${data.rol_activo_sesion}</div>
    `;
    feedback.classList.remove("hidden");

    mostrarToast(
      `Acceso Autorizado (${data.rol_activo_sesion})`,
      `Bienvenido(a) ${data.nombre_completo}. `,
      "success"
    );

    if (data.rol_activo_sesion === "rol_terapeuta") {
      await cargarDashboardTerapeuta(data.id_terapeuta);
      mostrarVistaSegura("vista-terapeuta");
    } else if (data.rol_activo_sesion === "rol_dba_admin") {
      await cargarConsolaDBA();
      mostrarVistaSegura("vista-dba");
    } else if (data.rol_activo_sesion === "rol_supervisor") {
      document.getElementById("supervisor-subtitulo").textContent =
        `${data.nombre_completo} • Céd. Prof. ${data.cedula_profesional} • ${data.especialidad_clinica}`;
      await cargarVistasRolesExtra();
      mostrarVistaSegura("vista-supervisor");
    } else if (data.rol_activo_sesion === "rol_recepcion") {
      document.getElementById("recepcion-subtitulo").textContent =
        `${data.nombre_completo} • Céd. Prof. ${data.cedula_profesional} • ${data.especialidad_clinica}`;
      await cargarVistasRolesExtra();
      mostrarVistaSegura("vista-recepcion");
    } else if (data.rol_activo_sesion === "rol_auditor") {
      document.getElementById("auditor-subtitulo").textContent =
        `${data.nombre_completo} • Céd. Prof. ${data.cedula_profesional} • ${data.especialidad_clinica}`;
      await cargarVistasRolesExtra();
      mostrarVistaSegura("vista-auditor");
    } else if (data.rol_activo_sesion === "rol_paciente") {
      estadoSesion.paciente_actual = data.id_paciente;
      await cargarPortalPaciente(data.id_paciente);
      mostrarVistaSegura("vista-paciente");
    }
  } catch (err) {
    mostrarToast("Error de Conexión", err.message, "danger");
  }
}

async function cargarDashboardTerapeuta(idTerapeuta) {
  const res = await fetch(`/api/terapeuta/dashboard?id_terapeuta=${encodeURIComponent(idTerapeuta)}`);
  const data = await res.json();

  estadoSesion.pacientes_asignados_rls = data.pacientes || [];

  document.getElementById("rls-current-user-badge").textContent = "CURRENT_USER";
  document.getElementById("terapeuta-subtitulo").textContent =
    `${data.terapeuta.nombre_completo} • Céd. Prof. ${data.terapeuta.cedula_profesional} • Especialidad: ${data.terapeuta.especialidad_clinica}`;

  document.getElementById("kpi-mis-pacientes").textContent = data.kpis.mis_pacientes_rls;
  document.getElementById("kpi-rls-sub").textContent = "Pacientes en seguimiento";
  document.getElementById("kpi-sesiones-hoy").textContent = data.kpis.sesiones_hoy_total;
  document.getElementById("kpi-sesiones-sub").textContent =
    `${data.kpis.sesiones_completadas} completadas • ${data.kpis.sesiones_pendientes} pendientes`;
  document.getElementById("kpi-promedio-delta").textContent = data.kpis.promedio_delta_bdi;
  document.getElementById("kpi-alertas-activas").textContent =
    `${data.kpis.alertas_activas_count} ${data.kpis.alertas_activas_count === 1 ? "Activa" : "Activas"}`;

  // Poblar selector de expedientes en Mockup 3 únicamente con los pacientes asignados por RLS a este terapeuta
  const selectExp = document.getElementById("select-expediente-activo");
  selectExp.innerHTML = estadoSesion.pacientes_asignados_rls.map((p) =>
    `<option value="${p.id_paciente}">${p.id_expediente} • Paciente: ${p.id_paciente}</option>`
  ).join("");

  const bannerAlerta = document.getElementById("banner-alerta-trigger");
  if (data.alerta_destacada) {
    bannerAlerta.classList.remove("hidden");
    document.getElementById("banner-alerta-mensaje").innerHTML = data.alerta_destacada.mensaje_alerta;
    document.getElementById("btn-revisar-alerta").setAttribute(
      "onclick",
      `abrirRegistroSesion('${data.alerta_destacada.id_paciente}')`
    );
  } else {
    bannerAlerta.classList.add("hidden");
  }

  const tbody = document.getElementById("tbody-pacientes-rls");
  tbody.innerHTML = data.pacientes.map((p) => {
    const filaRoja = p.alerta_activa ? "bg-red-50/40" : "hover:bg-slate-50";
    const testClase = p.alerta_activa
      ? "font-bold text-red-600"
      : p.ultimo_test_severidad === "Leve" || p.ultimo_test_severidad === "Mínimo"
      ? "font-semibold text-emerald-700"
      : "text-slate-700";

    const deltaClase = p.delta_tipo === "riesgo"
      ? "font-bold text-red-600"
      : "font-bold text-emerald-600";

    const botonAccion = p.alerta_activa
      ? `<button onclick="abrirRegistroSesion('${p.id_paciente}')" class="px-3 py-1.5 rounded-md bg-red-600 hover:bg-red-700 text-white text-xs font-bold shadow-sm transition">Atender Alerta</button>`
      : `<button onclick="abrirRegistroSesion('${p.id_paciente}')" class="text-xs font-bold text-blue-600 hover:text-blue-800 hover:underline">Ver Expediente</button>`;

    return `
      <tr class="${filaRoja} transition">
        <th class="py-4 px-5 font-mono text-xs font-bold text-slate-600">${p.id_paciente}</th>
        <td data-label="Nombre / Referencia" class="py-4 px-4 font-semibold text-slate-900">${p.iniciales_referencia}</td>
        <td data-label="Diagnóstico (DSM-5)" class="py-4 px-4 text-slate-600">${p.diagnostico_dsm}</td>
        <td data-label="Sesiones" class="py-4 px-4 font-mono text-xs font-semibold text-slate-700">${p.sesiones_progreso}</td>
        <td data-label="Último Test" class="py-4 px-4 ${testClase}">${p.ultimo_test}</td>
        <td data-label="Delta Psicométrico" class="py-4 px-4 ${deltaClase}">${p.delta_psicometrico}</td>
        <td data-label="Acción" class="py-4 px-5 text-right">${botonAccion}</td>
      </tr>
    `;
  }).join("");
}

function toggleAgendaTerapeuta() {
  const panel = document.getElementById("panel-agenda-terapeuta");
  panel.classList.toggle("hidden");
}

function abrirModalNuevaSesion() {
  const primerPaciente = estadoSesion.pacientes_asignados_rls.find((p) => p.alerta_activa)
    || estadoSesion.pacientes_asignados_rls[0];
  if (primerPaciente) {
    abrirRegistroSesion(primerPaciente.id_paciente);
  }
}

async function abrirRegistroSesion(idPaciente) {
  estadoSesion.paciente_actual = idPaciente;
  const sel = document.getElementById("select-expediente-activo");
  if ([...sel.options].some((o) => o.value === idPaciente)) {
    sel.value = idPaciente;
  }
  await cargarExpedienteEnMockup3(idPaciente);
  mostrarVistaSegura("vista-sesion");
}

async function cargarExpedienteEnMockup3(idPaciente) {
  estadoSesion.paciente_actual = idPaciente;
  const res = await fetch(`/api/expediente/${encodeURIComponent(idPaciente)}?rol=${encodeURIComponent(estadoSesion.rol_activo || "rol_terapeuta")}`);
  if (!res.ok) return;
  const exp = await res.json();

  estadoSesion.expediente_actual = exp.id_expediente;

  document.getElementById("titulo-numero-sesion").textContent = `Sesión Terapéutica #${exp.sesion_actual_numero}`;
  document.getElementById("input-tecnica").value = exp.ultima_sesion_tecnica;
  document.getElementById("input-cumplimiento").value = exp.ultima_sesion_cumplimiento;
  document.getElementById("input-notas-clinicas").value = exp.ultima_sesion_nota;
  document.getElementById("preview-ciphertext").textContent =
    `Columna cifrada en PostgreSQL (pgcrypto AES-256): ${exp.motivo_consulta_ciphertext}`;

  const r1 = document.querySelector(`input[name="item_1"][value="${exp.item_1_actual}"]`);
  if (r1) r1.checked = true;
  const r9 = document.querySelector(`input[name="item_9"][value="${exp.item_9_actual}"]`);
  if (r9) r9.checked = true;

  const resto = Math.max(0, exp.puntaje_actual - exp.item_1_actual - exp.item_9_actual);
  document.getElementById("input-resto-reactivos").value = resto;

  document.getElementById("diag-codigo-dsm").textContent = `${exp.codigo_diagnostico} (DSM-5)`;
  document.getElementById("diag-nombre-trastorno").textContent =
    exp.codigo_diagnostico === "F32.2"
      ? "Trastorno Depresivo Mayor, Episodio Único, Grave"
      : exp.nombre_trastorno;
  document.getElementById("diag-plan-resumen").textContent =
    exp.plan ? exp.plan.objetivos_terapeuticos : "Plan de Intervención: 10 sesiones estimadas con enfoque TCC.";

  const histContainer = document.getElementById("lista-historial-sesiones");
  histContainer.innerHTML = exp.historial_sesiones.map((s) => `
    <div class="p-3 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
      <div class="flex items-center justify-between text-[11px] font-bold text-slate-700">
        <span>Sesión #${s.numero_sesion} • ${s.tecnica_implementada}</span>
        <span class="text-slate-400 font-mono">${s.fecha_sesion}</span>
      </div>
      <p class="text-slate-600 leading-relaxed">${s.notas_descifradas}</p>
      <p class="text-[10px] font-mono text-emerald-700 truncate">Cifrado en disco: ${s.notas_ciphertext_preview}</p>
    </div>
  `).join("");

  await recalcularPuntajeYTriggerEnVivo();
}

async function recalcularPuntajeYTriggerEnVivo() {
  const item1 = parseInt(document.querySelector('input[name="item_1"]:checked')?.value || "0", 10);
  const item9 = parseInt(document.querySelector('input[name="item_9"]:checked')?.value || "0", 10);
  const resto = parseInt(document.getElementById("input-resto-reactivos").value || "0", 10);
  const puntajeActual = Math.min(63, Math.max(0, item1 + item9 + resto));

  const contItem9 = document.getElementById("contenedor-item-9");
  const badgeItem9 = document.getElementById("badge-trigger-item9");
  if (item9 >= 2) {
    contItem9.className = "p-4 rounded-xl bg-red-50/80 border-2 border-red-400 space-y-3 transition";
    badgeItem9.className = "inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-red-100 text-red-700 border border-red-300";
    badgeItem9.innerHTML = `<i class="fa-solid fa-bolt"></i> TRIGGER ACTIVO`;
  } else {
    contItem9.className = "p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-3 transition";
    badgeItem9.className = "inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-emerald-100 text-emerald-700 border border-emerald-300";
    badgeItem9.innerHTML = `<i class="fa-solid fa-shield-check"></i> SIN RIESGO CRÍTICO`;
  }

  const res = await fetch("/api/psicometria/calcular-delta", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      id_expediente: estadoSesion.expediente_actual,
      id_escala: "BDI-II",
      puntaje_actual: puntajeActual
    })
  });
  if (!res.ok) return;
  const sp = await res.json();

  document.getElementById("sp-puntaje-inicial").textContent = `${sp.puntaje_inicial} pts (Moderado)`;
  const elActual = document.getElementById("sp-puntaje-actual");
  elActual.textContent = `${sp.puntaje_actual} pts (${sp.baremo_severidad})`;
  elActual.className = sp.delta > 0 ? "font-bold text-red-600" : "font-bold text-emerald-600";

  const elDelta = document.getElementById("sp-delta-badge");
  elDelta.textContent = sp.delta_formateado;
  elDelta.className = sp.delta > 0
    ? "px-2.5 py-1 rounded-md text-xs font-bold bg-red-100 text-red-700 border border-red-200"
    : "px-2.5 py-1 rounded-md text-xs font-bold bg-emerald-100 text-emerald-700 border border-emerald-200";
}

async function guardarSesionYDispararTriggers(event) {
  event.preventDefault();
  const item1 = parseInt(document.querySelector('input[name="item_1"]:checked')?.value || "0", 10);
  const item9 = parseInt(document.querySelector('input[name="item_9"]:checked')?.value || "0", 10);
  const resto = parseInt(document.getElementById("input-resto-reactivos").value || "0", 10);
  const puntajeBruto = Math.min(63, Math.max(0, item1 + item9 + resto));

  const payload = {
    id_expediente: estadoSesion.expediente_actual,
    id_paciente: estadoSesion.paciente_actual,
    id_terapeuta: estadoSesion.id_terapeuta,
    tecnica_implementada: document.getElementById("input-tecnica").value,
    cumplimiento_tareas: document.getElementById("input-cumplimiento").value,
    notas_clinicas: document.getElementById("input-notas-clinicas").value,
    id_escala: "BDI-II",
    puntuacion_bruta: puntajeBruto,
    item_1_tristeza: item1,
    item_9_ideacion_riesgo: item9
  };

  const res = await fetch("/api/sesion/registrar", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  const data = await res.json();

  if (!res.ok) {
    mostrarToast("Violación de Integridad / CHECK", data.detail, "danger");
    return;
  }

  if (data.trigger_disparado) {
    mostrarToast(
      "¡ALERTA POR TRIGGER BEFORE INSERT DISPARADA!",
      `${data.mensaje_trigger} | Delta calculado: ${data.calculo_sp_delta.delta_formateado}`,
      "danger"
    );
  } else {
    mostrarToast(
      "Sesión Cifrada y Registrada (ACID COMMIT)",
      `Sesión #${data.numero_sesion} guardada con pgcrypto AES-256. Delta: ${data.calculo_sp_delta.delta_formateado}`,
      "success"
    );
  }

  await cargarDashboardTerapeuta(estadoSesion.id_terapeuta);
  await cargarExpedienteEnMockup3(estadoSesion.paciente_actual);
}

async function cargarConsolaDBA() {
  const res = await fetch("/api/dba/consola");
  const data = await res.json();

  document.getElementById("dba-motor-subtitulo").textContent = data.motor_info;
  document.getElementById("dba-ultimo-backup").textContent = data.ultimo_respaldo_completo;

  const tbody = document.getElementById("tbody-bitacora-drp");
  tbody.innerHTML = data.bitacora_respaldos.map((b) => `
    <tr class="hover:bg-slate-50">
      <th class="py-3 px-4 font-mono font-bold text-slate-600">#${b.id_respaldo}</th>
      <td data-label="Tipo de Respaldo" class="py-3 px-4 font-semibold text-slate-900">${b.tipo_respaldo}</td>
      <td data-label="Fecha / Ventana" class="py-3 px-4 text-slate-600">${b.fecha_ejecucion}</td>
      <td data-label="Ruta Destino" class="py-3 px-4 font-mono text-[11px] text-blue-700">${b.ruta_destino}</td>
      <td data-label="Tamaño" class="py-3 px-4 font-mono text-slate-700">${b.tamano_mb} MB</td>
      <td data-label="Hash SHA-256" class="py-3 px-4 font-mono text-[11px] text-slate-500">${b.hash_verificacion_sha256.slice(0, 18)}...</td>
      <td data-label="Estado" class="py-3 px-4">
        <span class="px-2 py-0.5 rounded-full text-[11px] font-bold bg-emerald-100 text-emerald-700 border border-emerald-200">
          ${b.estado_respaldo}
        </span>
      </td>
    </tr>
  `).join("");
}

async function dispararBackupManualDBA() {
  const res = await fetch("/api/dba/backup-manual", { method: "POST" });
  const data = await res.json();
  mostrarToast(
    "Backup Manual Consistente Ejecutado (DRP)",
    `Archivo: ${data.ruta_destino} | SHA-256: ${data.hash_sha256.slice(0, 20)}... | RPO=${data.rpo}`,
    "success"
  );
  await cargarConsolaDBA();
}

function mostrarModalBitacoraWAL() {
  const panel = document.getElementById("panel-bitacora-wal");
  panel.scrollIntoView({ behavior: "smooth" });
  mostrarToast(
    "Sincronización Write-Ahead Logging (WAL) Activa",
    "Todos los segmentos WAL están sincronizados hacia el repositorio secundario aislado (Air-Gapped) cumpliendo RPO <= 1.0 Hora.",
    "info"
  );
}

async function cargarVistasRolesExtra() {
  const res = await fetch("/api/roles/vistas-adicionales");
  const data = await res.json();

  // 1. Supervisor Clínico
  const contAlertas = document.getElementById("contenedor-alertas-supervisor");
  contAlertas.innerHTML = data.supervisor.alertas.map((a) => `
    <div class="p-4 rounded-xl border ${a.estado_alerta === "Activa" ? "bg-red-50 border-red-300" : "bg-emerald-50 border-emerald-200"} flex flex-wrap items-center justify-between gap-4">
      <div class="space-y-1 text-xs">
        <div class="flex items-center gap-2">
          <span class="px-2 py-0.5 rounded font-bold uppercase text-[10px] ${a.estado_alerta === "Activa" ? "bg-red-600 text-white" : "bg-emerald-600 text-white"}">
            ${a.estado_alerta}
          </span>
          <span class="font-bold text-slate-900">${a.tipo_reactivo} (Puntaje Reactivo: ${a.puntuacion_reactivo}/3 • Total BDI-II: ${a.puntuacion_total_test} pts)</span>
        </div>
        <p class="text-slate-700">${a.mensaje_alerta}</p>
        <p class="text-[11px] text-slate-500">Terapeuta responsable: <strong>${a.terapeuta_nombre}</strong> • Canal: ${a.canal_notificacion}</p>
      </div>
      ${a.estado_alerta === "Activa" ? `
        <button onclick="atenderAlertaComoSupervisor(${a.id_alerta})"
          class="px-3.5 py-2 rounded-lg bg-purple-700 hover:bg-purple-800 text-white text-xs font-bold shadow-sm transition">
          Atender Caso
        </button>
      ` : `<span class="text-xs font-semibold text-emerald-700">✓ Protocolo validado (${a.fecha_atencion || "Hoy"})</span>`}
    </div>
  `).join("");

  document.getElementById("tbody-supervisor-planes").innerHTML = data.supervisor.planes.map((pl) => `
    <tr class="hover:bg-slate-50">
      <th class="py-3 px-4 font-mono font-bold text-blue-700">${pl.id_expediente}</th>
      <td data-label="Consultante" class="py-3 px-4 font-semibold text-slate-800">${pl.iniciales_referencia}</td>
      <td data-label="Terapeuta Titular" class="py-3 px-4 text-slate-600">${pl.terapeuta_nombre}</td>
      <td data-label="Diagnóstico DSM-5" class="py-3 px-4 text-slate-700">${pl.codigo_diagnostico} - ${pl.nombre_trastorno}</td>
      <td data-label="Enfoque y Objetivos" class="py-3 px-4 text-slate-600 max-w-xs">${pl.objetivos_terapeuticos}</td>
      <td data-label="Avance" class="py-3 px-4 font-mono font-bold">${pl.sesiones_completadas}/${pl.sesiones_estimadas}</td>
      <td data-label="Nivel de Riesgo" class="py-3 px-4">
        <span class="px-2 py-0.5 rounded text-[11px] font-bold ${pl.nivel_riesgo_actual.includes("Alto") ? "bg-red-100 text-red-700" : "bg-emerald-100 text-emerald-700"}">
          ${pl.nivel_riesgo_actual}
        </span>
      </td>
    </tr>
  `).join("");

  // 2. Recepción y Citas
  document.getElementById("tbody-recepcion-agenda").innerHTML = data.recepcion.agenda.map((ag) => `
    <tr class="hover:bg-slate-50">
      <th class="py-3 px-4 font-mono font-bold text-slate-600">#${ag.id_sesion} (Sesión ${ag.numero_sesion})</th>
      <td data-label="Fecha / Hora" class="py-3 px-4 font-mono text-slate-800">${ag.fecha_sesion}</td>
      <td data-label="Paciente" class="py-3 px-4 font-semibold text-slate-900">${ag.id_paciente} • ${ag.iniciales_referencia}</td>
      <td data-label="Contacto" class="py-3 px-4 text-slate-600">${ag.telefono_contacto} <span class="text-slate-400">(${ag.contacto_emergencia_nombre})</span></td>
      <td data-label="Terapeuta" class="py-3 px-4 text-slate-700">${ag.terapeuta_nombre}</td>
      <td data-label="Diagnóstico / Notas" class="py-3 px-4">
        <span class="px-2 py-0.5 rounded bg-red-50 text-red-700 border border-red-200 font-mono text-[10px] font-semibold">
          Privado
        </span>
      </td>
      <td data-label="Estado de Cita" class="py-3 px-4">
        <select onchange="actualizarEstadoCitaRecepcion(${ag.id_sesion}, this.value, '${ag.fecha_sesion}')"
          class="px-2.5 py-1 rounded border border-slate-300 bg-white text-xs font-semibold text-slate-800">
          <option value="Programada" ${ag.estado_cita === "Programada" ? "selected" : ""}>Programada</option>
          <option value="Completada" ${ag.estado_cita === "Completada" ? "selected" : ""}>Completada</option>
          <option value="Cancelada" ${ag.estado_cita === "Cancelada" ? "selected" : ""}>Cancelada</option>
          <option value="Inasistencia" ${ag.estado_cita === "Inasistencia" ? "selected" : ""}>Inasistencia</option>
        </select>
      </td>
    </tr>
  `).join("");

  // 3. Auditoría y Dirección
  document.getElementById("aud-desercion").textContent = data.auditoria.tasa_desercion_global;
  document.getElementById("aud-volumen").textContent = `${data.auditoria.total_consultas_semestre} Consultas Registradas`;
  document.getElementById("aud-delta").textContent = data.auditoria.promedio_global_delta;

  document.getElementById("tbody-auditor-indicadores").innerHTML = data.auditoria.indicadores.map((ind) => `
    <tr class="hover:bg-slate-50">
      <th class="py-3 px-4 font-mono font-bold text-slate-800">${ind.codigo_diagnostico}</th>
      <td data-label="Trastorno Clínico" class="py-3 px-4 font-semibold text-slate-900">${ind.nombre_trastorno}</td>
      <td data-label="Expedientes Anonimizados" class="py-3 px-4 font-mono">${ind.total_expedientes} casos</td>
      <td data-label="Volumen Consultas" class="py-3 px-4 font-mono">${ind.volumen_consultas} sesiones</td>
      <td data-label="Media Puntaje Bruto" class="py-3 px-4 font-mono">${ind.media_psicometrica ?? "N/A"} pts</td>
      <td data-label="Promedio Delta" class="py-3 px-4 font-mono font-bold ${ind.media_delta_mejoria < 0 ? "text-emerald-600" : "text-amber-600"}">
        ${ind.media_delta_mejoria !== null ? `${ind.media_delta_mejoria > 0 ? "+" : ""}${ind.media_delta_mejoria} pts` : "Sin datos"}
      </td>
    </tr>
  `).join("");
}

async function atenderAlertaComoSupervisor(idAlerta) {
  await fetch("/api/supervisor/atender-alerta", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      id_alerta: idAlerta,
      notas_resolucion: "Supervisión clínica enterada. Se activó protocolo de acompañamiento universitario e intervención en crisis."
    })
  });
  mostrarToast("Alerta Atendida por Supervisor Clínico", `Se actualizó el estado de la alerta #${idAlerta} en la base de datos.`, "success");
  await cargarVistasRolesExtra();
}

async function actualizarEstadoCitaRecepcion(idSesion, nuevoEstado, fechaActual) {
  await fetch("/api/recepcion/actualizar-cita", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      id_sesion: idSesion,
      estado_cita: nuevoEstado,
      fecha_sesion: fechaActual
    })
  });
  mostrarToast("Agenda Actualizada (Rol_Recepcion_Citas)", `Cita #${idSesion} actualizada a estado '${nuevoEstado}' sin acceso a notas clínicas.`, "info");
}

async function cargarPortalPaciente(idPaciente) {
  const res = await fetch(`/api/paciente/portal/${encodeURIComponent(idPaciente)}`);
  if (!res.ok) return;
  const data = await res.json();

  document.getElementById("pac-id-badge").textContent = data.paciente.id_paciente;
  document.getElementById("pac-subtitulo").textContent =
    `${data.paciente.nombre_completo} (${data.paciente.edad} años, ${data.paciente.ocupacion_escolaridad}) • Expediente: ${data.paciente.id_expediente}`;

  document.getElementById("pac-kpi-terapeuta").textContent = data.paciente.terapeuta_nombre;
  document.getElementById("pac-kpi-especialidad").textContent = data.paciente.especialidad_clinica;

  if (data.plan) {
    document.getElementById("pac-kpi-sesiones").textContent =
      `${data.plan.sesiones_completadas} / ${data.plan.sesiones_estimadas}`;
    document.getElementById("pac-enfoque-badge").textContent = data.plan.enfoque_clinico;
    document.getElementById("pac-objetivos-texto").textContent = data.plan.objetivos_terapeuticos;
  }

  const resPsico = data.resumen_psicometrico;
  document.getElementById("pac-kpi-ultimo-test").textContent =
    `${resPsico.escala} (${resPsico.puntaje_actual} pts)`;
  document.getElementById("pac-kpi-baremo").textContent = `Nivel: ${resPsico.baremo_actual}`;

  const elDelta = document.getElementById("pac-kpi-delta");
  const deltaVal = resPsico.delta_cambio;
  elDelta.textContent = `${deltaVal > 0 ? "+" : ""}${deltaVal} pts`;
  elDelta.className = deltaVal <= 0
    ? "text-xl font-extrabold text-emerald-600 mt-1"
    : "text-xl font-extrabold text-amber-600 mt-1";

  document.getElementById("pac-select-escala").value = resPsico.escala;

  const tbody = document.getElementById("tbody-paciente-sesiones");
  tbody.innerHTML = data.sesiones.map((s) => `
    <tr class="hover:bg-slate-50">
      <th class="py-3 px-4 font-mono font-bold text-slate-700">#${s.numero_sesion}</th>
      <td data-label="Fecha / Horario" class="py-3 px-4 font-mono text-slate-600">${s.fecha_sesion}</td>
      <td data-label="Actividad / Técnica" class="py-3 px-4 font-semibold text-slate-900">${s.tecnica_implementada}</td>
      <td data-label="Avance de Tarea" class="py-3 px-4 text-slate-700">${s.cumplimiento_tareas}</td>
      <td data-label="Estado" class="py-3 px-4">
        <span class="px-2 py-0.5 rounded-full text-[11px] font-bold ${
          s.estado_cita === "Completada"
            ? "bg-emerald-100 text-emerald-700 border border-emerald-200"
            : "bg-blue-100 text-blue-700 border border-blue-200"
        }">
          ${s.estado_cita}
        </span>
      </td>
    </tr>
  `).join("");
}

async function enviarAutoevaluacionPaciente(event) {
  event.preventDefault();
  const payload = {
    id_paciente: estadoSesion.paciente_actual,
    cumplimiento_tareas: document.getElementById("pac-select-tarea").value,
    id_escala: document.getElementById("pac-select-escala").value,
    item_1_tristeza: parseInt(document.getElementById("pac-item-1").value, 10),
    item_9_ideacion_riesgo: parseInt(document.getElementById("pac-item-9").value, 10),
    puntaje_resto: parseInt(document.getElementById("pac-resto-items").value, 10)
  };

  const res = await fetch("/api/paciente/autoevaluacion", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  const data = await res.json();
  if (!res.ok) {
    mostrarToast("Error al enviar autoevaluación", data.detail, "danger");
    return;
  }

  mostrarToast(
    "Autoevaluación Registrada en su Expediente",
    `Se actualizó su progreso longitudinal (${data.calculo_sp_delta.delta_formateado}) para su terapeuta titular.`,
    "success"
  );
  await cargarPortalPaciente(estadoSesion.paciente_actual);
}

document.addEventListener("DOMContentLoaded", () => {
  mostrarVistaSegura("vista-login");
});

function autocompletarDemo(usuarioId) {
  document.getElementById("login-identificador").value = usuarioId;
  document.getElementById("login-password").value = "Psycho2026!";
  mostrarToast("Credenciales Cargadas", `Listo para iniciar sesión como ${usuarioId}.`, "info");
}

function filtrarPacientesEnVivo(texto) {
  const filtro = texto.toLowerCase().trim();
  const filas = document.querySelectorAll("#tbody-pacientes-rls tr");
  filas.forEach(fila => {
    const contenido = fila.innerText.toLowerCase();
    fila.style.display = contenido.includes(filtro) ? "" : "none";
  });
}
