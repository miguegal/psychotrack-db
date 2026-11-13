"""
Servidor Backend Principal (FastAPI + SQLAlchemy) para PsychoTrack DB
Plataforma de Seguimiento Psicológico y Evaluación Terapéutica
Materia: Administración de Bases de Datos - CUCEI, Universidad de Guadalajara
Autor: Galvez Arceo Miguel Angel (Código: 220537132)
"""

from pathlib import Path
from typing import Optional, Dict

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend.database import db_manager

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
SQL_DIR = BASE_DIR / "sql"

app = FastAPI(
    title="PsychoTrack DB - API Clínica y Administración de Bases de Datos",
    description=(
        "Plataforma de Seguimiento Psicológico y Evaluación Terapéutica con RBAC, "
        "Row-Level Security (RLS), Cifrado de Columnas (pgcrypto AES-256), "
        "Procedimientos Almacenados (Δ) y Disparadores Atómicos de Alerta por Riesgo."
    ),
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class LoginRequest(BaseModel):
    identificador: str = Field(..., examples=["TER-84920-GDL"])
    password: str = Field(..., examples=["Psycho2026!"])


class CalculoDeltaRequest(BaseModel):
    id_expediente: str = Field(..., examples=["EXP-2026-1084"])
    id_escala: str = Field(default="BDI-II")
    puntaje_actual: int = Field(..., ge=0, le=63)


class RegistroSesionTestRequest(BaseModel):
    id_expediente: str = Field(..., examples=["EXP-2026-1084"])
    id_paciente: str = Field(..., examples=["PAC-2026-042"])
    id_terapeuta: str = Field(default="TER-84920-GDL")
    tecnica_implementada: str = Field(default="Reestructuración Cognitiva y Registro de Pensamientos")
    cumplimiento_tareas: str = Field(default="Parcial (50%)")
    notas_clinicas: str = Field(...)
    id_escala: str = Field(default="BDI-II")
    puntuacion_bruta: int = Field(..., ge=0, le=63)
    item_1_tristeza: int = Field(..., ge=0, le=3)
    item_9_ideacion_riesgo: int = Field(..., ge=0, le=3)
    respuestas_adicionales: Optional[Dict[str, int]] = None


class AtenderAlertaRequest(BaseModel):
    id_alerta: int
    notas_resolucion: str


class ActualizarCitaRequest(BaseModel):
    id_sesion: int
    estado_cita: str
    fecha_sesion: str


class AutoevaluacionPacienteRequest(BaseModel):
    id_paciente: str = Field(..., examples=["PAC-2026-042"])
    cumplimiento_tareas: str = Field(default="Parcial (50%)")
    id_escala: str = Field(default="BDI-II")
    item_1_tristeza: int = Field(..., ge=0, le=3)
    item_9_ideacion_riesgo: int = Field(..., ge=0, le=3)
    puntaje_resto: int = Field(default=15, ge=0, le=57)


@app.post("/api/auth/login")
def api_login_rbac(payload: LoginRequest):
    resultado = db_manager.autenticar_usuario_rbac(
        identificador=payload.identificador,
        password_plano=payload.password,
        rol_solicitado=None
    )
    if not resultado["autenticado"]:
        raise HTTPException(status_code=401, detail=resultado["error"])
    return resultado


@app.get("/api/terapeuta/dashboard")
def api_dashboard_terapeuta(id_terapeuta: str = "TER-84920-GDL"):
    return db_manager.obtener_dashboard_terapeuta_rls(id_terapeuta_actual=id_terapeuta)


@app.get("/api/expediente/{id_paciente}")
def api_detalle_expediente(id_paciente: str, rol: str = "rol_terapeuta"):
    try:
        return db_manager.obtener_detalle_expediente_para_sesion(id_paciente=id_paciente, rol_actual=rol)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/api/psicometria/calcular-delta")
def api_calcular_delta_sp(payload: CalculoDeltaRequest):
    return db_manager.sp_calcular_delta_psicometrico(
        id_expediente=payload.id_expediente,
        id_escala=payload.id_escala,
        puntaje_actual=payload.puntaje_actual
    )


@app.post("/api/sesion/registrar")
def api_registrar_sesion_y_test(payload: RegistroSesionTestRequest):
    try:
        return db_manager.registrar_sesion_y_test_transaccional(
            id_expediente=payload.id_expediente,
            id_paciente=payload.id_paciente,
            id_terapeuta=payload.id_terapeuta,
            tecnica_implementada=payload.tecnica_implementada,
            cumplimiento_tareas=payload.cumplimiento_tareas,
            notas_clinicas=payload.notas_clinicas,
            id_escala=payload.id_escala,
            puntuacion_bruta=payload.puntuacion_bruta,
            item_1_tristeza=payload.item_1_tristeza,
            item_9_ideacion_riesgo=payload.item_9_ideacion_riesgo,
            respuestas_adicionales=payload.respuestas_adicionales
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/dba/consola")
def api_consola_dba():
    return db_manager.obtener_estado_consola_dba()


@app.post("/api/dba/backup-manual")
def api_disparar_backup_manual():
    return db_manager.ejecutar_backup_manual_dba()


@app.get("/api/roles/vistas-adicionales")
def api_vistas_supervisor_recepcion_auditor():
    return db_manager.obtener_vista_supervisor_rec_auditor()


@app.post("/api/supervisor/atender-alerta")
def api_atender_alerta(payload: AtenderAlertaRequest):
    return db_manager.atender_alerta_supervisor(
        id_alerta=payload.id_alerta,
        notas_resolucion=payload.notas_resolucion
    )


@app.post("/api/recepcion/actualizar-cita")
def api_actualizar_cita(payload: ActualizarCitaRequest):
    return db_manager.actualizar_estado_cita_recepcion(
        id_sesion=payload.id_sesion,
        nuevo_estado=payload.estado_cita,
        nueva_fecha=payload.fecha_sesion
    )


@app.get("/api/paciente/portal/{id_paciente}")
def api_portal_paciente(id_paciente: str):
    try:
        return db_manager.obtener_portal_paciente_rls(id_paciente=id_paciente)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/api/paciente/autoevaluacion")
def api_registrar_autoevaluacion_paciente(payload: AutoevaluacionPacienteRequest):
    try:
        return db_manager.registrar_autoevaluacion_paciente(
            id_paciente=payload.id_paciente,
            cumplimiento_tareas=payload.cumplimiento_tareas,
            id_escala=payload.id_escala,
            item_1_tristeza=payload.item_1_tristeza,
            item_9_ideacion_riesgo=payload.item_9_ideacion_riesgo,
            puntaje_resto=payload.puntaje_resto
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/sql/scripts")
def api_listar_scripts_sql():
    scripts = []
    for ruta in sorted(SQL_DIR.glob("*.sql")):
        scripts.append({
            "nombre": ruta.name,
            "contenido": ruta.read_text(encoding="utf-8")
        })
    return {"scripts": scripts}


@app.get("/")
def servir_frontend():
    return FileResponse(
        FRONTEND_DIR / "index.html",
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")
