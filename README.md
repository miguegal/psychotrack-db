# PsychoTrack DB — Plataforma de Seguimiento Psicológico y Evaluación Terapéutica

**Universidad de Guadalajara — Centro Universitario de Ciencias Exactas e Ingenierías (CUCEI)**  
**Materia:** Administración de Bases de Datos  
**Profesor:** Jovan Ricardo Zepeda Gomez  
**Alumno:** Galvez Arceo Miguel Angel (`220537132`) — Ingeniería Informática

---

## 1. Descripción del Proyecto

**PsychoTrack DB** es una plataforma clínica y transaccional diseñada bajo una arquitectura en 6 capas para centros universitarios de atención psicológica y clínicas de consulta externa. Implementa todos los componentes de **Administración de Bases de Datos (ABD)** y los **Atributos de Calidad (ISO/IEC 25010)** estipulados en el documento rector:

1. **Modelo Lógico y Físico Normalizado (8 Entidades Principales + 2 Tablas de Gobernanza/DRP):**
   - `terapeuta`, `paciente`, `expediente_clinico`, `diagnostico_dsm`, `plan_intervencion`, `sesion_terapeutica`, `escala_evaluacion`, `resultado_psicometrico`, `alerta_riesgo_clinico` y `bitacora_respaldo_drp`.
   - Integridad referencial estricta (`ON DELETE RESTRICT`), restricciones semánticas (`CHECK`) e índices `B-Tree` en columnas de filtrado frecuente.
2. **Control de Acceso Basado en Roles (RBAC) y Principio del Menor Privilegio:**
   - `rol_terapeuta`, `rol_supervisor`, `rol_recepcion`, `rol_auditor`, `rol_dba_admin`.
3. **Seguridad Criptográfica y Aislamiento por Filas (RLS):**
   - Autenticación con `Salt` aleatorio + `Hash SHA-256` determinista de 256 bits.
   - Cifrado a nivel de columna (`pgcrypto` AES-256) para `notas_clinicas_cifradas`, `motivo_consulta_cifrado` y `antecedentes_psicosociales_cifrado`.
   - Políticas **Row-Level Security (RLS)** vinculadas a `CURRENT_USER` para garantizar que cada terapeuta solo visualice y edite a sus pacientes asignados.
4. **Lógica Activa en el Motor de Base de Datos (PL/pgSQL):**
   - **Procedimiento Almacenado (`sp_calcular_delta_psicometrico`):** Calcula automáticamente el vector longitudinal de cambio sintomático ($\Delta = \text{Puntaje}_{\text{actual}} - \text{Puntaje}_{\text{inicial}}$).
   - **Disparador Atómico (`BEFORE INSERT` / `AFTER INSERT`):** Analiza en tiempo real el reactivo crítico (**Ítem 9 del BDI-II** sobre ideación/autolesión $\ge 2$) e inserta atómicamente una bandera de emergencia notificando al Supervisor Clínico.
5. **Políticas de Respaldo, Contingencia y Alta Disponibilidad (DRP):**
   - Cumplimiento de **RPO = 1.0 Hora** y **RTO < 2.0 Horas** mediante respaldo completo semanal (`pg_dump`), diferencial diario y archivado continuo `Write-Ahead Logging (WAL)` hacia medio aislado (*air-gapped*).

---

## 2. Estructura del Directorio

- `sql/`
  - `01_ddl_esquema_tablas.sql`: Creación de `pgcrypto`, tablas, `CHECK`, `FOREIGN KEY ... ON DELETE RESTRICT` e índices `B-Tree`.
  - `02_rbac_roles_y_rls.sql`: Creación de roles RBAC, directivas `GRANT`/`REVOKE`, políticas `ROW LEVEL SECURITY` y vistas protegidas.
  - `03_triggers_y_procedimientos.sql`: Funciones criptográficas, `sp_calcular_delta_psicometrico()` y triggers `BEFORE/AFTER INSERT`.
  - `04_datos_semilla_anonimizados.sql`: Datos clínicos anonimizados que reproducen los Mockups 1 a 4.
  - `05_politicas_respaldo_drp.sql`: Configuración WAL y procedimiento `sp_disparar_backup_manual_consistente()`.
  - `backup_drp_automatizado.ps1`: Script PowerShell para respaldos completos, diferenciales y verificación WAL.
- `backend/`
  - `database.py`: Capa de persistencia SQLAlchemy (Pool de conexiones PostgreSQL 18 + motor transaccional autónomo integrado).
  - `main.py`: Servidor FastAPI con endpoints REST para las 4 vistas de los Mockups y los roles complementarios.
- `frontend/`
  - `index.html` y `app.js`: Interfaz web responsiva maquetada con **Tailwind CSS** que implementa fielmente los **Mockups 1, 2, 3 y 4**, además de las vistas para Supervisor Clínico, Recepción, Auditoría y el visor de scripts SQL.

---

## 3. Ejecución Rápida

```powershell
# 1. Activar el entorno virtual e iniciar el servidor FastAPI
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Luego abre en tu navegador: **http://127.0.0.1:8000**

### Credenciales de Prueba Pre-cargadas (Contraseña para todos: `Psycho2026!`)
- **Terapeuta Principal (Mockups 1, 2 y 3):** `TER-84920-GDL` (Dr. Alejandro Morales Ramos)
- **Terapeuta Secundario (Prueba de aislamiento RLS):** `TER-91045-GDL` (Dra. Valeria Solís Mendoza)
- **Supervisor Clínico:** `SUP-10200-GDL` (Dr. Roberto Guzmán Cárdenas)
- **Recepción y Citas:** `REC-50012-GDL` (Lic. Sofía Herrera Vázquez)
- **Auditoría y Dirección:** `AUD-30099-GDL` (Mtro. Carlos Ibarra Montes)
- **Administrador de BD (Mockup 4 - Consola DBA):** `DBA-00001-GDL` (Ing. Miguel Angel Galvez Arceo)
