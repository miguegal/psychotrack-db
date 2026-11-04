# PsychoTrack DB — Plataforma de Seguimiento Psicológico y Evaluación Terapéutica

[![Abrir Plataforma en Vivo en Railway](https://img.shields.io/badge/🚀_Acceder_a_la_Plataforma_en_Vivo-Railway_Cloud-0B0D0E?style=for-the-badge&logo=railway&logoColor=white)](https://psychotrack-web-production.up.railway.app)

**Universidad de Guadalajara — Centro Universitario de Ciencias Exactas e Ingenierías (CUCEI)**  
**Materia:** Administración de Bases de Datos  
**Profesor:** Jovan Ricardo Zepeda Gomez  
**Alumno:** Galvez Arceo Miguel Angel (`220537132`) — Ingeniería Informática

---

## 🌐 Acceso Directo a la Aplicación en Línea (Railway)

La plataforma se encuentra desplegada y disponible 24/7 en la nube mediante **Railway**. Puedes acceder directamente desde cualquier navegador o dispositivo móvil haciendo clic en el siguiente enlace:

👉 **[https://psychotrack-web-production.up.railway.app](https://psychotrack-web-production.up.railway.app)**

### 🔐 Credenciales de Acceso por Rol (`RBAC` + `RLS`)
- **Contraseña general para todas las cuentas:** `Psycho2026!`

| Rol Operativo (`RBAC`) | Usuario / Identificador | Titular | Alcance y Permisos (`RLS`) |
| :--- | :--- | :--- | :--- |
| **`rol_terapeuta`** | `TER-84920-GDL` *(o `84920`)* | Dr. Alejandro Morales Ramos | Visualiza únicamente sus 3 pacientes asignados (`PAC-2026-015`, `PAC-2026-042`, `PAC-2026-088`), registra notas cifradas (`AES-256`) y aplica tests `BDI-II`. |
| **`rol_terapeuta`** | `TER-91045-GDL` *(o `91045`)* | Dra. Valeria Solís Mendoza | Visualiza únicamente su paciente asignado (`PAC-2026-109`) por aislamiento `RLS`. |
| **`rol_supervisor`** | `SUP-10200-GDL` *(o `10200`)* | Dr. Roberto Guzmán Cárdenas | Supervisión clínica global y atención de alertas críticas generadas por el *Trigger* del Ítem 9 ($\ge 2$). |
| **`rol_recepcion`** | `REC-50012-GDL` *(o `50012`)* | Lic. Sofía Herrera Vázquez | Control de agenda y teléfonos de emergencia (`vw_agenda_recepcion_segura`), sin acceso a notas clínicas. |
| **`rol_auditor`** | `AUD-30099-GDL` *(o `30099`)* | Mtro. Carlos Ibarra Montes | Consulta de métricas e indicadores institucionales agregados y anonimizados (`vw_auditoria_indicadores_anonimizados`). |
| **`rol_dba_admin`** | `DBA-00001-GDL` *(o `220537132`)* | Ing. Miguel Angel Galvez Arceo | Consola de Salud de PostgreSQL, métricas `RPO`/`RTO`, ejecución de *Backup Manual Consistente* (`SHA-256`), matriz `RBAC` y visor de scripts `.sql`. |
| **`rol_paciente`** | `PAC-2026-042`, `PAC-2026-015`, `PAC-2026-088`, `PAC-2026-109` | Consultantes Registrados | Portal del Paciente filtrado por `RLS`: consulta de plan terapéutico, citas, evolución longitudinal $\Delta$ y autoevaluación `BDI-II` pre-sesión. |

---

## 1. Descripción del Proyecto

**PsychoTrack DB** es una plataforma clínica y transaccional diseñada bajo una arquitectura Cliente-Servidor de Tres Capas para centros universitarios de atención psicológica y clínicas de consulta externa. Implementa todos los componentes de **Administración de Bases de Datos (ABD)** y los **Atributos de Calidad (ISO/IEC 25010)** estipulados en el documento rector:

1. **Modelo Lógico y Físico Normalizado (8 Entidades Principales + 2 Tablas de Gobernanza/DRP):**
   - `terapeuta`, `paciente`, `expediente_clinico`, `diagnostico_dsm`, `plan_intervencion`, `sesion_terapeutica`, `escala_evaluacion`, `resultado_psicometrico`, `alerta_riesgo_clinico` y `bitacora_respaldo_drp`.
   - Integridad referencial estricta (`ON DELETE RESTRICT`), restricciones semánticas (`CHECK`) e índices `B-Tree` en columnas de filtrado frecuente.
2. **Control de Acceso Basado en Roles (RBAC) y Principio del Menor Privilegio:**
   - `rol_terapeuta`, `rol_supervisor`, `rol_recepcion`, `rol_auditor`, `rol_dba_admin` y `rol_paciente`.
3. **Seguridad Criptográfica y Aislamiento por Filas (RLS):**
   - Autenticación con `Salt` aleatorio + `Hash SHA-256` determinista de 256 bits.
   - Cifrado a nivel de columna (`pgcrypto` AES-256) para `notas_clinicas_cifradas`, `motivo_consulta_cifrado` y `antecedentes_psicosociales_cifrado`.
   - Políticas **Row-Level Security (RLS)** vinculadas a `CURRENT_USER` para garantizar que cada terapeuta o consultante solo visualice los registros autorizados.
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
  - `main.py`: Servidor FastAPI con endpoints REST para todas las vistas por rol.
- `frontend/`
  - `index.html` y `app.js`: Interfaz web responsiva maquetada con **Tailwind CSS** que implementa fielmente los **Mockups 1, 2, 3 y 4**, además de las vistas dedicadas para Supervisor Clínico, Recepción, Auditoría, Portal del Paciente y Consola DBA.

---

## 3. Ejecución Local

```powershell
# Activar el entorno virtual e iniciar el servidor FastAPI
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Luego abre en tu navegador: **http://127.0.0.1:8000**
