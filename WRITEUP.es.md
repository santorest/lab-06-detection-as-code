---
title: "Detección como código con Sigma"
id: "lab-06-detection-as-code"
category: "Detección de amenazas y SIEM"
type: "Laboratorio"
status: "completado"
date: "2026-09-30"
time_to_reproduce: "30–60 minutos (fork, activar Actions, aplicar el ruleset)"
skills: [Sigma, sigma-cli, pySigma, Zircolite, Elasticsearch, Splunk SPL, ES|QL, KQL, Microsoft Sentinel, Sysmon, auditd, GitHub Actions, Python, pytest]
frameworks: [MITRE ATT&CK v19, especificación Sigma, NIST CSF 2.0 (DE.CM, DE.AE)]
repo: "https://github.com/santorest/lab-06-detection-as-code"
bundle: "Publicado en el sitio del portafolio con su checksum SHA-256"
---

# Detección como código con Sigma

> **En resumen:** quince reglas Sigma mapeadas a ATT&CK (siete de Windows, tres de Linux auditd y cinco de Azure)
> viven en Git y se prueban como código. Cada pull request las valida, las convierte a cuatro lenguajes de consulta
> de SIEM, compara el resultado con archivos "golden" versionados y las **ejecuta** contra eventos de prueba
> positivos y negativos en dos motores (Zircolite y Elasticsearch). Un ruleset de rama bloquea la fusión si no pasan
> los diez controles.
> **Las ejecuciones de CI son reales; los eventos de prueba son sintéticos**, escritos a mano a partir de esquemas
> de registro documentados.

| | |
|---|---|
| **Rol** | Ingeniero de detección que convierte un puñado de búsquedas de SIEM en un repositorio de reglas revisado y probado |
| **Entorno** | Repositorio público de GitHub, runners Ubuntu de GitHub, contenedor de servicio Elasticsearch 9.5.3 |
| **Herramientas** | Sigma, sigma-cli 3.1.0 / pySigma 1.5.1, Zircolite 4.1.0, Elasticsearch, Python, pytest, gitleaks |
| **Entregables** | 15 reglas, 64 archivos de eventos, conversiones golden, 7 jobs de CI (10 controles), ruleset, PR de demostración, resultados |

---

## 1. Problema

Las detecciones se degradan en silencio. Un campo renombrado en un parser, un error tipográfico en una regla o un
cambio que hace que la regla "atrape más" no hace fallar nada: el SIEM simplemente deja de alertar, o empieza a
alertar por todo. Escribir las reglas una sola vez en Sigma, neutral respecto al proveedor, y tratarlas como código
(revisado, versionado y probado en cada cambio) convierte esos fallos silenciosos en pull requests en rojo.

## 2. Las reglas

| Plataforma | Regla | ATT&CK |
|---|---|---|
| Windows (Sysmon 1) | PowerShell iniciado con un comando codificado | T1059.001 |
| Windows (Sysmon 10) | Memoria del proceso LSASS abierta con acceso de lectura | T1003.001 |
| Windows (Security 4732) | Miembro añadido al grupo local Administradores | T1098 |
| Windows (Sysmon 1) | Tarea programada creada con schtasks | T1053.005 |
| Windows (Security 1102) | Registro de seguridad borrado | T1685.005 |
| Windows (Sysmon 1) | Instantáneas de volumen eliminadas | T1490 |
| Windows (System 7045) | Servicio instalado desde una ruta escribible por el usuario | T1543.003 |
| Linux (auditd EXECVE) | Reverse shell mediante /dev/tcp o /dev/udp | T1059.004 |
| Linux (auditd PATH) | Archivo SSH authorized_keys creado o modificado | T1098.004 |
| Linux (auditd PATH) | Archivo de persistencia en cron escrito | T1053.003 |
| Azure Activity | Rol Owner o User Access Administrator asignado | T1098 |
| Azure Activity | Regla de NSG que permite tráfico entrante desde Internet | T1686.001 |
| Auditoría de Entra | Directiva de acceso condicional creada, cambiada o eliminada | T1556 |
| Azure Activity | Eliminación masiva de recursos por un mismo autor (regla de correlación) | T1485 |
| Inicios de sesión de Entra | Inicio de sesión exitoso desde un país fuera de la lista permitida | T1078 |

Las cinco reglas de Azure vuelven a expresar en Sigma las detecciones KQL escritas a mano en el Laboratorio 05
(landing zone de Azure). Cada regla lleva descripción, referencias, notas de falsos positivos y nivel, y
`check_metadata.py` lo exige en CI. Las etiquetas siguen ATT&CK v19.

## 3. El pipeline

- **lint:** `sigma check` (con validadores y los datos de ATT&CK fijados en la v19.2), yamllint y una comprobación
  de metadatos y eventos.
- **convert:** cada regla se convierte a Splunk SPL, Elastic Lucene, ES|QL y KQL de Sentinel, y el resultado se
  compara con `tests/expected/`. Un cambio en una regla, en un pipeline o en la versión de un backend aparece como
  un diff revisable de la consulta generada.
- **match-zircolite** y **match-elasticsearch:** cada archivo de eventos pasa por dos motores. Los positivos deben
  disparar en todos sus eventos (en la regla de correlación, al menos una alerta) y los negativos, casi aciertos,
  deben quedar en silencio. Son dos motores porque una consulta puede estar bien en uno y mal en otro: los campos
  keyword de Elasticsearch distinguen mayúsculas si no se normalizan, mientras que Sigma no las distingue.
- **coverage** mantiene la tabla ATT&CK del README y una capa de Navigator sincronizadas con las etiquetas;
  **python** prueba los scripts; **secrets** ejecuta gitleaks sobre todo el historial.

## 4. Brechas declaradas

No todas las reglas se convierten a todos los destinos, y el pipeline lo dice en lugar de omitirlo en silencio.
`support.yaml` lista cada brecha con su motivo: la regla de correlación (sin soporte en Lucene ni en kusto), cuatro
reglas de Windows para las que el mapeo `microsoft_xdr` de Sentinel no tiene tabla, y las reglas de auditd (no hay
una tabla estándar en Sentinel). CI vuelve a ejecutar cada conversión "unsupported" y falla en cuanto empieza a
funcionar, así que la lista no puede quedar desactualizada.

## 5. Sigma frente al KQL escrito a mano del Laboratorio 05

| Detección | KQL del Laboratorio 05 | Convertido desde Sigma (`tests/expected/kusto/`) |
|---|---|---|
| Asignación de rol privilegiado | Analiza el cuerpo de la solicitud y revisa `RoleDefinitionId` | `Properties contains "<GUID del rol>"`: coincidencia de subcadena sobre todo el bloque de propiedades, más gruesa |
| NSG abierto a Internet | Analiza el JSON de la regla y revisa dirección, acceso y prefijo de origen | Subcadenas sobre JSON compacto: falla si el cuerpo tiene otro formato |
| Cambio de acceso condicional | Mismas operaciones; sin filtro por resultado | Mismas operaciones **más** `Result =~ "success"`: los intentos fallidos ya no alertan |
| Eliminación masiva | `summarize count() by Caller` en la ventana de 15 minutos de la regla | **Sin KQL:** el backend kusto no admite reglas de correlación (Splunk y ES|QL sí) |
| Inicio de sesión fuera de países permitidos | Lista permitida `US`; ignora `Location` vacío | Lista `CO, US`; sin comprobar `Location` vacío, así que dispararía con inicios de sesión sin ubicación |

Sigma aporta portabilidad y capacidad de prueba. Lo que cuesta es la precisión del KQL escrito a mano allí donde
los datos son JSON anidado.

## 6. Resultados

Los resultados se añaden a partir de las primeras ejecuciones de GitHub Actions (ver la tarea 13 del plan).

## 7. Lecciones

- **Los eventos negativos fueron los primeros en demostrar su valor.** La regla de NSG, tal como se escribió
  primero, coincidía con cualquier origen: un `*` sin escapar dentro de un valor Sigma es un comodín, así que
  `"sourceAddressPrefix":"*"` también coincidía con `VirtualNetwork`. El evento de casi acierto lo detectó antes de
  que la regla llegara a `main`; ahora el asterisco está escapado.
- **Validar contra un ATT&CK fijado.** pySigma valida las etiquetas contra la rama `master` de ATT&CK. A mitad de
  la construcción esa rama era la v19, que dividió Defense Evasion y renumeró técnicas, y `sigma check` empezó a
  fallar con etiquetas que el día anterior eran válidas. Ahora la comprobación usa un archivo de ATT&CK versionado
  en un commit fijo.
- **Los mapeos pueden cambiar una regla sin avisar.** Enviar las reglas del registro de seguridad a la tabla
  `SecurityEvent` de Sentinel con un pipeline propio parecía funcionar, pero combinado con `microsoft_xdr` eliminaba
  la condición de `EventID` (la consulta de 4732 también coincidiría con 4733). Leer la consulta generada lo hizo
  visible, y ahora la brecha se declara.
- **Los tipos importan entre backends.** Escribir `ResultType` como número satisfacía al validador de Sigma, pero
  producía `ResultType == 0` en KQL, un error de tipo contra una columna de texto.
- **La semántica de correlación cambia según el motor.** Las conversiones a Splunk y ES|QL cuentan en intervalos
  fijos de 15 minutos. Zircolite usa una ventana deslizante y detecta una ráfaga de 13:10 a 13:19 que, según las
  consultas, los intervalos fijos partirían en 5 + 5.
- **Los motores tienen sus manías.** Zircolite elimina los guiones bajos de los nombres de campo, y una regla de
  correlación solo se convierte si está en el mismo archivo que su regla base.

## 8. Límites

- Los eventos son sintéticos. Las pruebas demuestran que cada regla coincide con lo que dice y que ignora sus casi
  aciertos. No miden tasas de falsos positivos sobre telemetría real, que requieren una línea base en un entorno
  en vivo.
- Sin conversión a Wazuh (fuera de alcance, en la hoja de ruta).
- Elasticsearch solo se ejercita en CI (servicio Docker); Zircolite también se ejecuta en local.
- Las consultas de Splunk, ES|QL y KQL se generan y se comparan, pero no se ejecutan.

## 9. Cómo reproducirlo

1. Hacer fork del repositorio y activar GitHub Actions.
2. Aplicar `.github/rulesets/main.json` como ruleset de rama (Settings → Rules → Import).
3. En local: `python -m venv .venv`, `pip install -r requirements-dev.txt` y los comandos del README.
4. Abrir un pull request que edite una regla y observar los diez controles.

## 10. Correspondencia con marcos

- **MITRE ATT&CK v19:** 14 técnicas en 7 tácticas (tabla y capa de Navigator en el repositorio).
- **NIST CSF 2.0:** DE.CM (monitoreo continuo) y DE.AE (análisis de eventos adversos): las detecciones como
  activos mantenidos y probados.
