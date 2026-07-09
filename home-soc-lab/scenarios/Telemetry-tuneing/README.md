# Wazuh Windows Telemetry Tuning: cierre de gaps de visibilidad y reglas custom

## Resumen ejecutivo

Este documento detalla el proceso de cierre de tres gaps críticos de visibilidad identificados en el escenario [Enumeración de Windows vía WinRM](../scenarios/windows-enumeration-via-winrm.md). Los gaps no son configuraciones erróneas, sino **decisiones conservadoras de la instalación por defecto de Wazuh y SwiftOnSecurity** que priorizan estabilidad inicial sobre profundidad de telemetría.

Los tres gaps abordados:

| # | Gap | Capa de defensa cubierta |
|---|---|---|
| 1 | Canal de Microsoft Defender no recolectado | Detección de bloqueos AMSI / threats por firma |
| 2 | PowerShell script-block logging deshabilitado | Visibilidad de actividad PowerShell in-memory |
| 3 | Sysmon EID 3 (Network Connect) deshabilitado | Telemetría de conexiones salientes |

Adicionalmente se diseñaron dos reglas custom de Wazuh para hacer accionable la telemetría incorporada, y se documentaron **limitaciones técnicas no obvias** descubiertas durante la implementación — específicamente el límite de 65.535 bytes del manager Wazuh y la inconsistencia de Sysmon EID 3 con procesos efímeros.

El documento se estructura como un manual técnico reproducible: cada gap incluye motivación, comandos exactos, verificación, troubleshooting real encontrado durante la implementación, y rollback. La intención es que cualquier lector pueda replicar los cambios y entender por qué se tomaron.

---

## Estado inicial del entorno

Configuración base del Home SOC Lab antes de aplicar los cambios documentados aquí:

| Componente | Versión | Estado relevante |
|---|---|---|
| Wazuh Manager (Ubuntu 22.04) | 4.7.5 All-in-One | Configuración default, `<logall>yes</logall>` ya habilitado |
| Wazuh Agent (Windows Server 2025) | 4.7.5 | Suscripto a canales: Security, System, Application, Sysmon |
| Sysmon | 15.20 | Schema 4.91 | Config: SwiftOnSecurity v74 (julio 2021), instalación previa con XML perdido |
| Microsoft Defender | Activo | RealTimeProtection enabled, AMSI funcional |
| PowerShell | 5.1 | Script-block logging deshabilitado por defecto |

### Notas sobre el estado inicial

- **Wazuh Manager** ya tenía `<logall>yes</logall>` activado, lo que resultó relevante durante el diagnóstico del Gap 2 (permitió ver eventos crudos en archives).
- **Sysmon** estaba instalado con SwiftOnSecurity v74, pero el archivo XML original había sido eliminado del disco tras la instalación inicial. Esto forzó a re-descargar el XML oficial desde GitHub durante el Gap 3.
- **Ningún cambio previo** se había hecho a `local_rules.xml` (solo contenía el ejemplo SSH del template).

---

## Gap 1 — Canal de Microsoft Defender

### Motivación

Durante la ejecución del escenario, el ataque PowerUp.ps1 fue bloqueado por AMSI/Defender (firma `HackTool:PowerShell/EventVwrBypass`, mapeada a T1548.002). El bloqueo se registró localmente en el canal `Microsoft-Windows-Windows Defender/Operational` con Event ID 1117, pero **el SOC no recibió ninguna alerta** porque el agente Wazuh no estaba suscrito a ese canal.

Esta es una situación crítica: la prevención funcionó (Defender bloqueó el ataque), pero la detección falló (nadie en el equipo de seguridad se enteró). **Prevención sin detección equivale a un muro ciego** — un atacante puede iterar hasta encontrar una técnica que evada la firma sin que el equipo defensivo lo sepa.

### Implementación

#### Paso 1 — Backup del archivo de configuración del agente

Disciplina obligatoria antes de cualquier cambio. En la consola del Windows Server, PowerShell elevada:

```powershell
Copy-Item "C:\Program Files (x86)\ossec-agent\ossec.conf" "C:\Program Files (x86)\ossec-agent\ossec.conf.bak"
```

#### Paso 2 — Agregar el bloque `<localfile>` al final de `ossec.conf`

El bloque se inserta justo antes del cierre `</ossec_config>`. Comando en PowerShell:

```powershell
$conf = "C:\Program Files (x86)\ossec-agent\ossec.conf"
$bloque = "  <localfile>`n    <location>Microsoft-Windows-Windows Defender/Operational</location>`n    <log_format>eventchannel</log_format>`n  </localfile>`n"
(Get-Content $conf -Raw) -replace '</ossec_config>', "$bloque</ossec_config>" | Set-Content $conf -Encoding UTF8
```

#### Paso 3 — Verificar la inserción

```powershell
Select-String -Path $conf -Pattern "Defender" -Context 2,2
```

El output debe mostrar el bloque XML completo con el nombre del canal exacto `Microsoft-Windows-Windows Defender/Operational` (respetando mayúsculas).

#### Paso 4 — Reiniciar el agente

```powershell
Restart-Service -Name WazuhSvc
Get-Service WazuhSvc
```

Estado esperado: `Running`. Si queda en `Stopped`, hay un error de sintaxis XML — restaurar el backup.

### Validación

Reproducción del ataque original (IEX desde evil-winrm) y búsqueda en el dashboard Wazuh:

```
data.win.system.channel: "Microsoft-Windows-Windows Defender/Operational"
```

Resultado: **regla 62124 (nivel 3) y regla 62123 (nivel 12) disparan**. El SOC ahora recibe alertas sobre bloqueos de Defender.

![Captura: alerta 62124/62123 tras cerrar Gap 1](../images/11-01-gap1-defender-alert.png)

### Hallazgos para mejora futura

| Hallazgo | Severidad | Mitigación propuesta |
|---|---|---|
| Regla 62124 dispara nivel 3 (informativo) | Media | Promover a nivel 8+ con regla custom |
| Mapeo MITRE de regla 62124 vacío | Media | Mapear manualmente a T1059.001 + T1027 vía regla custom |

Ambos hallazgos se aborrdan parcialmente en la sección [Reglas custom](#reglas-custom-de-wazuh) más adelante.

### Caveats

| Caveat | Detalle |
|---|---|
| Smart quotes en PowerShell | Algunos clientes de chat embellecen comillas durante copy-paste, rompiendo here-strings. Tipear las comillas a mano en la consola |
| Case-sensitivity del canal | `Microsoft-Windows-Windows Defender/Operational` requiere mayúsculas exactas. En minúsculas el agente no se suscribe |
| Restart del agente, no del manager | Solo el agente necesita reiniciar para tomar la nueva suscripción |

### Rollback

```powershell
Copy-Item "C:\Program Files (x86)\ossec-agent\ossec.conf.bak" "C:\Program Files (x86)\ossec-agent\ossec.conf" -Force
Restart-Service -Name WazuhSvc
```

---

## Gap 2 — PowerShell script-block logging

### Motivación

Durante la enumeración del escenario, comandos como `Get-LocalUser` (cmdlet PowerShell in-process) **no generaron ninguna telemetría visible para Wazuh**. La razón: PowerShell no loguea por defecto el código que ejecuta, y cmdlets nativos no crean procesos hijos visibles a Sysmon EID 1. Resultado: actividad de reconnaissance completamente invisible al SOC.

PowerShell soporta **script-block logging** (Event ID 4104), que registra el texto literal de cada bloque de código ejecutado, incluyendo cmdlets que corren in-process. Esta capacidad existe desde PowerShell 5 pero está deshabilitada por defecto.

### Implementación

El Gap 2 requiere cambios en **dos sistemas**: Windows (habilitar el logging) y el agente Wazuh (suscribir el canal). Si solo se hace uno, no funciona.

#### Paso 1 — Habilitar script-block logging en Windows (Registry)

En la consola del Windows Server, PowerShell elevada:

```powershell
# Backup conceptual de la clave (puede no existir todavía, error esperado)
reg export "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell" C:\ScriptBlockLogging_backup.reg 2>$null

# Crear la clave y habilitar la flag
$regPath = "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $regPath -Force | Out-Null
New-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWORD -Force | Out-Null

# Verificar
Get-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging"
```

Output esperado: `EnableScriptBlockLogging : 1`. PowerShell comienza a loguear inmediatamente, no requiere reinicio.

#### Paso 2 — Suscribir el canal PowerShell en el agente Wazuh

Mismo patrón que el Gap 1:

```powershell
$conf = "C:\Program Files (x86)\ossec-agent\ossec.conf"
$bloque = "  <localfile>`n    <location>Microsoft-Windows-PowerShell/Operational</location>`n    <log_format>eventchannel</log_format>`n  </localfile>`n"
(Get-Content $conf -Raw) -replace '</ossec_config>', "$bloque</ossec_config>" | Set-Content $conf -Encoding UTF8

# Verificar
Select-String -Path $conf -Pattern "PowerShell/Operational" -Context 2,2

# Reiniciar agente
Restart-Service -Name WazuhSvc
Get-Service WazuhSvc
```

### Validación — y un diagnóstico que se complicó

La validación de este gap fue significativamente más compleja de lo anticipado. Documento el proceso real porque las lecciones son valiosas.

#### Primera validación (esperada, falló)

Tras habilitar todo, se ejecutó el IEX desde evil-winrm. Resultado: **ninguna alerta nueva en el dashboard**. Búsquedas DQL como `data.win.system.eventID: 4104` no devolvieron nada.

#### Segunda hipótesis (también incorrecta)

Se asumió que los eventos no llegaban al manager. Búsqueda en archives del manager:

```bash
grep "Microsoft-Windows-PowerShell" /var/ossec/logs/archives/archives.log
```

Resultado: vacío. Esto reforzó la hipótesis errónea de que la cadena Windows→Wazuh estaba rota.

#### Verificación correcta

`Get-WinEvent` en el Windows confirmó que PowerShell **sí estaba logueando** Event ID 4104:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 5 -FilterXPath "*[System[EventID=4104]]" | Format-Table TimeCreated, Id, LevelDisplayName -AutoSize
```

Los eventos existían, con timestamps coincidentes con los intentos de IEX. El gap real estaba más adelante.

#### Test con evento pequeño

```powershell
Write-Host "Test 4104 pequeño desde Wazuh debug"
```

```bash
grep -i "Test 4104" /var/ossec/logs/archives/archives.log
```

**Este evento sí apareció en archives del manager**. Lo cual revela que la cadena de telemetría funciona — el problema era específico de eventos grandes.

### Hallazgo crítico — Límite de 64KB del manager Wazuh

Test con script de tamaño controlado (~75KB):

```powershell
$bigScript = "Write-Host 'A' " * 5000
Invoke-Expression $bigScript
```

En archives del manager, el evento aparece **truncado**. El `scriptBlockText` se corta arbitrariamente.

Causa raíz documentada en [Wazuh issue #17689](https://github.com/wazuh/wazuh/issues/17689):

> *"the maximum single event size that analysisd can handle is 65535B. If we sent any event greater than 65535B analysisd will truncate it until the max size and the user never will be alerted about it."*

**Implicancia defensiva crítica**: scripts grandes (como PowerUp.ps1 ~600KB) **superan el límite por un orden de magnitud**. El evento se trunca silenciosamente y cualquier regla custom que matchee contra `win.eventdata.scriptBlockText` puede fallar al no encontrar la cadena buscada en la porción truncada.

Esto es un **gap arquitectónico**, no de configuración. No se resuelve cambiando una flag — requiere diseñar reglas que no dependan del contenido completo del evento.

### Lecciones aprendidas

| Lección | Aplicación |
|---|---|
| `Get-WinEvent` es la verdad sobre lo que Windows registra | Diagnóstico debe partir del endpoint, no del SIEM |
| `archives.json` puede no existir aunque archives esté activo | El formato es `.log` por defecto, no JSON |
| Eventos pequeños llegan, grandes se truncan | Test con eventos chicos primero para validar la cadena |
| Suscripción del canal ≠ recepción del evento | Validar con `ossec.log` del agente (`INFO: (1951): Analyzing event log`) y archives del manager |

### Caveats

| Caveat | Detalle |
|---|---|
| Volumen alto | Script-block logging genera muchos eventos rutinarios (Windows, modules, scripts admin). En producción, complementar con reglas de filtrado |
| `logall` puede estar desactivado | Si archives está vacío, verificar `<logall>yes</logall>` en `/var/ossec/etc/ossec.conf` antes de asumir que la telemetría no llega |
| Caché de smart quotes en herramientas remotas | El mismo problema del Gap 1, agravado por here-strings de PowerShell |

---

## Gap 3 — Sysmon Event ID 3 (Network Connect)

### Motivación

Durante el escenario, las cuatro descargas de PowerUp.ps1 desde el Windows hacia el server Python en Kali (puerto 8000) no generaron telemetría en Wazuh. La razón: Sysmon con la versión instalada de SwiftOnSecurity tenía NetworkConnect deshabilitado o filtrado de forma muy restrictiva.

Sysmon EID 3 registra conexiones TCP/UDP salientes de procesos, incluyendo IP origen, IP destino, puerto, proceso y usuario. Es la pieza de telemetría que cubre comportamiento de red a nivel de endpoint cuando no hay integración con firewall.

### Implementación

#### Paso 1 — Encontrar la configuración activa de Sysmon

Sysmon almacena la config en memoria. Verificación del estado actual:

```powershell
C:\Windows\Sysmon64.exe -c | Select-Object -First 30
```

Output revela el archivo de config activo (`Config file:`) y el estado de NetworkConnect (`Network connection: disabled` o `enabled`).

Caveat importante: el output de `Sysmon64.exe -c` es **un dump human-readable**, NO XML cargable. No se puede usar como archivo de configuración para re-aplicar con `-c`.

#### Paso 2 — Descargar SwiftOnSecurity v74 oficial

El XML original instalado había sido eliminado tras la instalación. Re-descarga desde GitHub:

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\sysmonconfig.xml"

# Verificar
Get-Item C:\sysmonconfig.xml | Select-Object Name, Length
Get-Content C:\sysmonconfig.xml | Select-Object -First 5
```

Esperado: archivo de ~123 KB, primera línea es comentario XML con header del proyecto.

#### Paso 3 — Aplicar la nueva configuración

```powershell
C:\Windows\Sysmon64.exe -c C:\sysmonconfig.xml
```

Output esperado:

```
Loading configuration file with schema version 4.50
Sysmon schema version: 4.91
Configuration file validated.
Configuration updated.
```

#### Paso 4 — Verificar que NetworkConnect quedó activo

```powershell
C:\Windows\Sysmon64.exe -c | Select-String -Pattern "Network connection"
```

Esperado: `Network connection: enabled`.

#### Paso 5 — Caveat crítico que requiere reboot

A pesar de que `Sysmon64 -c` reporta "Configuration updated", **Sysmon no comienza a loguear EID 3 hasta que el sistema se reinicie**. Esto no está documentado oficialmente por Microsoft pero está documentado por terceros (EventSentry):

> *"Despite of what is stated in the official documentation, a reboot is often necessary to activate the logging of event id 3."*

El servicio Sysmon corre como **protected process** — no se puede detener con `Stop-Service` ni `Restart-Service` aunque se sea Administrator. Es una protección deliberada de Microsoft contra malware que intenta deshabilitar Sysmon. Únicamente un reboot completo recarga el componente de driver.

```powershell
Restart-Computer -Force
```

Tras el reboot, verificación:

```powershell
Invoke-WebRequest http://192.168.10.100:8000/ -UseBasicParsing
Start-Sleep -Seconds 5
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 -FilterXPath "*[System[EventID=3]]" | Format-Table TimeCreated, Id -AutoSize
```

Esperado: EID 3 con timestamp posterior al reboot.

### Hallazgo crítico — Sysmon EID 3 inconsistente con procesos efímeros

Tras habilitar EID 3, se observó un comportamiento inesperado: conexiones iniciadas **desde la consola directa del Windows** (`Invoke-WebRequest`) generaban EID 3 normalmente, pero conexiones iniciadas **desde sesiones evil-winrm** no aparecían.

Esto coincide con un comportamiento documentado en Microsoft Q&A:

> *"If there is no delay before the application terminates, Sysmon logs neither the process image, process GUID, nor the user name. (...) This issue seems to still be there in version 13.34, tested and reproducible on my Windows 11 Pro machine."*

La causa: en sesiones WinRM, los comandos generan procesos de muy corta vida (created → connect → exits). Sysmon no logra asociar process info y descarta el evento o lo registra como `<unknown process>`, donde queda fuera del matching de reglas.

#### Implicancia defensiva

**Sysmon EID 3 es inadecuado como única fuente para detectar lateral movement vía WinRM**. La cobertura confiable estándar es:

| Fuente | Captura |
|---|---|
| Sysmon EID 1 con `parentImage=wsmprovhost.exe` | Cualquier proceso lanzado desde WinRM |
| Windows Event 5156 (Windows Filtering Platform) | Conexiones autorizadas a puertos 5985/5986 |
| PowerShell EID 400/4103 con `HostApplication=wsmprovhost` | Actividad PowerShell originada en WinRM |

Estas tres fuentes combinadas son más confiables que EID 3 para WinRM lateral movement. Referencias: [ThreatHunterPlaybook](https://threathunterplaybook.com/hunts/windows/190511-RemotePwshExecution/notebook.html), [Detection Engineer's Guide to PowerShell Remoting](https://securityboulevard.com/2024/12/detection-engineers-guide-to-powershell-remoting/).

### Caveats consolidados

| Caveat | Detalle |
|---|---|
| Sysmon necesita reboot para EID 3 | `Restart-Service` no funciona (protected process). Solo reboot completo |
| `Sysmon64 -c` output ≠ XML cargable | Es human-readable, no usar como template |
| SwiftOnSecurity v74 es de julio 2021 | Versión estable pero no actualizada; alternativa moderna: `olafhartong/sysmon-modular` |
| EID 3 inconsistente con WinRM | Documentar como limitación, complementar con EID 1 + 5156 |
| Si hay un segundo Sysmon instalado | Síntomas raros de filtrado. Verificar con `Get-Service | Where {$_.Name -like "*Sysmon*"}` |

---

## Reglas custom de Wazuh

Habilitar fuentes de telemetría no es suficiente: muchos eventos llegan al manager pero no se elevan a alertas si no hay reglas que matcheen. Wazuh trae rulesets nativos amplios, pero específicamente para PowerShell script-block (4104) y Sysmon EID 1 con `parentImage=wsmprovhost.exe`, **no hay reglas que eleven los eventos a niveles accionables**.

Se diseñaron dos reglas custom en `/var/ossec/etc/rules/local_rules.xml`.

### Anatomía del archivo

Wazuh tiene dos categorías de archivos de reglas:

| Tipo | Ubicación | Modificable |
|---|---|---|
| Reglas nativas | `/var/ossec/ruleset/rules/*.xml` | NO — se sobrescriben en updates |
| Reglas custom | `/var/ossec/etc/rules/local_rules.xml` | SÍ — persistente entre updates |

IDs reservados: `<100000` para reglas nativas, `>=100000` para reglas custom.

### Regla 100100 — PowerShell con DownloadString/IEX

Detecta ejecución de cadenas típicas de descarga remota in-memory dentro de un Event ID 4104.

```xml
<group name="local,windows,powershell,">
  <rule id="100100" level="10">
    <if_sid>91802</if_sid>
    <field name="win.eventdata.scriptBlockText" type="pcre2">(?i)DownloadString|IEX|Invoke-Expression</field>
    <description>PowerShell: descarga remota detectada via DownloadString</description>
    <mitre>
      <id>T1059.001</id>
      <id>T1105</id>
    </mitre>
  </rule>
</group>
```

Desglose:

| Elemento | Función |
|---|---|
| `<if_sid>91802</if_sid>` | Herencia: solo evalúa esta regla si la regla nativa 91802 (Event ID 4104) ya disparó |
| `type="pcre2"` | Matching por expresión regular, no string literal |
| `(?i)` | Case-insensitive |
| `\|` | Alternativas: matchea cualquiera de `DownloadString`, `IEX`, `Invoke-Expression` |
| `level="10"` | Alerta accionable (nivel >=7 sale en dashboards por defecto) |

#### Limitación de esta regla

**No funciona contra scripts grandes** debido al límite de 64KB del manager. Si PowerUp.ps1 (~600KB) viaja como contenido de un IEX, el `scriptBlockText` se trunca y el regex puede no encontrar "DownloadString" en la porción retenida. Esta regla es efectiva contra ataques con scripts pequeños o cuando "DownloadString" aparece al inicio del script.

### Regla 100102 — PowerShell desde sesión WinRM

Detecta cualquier proceso hijo de `wsmprovhost.exe`, mapeable a lateral movement.

```xml
<rule id="100102" level="10">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.parentImage" type="pcre2">(?i)wsmprovhost\.exe</field>
  <description>PowerShell ejecutando desde sesión WinRM Remota - posible lateral movement</description>
  <mitre>
    <id>T1021.006</id>
    <id>T1059.001</id>
  </mitre>
</rule>
```

Diseño deliberado:

| Decisión | Razón |
|---|---|
| `if_group sysmon_event1` (no `if_sid`) | Group más estable entre versiones que un SID específico |
| Campo `parentImage` (no `image`) | El proceso WinRM es el padre; el comando ejecutado es el hijo |
| Independiente del contenido | Captura `whoami`, `Get-Date`, `IEX` arbitrario — robusta al límite de 64KB |
| Nivel 10 | Acción WinRM en cuentas no-admin es señal alta en entornos donde no se espera |

#### Por qué esta regla es superior a 100100

| Aspecto | 100100 (contenido) | 100102 (metadato) |
|---|---|---|
| Robustez ante truncamiento | Vulnerable | Inmune (campo `parentImage` siempre llega completo) |
| Cobertura | Solo PowerShell con strings sospechosas | Cualquier comando hijo de WinRM |
| Falsos positivos | Bajos | Más altos (admins legítimos también disparan) |
| Detección con AMSI bypass | Solo si ejecuta keywords matcheadas | Sí, independiente del payload |

**Recomendación operacional**: ambas reglas se complementan. 100100 da contexto sobre qué se intentó ejecutar; 100102 garantiza detección incluso cuando 100100 fallaría.

### Implementación

#### Paso 1 — Backup

En la VM Wazuh, como root (`sudo -i`):

```bash
cp /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml.bak
```

#### Paso 2 — Editar el archivo

```bash
nano /var/ossec/etc/rules/local_rules.xml
```

Agregar el bloque `<group name="local,windows,powershell,">` con las dos reglas, **después** del último `</group>` existente. Guardar con `Ctrl+O`, salir con `Ctrl+X`.

#### Paso 3 — Validar sintaxis

```bash
/var/ossec/bin/wazuh-logtest
```

La herramienta carga el ruleset. Si hay error XML, se reporta al inicio:

```
ERROR: (1226): Error reading XML file 'etc/rules/local_rules.xml': XMLERR: ... (line: X).
```

Si llega al prompt `>>` sin errores, salir con `Ctrl+C`.

**Caveat crítico**: `wazuh-logtest` valida sintaxis XML pero **no atrapa todos los errores semánticos**. Errores como atributo sin valor (`name=>`) o estructura `<field>` rota pueden pasar la validación y solo fallar al reiniciar el manager.

#### Paso 4 — Reiniciar el manager

```bash
systemctl restart wazuh-manager
systemctl status wazuh-manager
```

Estado esperado: `active (running)`. Si arranca y falla:

```bash
journalctl -xeu wazuh-manager.service --no-pager | tail -50
```

Busca líneas `ERROR: (1226)` con número de línea del archivo XML para diagnóstico.

### Validación

#### Test de regla 100100

```powershell
# En consola PowerShell del Windows (NO evil-winrm)
Write-Host "DownloadString test desde host"
```

Esperado: alerta nivel 10 con regla 100100, descripción "PowerShell: descarga remota detectada via DownloadString", técnicas T1059.001 y T1105.

#### Test de regla 100102

```powershell
# En sesión evil-winrm
whoami
```

Esperado: alerta nivel 10 con regla 100102, descripción "PowerShell ejecutando desde sesión WinRM Remota", técnicas T1021.006 y T1059.001.

![Captura: regla 100102 disparando con whoami](../images/11-02-gap2-rule100102.png)

### Rollback

```bash
cp /var/ossec/etc/rules/local_rules.xml.bak /var/ossec/etc/rules/local_rules.xml
systemctl restart wazuh-manager
```

---

## Tabla resumen — Estado de cobertura post-cierre

Cobertura defensiva del Home SOC Lab tras aplicar los tres gaps:

| Vector de ataque | Antes | Después | Mecanismo |
|---|---|---|---|
| Bloqueo de AMSI/Defender | Invisible al SOC | Alerta nivel 12 (regla 62123) | Gap 1 |
| Enumeración con `Get-LocalUser` | Invisible al SOC | Alerta nivel 10 (regla 100102) | Gap 2 + regla 100102 |
| Enumeración con `whoami` | No alertaba | Alerta nivel 10 (regla 100102) | Gap 2 + regla 100102 |
| `IEX` con script pequeño desde WinRM | Solo Defender | Reglas 100100 + 100102 + Defender | Gap 2 + reglas |
| `IEX` con script grande (>64KB) desde WinRM | Solo Defender | Regla 100102 + Defender | Gap 2 + regla 100102 (100100 fallaría por truncamiento) |
| Conexiones salientes desde consola directa | No capturadas | Sysmon EID 3 visible | Gap 3 |
| Conexiones salientes desde WinRM | No capturadas | EID 3 inconsistente — fallback a EID 1 | Gap 3 + caveat documentado |

---

## Lecciones aprendidas (transversales)

### 1. Habilitar fuentes ≠ tener detección

Cada gap requirió **al menos dos pasos**: habilitar la fuente Y verificar/escribir la regla que la eleve a alerta. El paso 1 es trivial; el paso 2 es donde está el trabajo real de SOC engineering. Documentar fuentes habilitadas sin validar que generan alertas es portfolio engañoso.

### 2. La búsqueda externa es disciplina, no debilidad

Durante el Gap 2 y Gap 3, dos problemas se resolvieron únicamente consultando documentación oficial y foros (issue #17689 de Wazuh, README de SwiftOnSecurity, Microsoft Q&A sobre Sysmon, ThreatHunterPlaybook). Diagnosticar desde primeros principios sin consultar fuentes externas hubiera prolongado el proceso por horas. Un SOC engineer maduro googlea constantemente.

### 3. Validar end-to-end con eventos reales, no asumidos

`wazuh-logtest` valida sintaxis pero no captura errores semánticos. El restart del manager es la validación real de cualquier regla custom. Análogamente, exportar configs (`Sysmon64 -c`) puede dar dumps human-readable, no necesariamente XML cargable.

### 4. Detección por metadatos > detección por contenido

Reglas que matchean contra **metadatos del evento** (`parentImage`, `processName`, `processId`, `severity`) son más robustas que reglas que matchean **contenido** (`scriptBlockText`, `commandLine`). Los metadatos siempre llegan completos; el contenido puede truncarse, ofuscarse o no estar presente.

### 5. Documentar limitaciones es más valioso que ocultarlas

El límite de 64KB del manager Wazuh y la inconsistencia de EID 3 con WinRM son **limitaciones técnicas reales** que la mayoría de los analistas SOC desconocen. Documentarlas explícitamente con referencias a fuentes oficiales eleva la calidad del trabajo de "configuré las cosas" a "entiendo cómo y dónde puede fallar la detección".

---

## Próximos pasos / mejoras futuras

Pendientes identificados durante este proceso, documentados para futuras iteraciones del lab:

| Mejora | Prioridad | Esfuerzo estimado |
|---|---|---|
| Promover regla 62124 (Defender) de nivel 3 a nivel 8 con mapeo MITRE manual | Media | Bajo (1 regla custom adicional) |
| Habilitar Windows Event 5156 (WFP) para captura confiable de WinRM | Alta | Medio (auditpol + GPO + regla custom) |
| Integración pfSense → Wazuh syslog (pendiente del escenario anterior) | Alta | Alto (config en pfSense + decoder custom en Wazuh) |
| Migración de SwiftOnSecurity a `olafhartong/sysmon-modular` | Baja | Alto (refactor de toda la config Sysmon) |
| Reglas correlacionales (ej. WinRM logon + AMSI block en <5s) | Media | Medio (composite rules con `if_matched_sid` y timeframe) |
| Configurar `<logall_json>yes</logall_json>` para diagnóstico estructurado | Baja | Bajo (1 línea en `ossec.conf` del manager) |

---

## Referencias

### Documentación oficial
- [Wazuh — Configuration archive](https://documentation.wazuh.com/current/user-manual/manager/event-logging.html)
- [Wazuh — Custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html)
- [Sysmon documentation (Sysinternals)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Microsoft — PowerShell logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows)

### Fuentes externas consultadas durante la implementación
- [Wazuh issue #17689 — Event size limit](https://github.com/wazuh/wazuh/issues/17689)
- [SwiftOnSecurity sysmon-config — README](https://github.com/SwiftOnSecurity/sysmon-config)
- [EventSentry — Sysmon integration notes](https://www.eventsentry.com/support/documentation/configtrackingprocesssysmon-integration.htm)
- [ThreatHunterPlaybook — PowerShell Remote Session](https://threathunterplaybook.com/hunts/windows/190511-RemotePwshExecution/notebook.html)
- [Detection Engineer's Guide to PowerShell Remoting](https://securityboulevard.com/2024/12/detection-engineers-guide-to-powershell-remoting/)
- [Microsoft Q&A — Process info missing from EID 3](https://learn.microsoft.com/en-us/answers/questions/417625/process-information-missing-from-network-connectio)

### Frameworks
- MITRE ATT&CK — [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- MITRE ATT&CK — [T1021.006 Windows Remote Management](https://attack.mitre.org/techniques/T1021/006/)
- MITRE ATT&CK — [T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)

---

*Documento elaborado como parte del Home SOC Lab — [Thomas / thomas-cybersec](https://github.com/thomas-cybersec/Projects).*
*Escenario relacionado: [Enumeración de Windows vía WinRM](../scenarios/windows-enumeration-via-winrm.md).*
