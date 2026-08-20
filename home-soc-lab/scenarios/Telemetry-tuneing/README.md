# Wazuh Windows Telemetry Tuning — cierre de gaps de visibilidad

Tres puntos ciegos de detección identificados en el [escenario de post-explotación vía WinRM](../../scenarios/winrm-post-exploitation/) resultaron no ser errores de configuración, sino **decisiones conservadoras de la instalación por defecto** de Wazuh y SwiftOnSecurity, que priorizan estabilidad inicial sobre profundidad de telemetría. Este documento resume qué se cambió en cada caso, el código escrito para cerrarlos, y las limitaciones técnicas —no evidentes— que aparecieron durante el proceso. El formato del[escenario de laboratorio se encuentra aqui](../../../home-soc-lab/)

## El problema de fondo

Durante el escenario, un ataque fue **bloqueado por Microsoft Defender**, pero el SOC no recibió ninguna alerta: el agente Wazuh no estaba suscrito al canal donde Defender registra ese bloqueo. La prevención funcionó; la detección falló. Prevención sin detección es un muro ciego —un atacante puede iterar hasta evadir la firma sin que el equipo defensivo se entere. El mismo patrón (telemetría existente pero no recolectada, o recolectada pero sin regla que la eleve a alerta) se repetía en la actividad PowerShell en memoria y en las conexiones de red salientes.

---

## Gap 1 — Canal de Microsoft Defender

Defender bloqueó el ataque y lo registró localmente (Event ID 1117), pero el agente no estaba suscrito al canal `Windows Defender/Operational`, así que ese evento nunca llegaba al SOC. **No requiere una regla custom**: alcanza con suscribir el canal en el `ossec.conf` del agente. Una vez suscrito, las reglas **nativas** de Wazuh 62124 (nivel 3) y 62123 (nivel 12) disparan solas.

```xml
<localfile>
  <location>Microsoft-Windows-Windows Defender/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

---

## Gap 2 — PowerShell script-block logging

Cmdlets in-process como `Get-LocalUser` no crean un proceso hijo visible a Sysmon, y PowerShell no loguea su propio código por defecto: la enumeración quedaba invisible. El cierre tiene dos partes.

Primero, habilitar el **Event ID 4104** (script-block logging) en el registro de Windows:

```powershell
$regPath = "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $regPath -Force | Out-Null
New-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWORD -Force
```

Segundo —y acá está el trabajo real de SOC engineering— **las dos únicas reglas custom del proyecto**, en `local_rules.xml` (ambas dentro de un mismo bloque `<group name="local,windows,powershell,">`).

La **100100** detecta por **contenido**: busca cadenas de descarga remota dentro del texto del script.

```xml
<rule id="100100" level="10">
  <if_sid>91802</if_sid>
  <field name="win.eventdata.scriptBlockText" type="pcre2">(?i)DownloadString|IEX|Invoke-Expression</field>
  <description>PowerShell: descarga remota detectada via DownloadString</description>
  <mitre>
    <id>T1059.001</id>
    <id>T1105</id>
  </mitre>
</rule>
```

La **100102** detecta por **metadato**: cualquier proceso cuyo padre sea `wsmprovhost.exe`, es decir, actividad originada en una sesión WinRM.

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

La diferencia entre ambas es el concepto central del proyecto: la 100100 mira el **contenido** del script (frágil —se trunca u ofusca) y la 100102 mira un **metadato** que siempre llega completo (robusto). Se complementan: una garantiza la detección, la otra aporta el detalle de qué se intentó ejecutar.

---

## Gap 3 — Sysmon EID 3 (Network Connect)

La config de SwiftOnSecurity tenía NetworkConnect filtrado, así que las descargas salientes no generaban telemetría. **Tampoco lleva regla custom**: el cierre es reconfigurar Sysmon y **reiniciar el equipo** (el servicio corre como *protected process* y no admite `Restart-Service`).

```powershell
C:\Windows\Sysmon64.exe -c C:\sysmonconfig.xml
Restart-Computer -Force
```

Hallazgo importante: EID 3 resultó **poco confiable para WinRM**. En sesiones remotas los procesos son tan efímeros que Sysmon no logra asociarles información de proceso y descarta el evento. Por eso la detección real de actividad WinRM **no se apoya en EID 3**, sino en Sysmon EID 1 mediante la regla 100102 del Gap 2. El Gap 3 aportó, sobre todo, la lección de por qué EID 3 no alcanzaba.

---

## Cobertura consolidada

Estado de detección antes y después de los tres cambios, con el mecanismo responsable en cada caso:

| Actividad de ataque | Antes | Después | Gap / mecanismo |
|---|---|---|---|
| Bloqueo de AMSI / Defender | Invisible al SOC | Alerta nivel 12 (reglas nativas 62123 / 62124) | Gap 1 — suscripción del canal |
| Enumeración y ejecución vía WinRM (`whoami`, `Get-LocalUser`) | Invisible al SOC | Alerta nivel 10 (regla 100102) | Gap 2 — metadato `parentImage` |
| Descarga remota en memoria (`IEX` / `DownloadString`) | Solo lo veía Defender | Alerta nivel 10 (regla 100100) ¹ | Gap 2 — contenido `scriptBlockText` |
| Conexiones salientes del endpoint | No capturadas | Sysmon EID 3 visible ² | Gap 3 — reconfiguración de Sysmon |

¹ Falla si el script supera los ~64 KB (ver Limitaciones). &nbsp; ² Inconsistente en sesiones WinRM; cobertura confiable vía EID 1.

---

## Limitaciones técnicas descubiertas

Lo que distingue este trabajo no es la configuración en sí, sino los límites reales que aparecieron al validarla de punta a punta:

- **Límite de 65.535 bytes del manager Wazuh.** Cualquier evento mayor se trunca de forma silenciosa ([issue #17689](https://github.com/wazuh/wazuh/issues/17689)). Scripts como PowerUp.ps1 (~600 KB) superan ese límite por un orden de magnitud, y una regla que dependa del contenido completo (como la 100100) puede fallar sin previo aviso. Es una limitación arquitectónica, no una flag: la respuesta correcta es diseñar reglas que no dependan del contenido íntegro —exactamente lo que hace la 100102.
- **Sysmon EID 3 requiere reinicio y es inconsistente con procesos efímeros.** El servicio corre como *protected process* (no se reinicia sin reboot completo), y en sesiones WinRM los procesos son tan cortos que Sysmon a menudo no logra asociarles información y descarta el evento. Conclusión: EID 3 es inadecuado como única fuente para detectar lateral movement vía WinRM; la cobertura confiable combina Sysmon EID 1 (`parentImage=wsmprovhost.exe`) y Windows Event 5156.

---

## Lecciones

1. **Habilitar una fuente no es tener detección.** Cada gap necesitó dos pasos: activar la telemetría *y* verificar/escribir la regla que la eleva a alerta. Documentar lo primero sin lo segundo es un portfolio engañoso.
2. **La detección por metadatos supera a la de contenido.** Los metadatos del evento (`parentImage`, `processName`, `severity`) llegan siempre completos; el contenido puede truncarse, ofuscarse o directamente faltar.
3. **Documentar las limitaciones vale más que ocultarlas.** El límite de 64 KB y la inconsistencia de EID 3 son fallas de detección reales que la mayoría de los analistas desconoce. Nombrarlas explícitamente distingue "configuré las cosas" de "entiendo dónde y cómo puede fallar la detección".
4. **La validación real es el evento real.** `wazuh-logtest` valida sintaxis, no semántica; solo un evento reproducido de punta a punta confirma que una regla funciona.

---

*Parte del [Home SOC Lab](../../). Escenario relacionado: [Post-explotación en Windows vía WinRM](../../scenarios/winrm-post-exploitation/). La versión técnica completa —con comandos exactos, troubleshooting y procedimientos de rollback— se conserva como referencia reproducible.*
