# Home SOC Lab 

Laboratorio personal de detección montado en VirtualBox. El objetivo fue construir un entorno con segmentación de red real, un SIEM aislado y telemetría enriquecida en endpoints Windows, replicando cómo se diseñaría una arquitectura defensiva en una organización chica —no seguir un tutorial, sino armar algo que pueda defender técnicamente en una entrevista.

---

## Stack

| Componente | Versión | Rol |
|---|---|---|
| pfSense | 2.7.2 | Firewall, NAT, segmentación, host de Suricata |
| Wazuh | 4.7.5 (All-in-One) | SIEM (Indexer + Manager + Dashboard) |
| Ubuntu Server | 22.04 LTS | Base del SIEM |
| Windows Server | 2025 | Endpoint víctima (`SV-WEB-01`) |
| Sysmon | 15.x + config SwiftOnSecurity | Telemetría de endpoint |
| Kali Linux | 2024.x | Máquina atacante |
| Sliver | build `devel` | Framework de Command & Control |
| Suricata | paquete pfSense | IDS de red |

### Esquema de IPs

> Verificar contra la configuración real: nombres de red interna (VirtualBox) e interfaces de pfSense.

| Segmento | Red interna (VBox) | Gateway (pfSense) | Host | IP |
|---|---|---|---|---|
| ATK | `REDKALI` | 192.168.10.1 | Kali Linux (atacante) | 192.168.10.10 |
| DMZ | `REDDMZ` | 192.168.20.1 | Windows Server 2025 (`SV-WEB-01`) | 192.168.20.10 |
| MGMT | `REDMGMT` | 192.168.30.1 | Wazuh 4.7.5 (SIEM) | 192.168.30.10 |
| WAN | — | DHCP | pfSense hacia router doméstico (doble NAT) | — |

---

## Arquitectura del laboratorio

```
                        Internet (router doméstico)
                                   │
                          ┌────────┴────────┐
                          │     pfSense     │  Firewall + NAT + Suricata IDS
                          │  Default deny   │
                          └────────┬────────┘
          ┌───────────────────────┼───────────────────────┐
     REDKALI                  REDDMZ                   REDMGMT
   192.168.10.1              192.168.20.1             192.168.30.1
          │                       │                       │
 ┌────────┴─────────┐   ┌─────────┴──────────┐  ┌─────────┴─────────┐
 │  Kali Linux      │   │ Windows Server 2025│  │ Wazuh 4.7.5       │
 │  192.168.10.10   │   │ 192.168.20.10      │  │ 192.168.30.10     │
 │  (Atacante)      │   │ (Víctima/SV-WEB-01)│  │ (SIEM / MGMT)     │
 │  Sliver C2       │   │ Sysmon + Ag. Wazuh │  │ Ubuntu 22.04      │
 └──────────────────┘   │ Defender / AMSI    │  └───────────────────┘
   Red interna "ATK"     └────────────────────┘   Red interna "MGMT"
                          Red interna "DMZ"

Beaconing:  WinSrv(20.10) ── HTTPS/443 ──> pfSense ──> Kali(10.10)   [cruza pfSense → visible para Suricata]
Telemetría: WinSrv(20.10) ── 1514/1515 ──> pfSense ──> Wazuh(30.10)
```

### Tráfico permitido entre zonas

| Origen | Destino | Puertos | Para qué |
|---|---|---|---|
| ATK | DMZ | 80, 443, 3389 | Simular ataques externos |
| DMZ | MGMT | 1514, 1515 | Telemetría del agente Wazuh |
| MGMT | Internet | 80, 443 | Updates del SIEM (salida controlada) |

Todo lo demás está bloqueado por defecto. En particular, **ATK no puede alcanzar MGMT** — el SIEM tiene que ser invisible para el atacante.

---

## Decisiones de diseño

**Por qué el SIEM va aislado y sin salida libre a internet.** La intuición inicial era armar todo en una LAN plana para simplificar. Al leer casos de incidentes donde el atacante compromete el SIEM para borrar evidencia, quedó clara la razón: MGMT solo tiene salida controlada a 80/443 para updates, y nada más. El sistema que registra la evidencia no puede ser accesible desde el segmento donde ocurre el ataque.

**Por qué las reglas se aplican en la interfaz de origen, no de destino.** En pfSense, una regla "DMZ → MGMT en 1514" se define en la interfaz **DMZ**, porque es donde el tráfico *entra* al firewall. Esto se conecta con que pfSense es *stateful*: si la conexión la inicia el agente, el tráfico de respuesta vuelve solo, sin necesidad de una regla explícita de retorno.

**Por qué Wazuh All-in-One y no distribuido.** Para un lab, All-in-One es suficiente. En producción se separan Indexer / Manager / Dashboard en nodos distintos por escalabilidad (el Indexer consume mucha RAM a medida que crece el EPS) y por tolerancia a fallos; el Indexer se clusteriza normalmente en al menos 3 nodos para mantener quórum.

**Por qué Sysmon con la config de SwiftOnSecurity.** Sysmon sin configuración no captura nada útil. La config de SwiftOnSecurity es el estándar de facto en blue teams porque filtra el ruido del sistema y captura las señales relevantes, alineadas con MITRE ATT&CK. Es una de las primeras cosas que revisa cualquier analista que arranca en un SOC.

---

## Lo que aprendí rompiendo cosas

Cada entrada sigue el formato que usaría para documentar un troubleshooting en un SOC: síntoma observable, causa raíz, resolución y lección transferible.

### Reset completo de Wazuh tras *configuration drift*

- **Síntoma:** los daemons críticos no levantaban (`wazuh-modulesd`, `wazuh-analysisd`, `wazuh-execd`, `wazuh-remoted`) y el dashboard devolvía HTTP 500.
- **Causa raíz:** credenciales y certificados desincronizados entre componentes tras un intento de instalación previo — *configuration drift* en un stack fuertemente acoplado.
- **Resolución:** en lugar de parchear componente por componente, desinstalé y reprovisioné limpio.
- **Lección:** en stacks fuertemente acoplados, reprovisionar es más rápido y confiable que parchear estado corrupto. Es el principio de *"cattle, not pets"* aplicado a infraestructura.

### `cloud-init` pisando la configuración de red en cada reboot

- **Síntoma:** la IP estática del SIEM se reseteaba en cada reinicio.
- **Causa raíz:** dos archivos de netplan coexistiendo (uno del instalador, otro generado por `cloud-init`); el de `cloud-init` sobrescribía al del instalador en cada boot.
- **Resolución:** deshabilité la gestión de red de `cloud-init` con `/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg`.
- **Lección:** cuando dos sistemas gestionan el mismo recurso, uno gana de forma no determinista. Hay que definir explícitamente cuál tiene autoridad.

### *Block private networks* en la WAN de pfSense

- **Síntoma:** no podía acceder al dashboard de Wazuh desde mi equipo en la LAN doméstica.
- **Causa raíz:** la regla *"Block private networks"* viene activada por defecto en la WAN de pfSense para prevenir spoofing de rangos privados desde internet. Como pfSense está doblemente NAT-eado dentro de la LAN de casa, esa regla bloqueaba mi propio tráfico legítimo.
- **Resolución:** la deshabilité **solo para el contexto del lab**.
- **Lección:** una protección por defecto es correcta hasta que el contexto de red cambia. En producción, esa regla es crítica y no se toca — entender *por qué* está ahí es lo que permite decidir cuándo aplica.

### Higiene de credenciales en la CLI

- **Síntoma:** durante el debugging escribí una contraseña en `curl -u user:pass`, que queda en el historial de bash en texto plano.
- **Causa raíz:** el patrón `usuario:contraseña` inline expone el secreto en `~/.bash_history` y en la tabla de procesos.
- **Resolución:** usar `curl -u admin` (sin contraseña, la pide de forma interactiva) o cargar el secreto con `read -s` en una variable.
- **Lección:** un hábito menor en un lab es, con datos reales, un incidente reportable. El reflejo se entrena antes de que importe.

---

## Estado actual

- Wazuh recibe eventos del Windows Server en tiempo real.
- Sysmon captura *process create*, *network connection*, *registry value set* y *DNS query*.
- El módulo MITRE ATT&CK ya está enriqueciendo eventos con técnicas mapeadas (T1078, T1562.001, T1059.001, entre otras) sobre la actividad de base del sistema; el siguiente paso es generar detecciones a partir de actividad ofensiva controlada.
- Toda la cadena sobrevive un reboot completo (servicios habilitados en el arranque).

---

## Detecciones documentadas

> Sección en construcción. Enlaces a los writeups de detección generados con este lab
> (p. ej. *RDP brute force*, post-explotación vía WinRM). Cada writeup: contexto del ataque →
> telemetría observada (Event IDs / reglas Wazuh) → lógica de detección → mapeo ATT&CK.

- _(pendiente de enlazar)_

---

## Referencias

- Documentación oficial de Wazuh y pfSense.
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config) — config estándar de facto.
- [MITRE ATT&CK](https://attack.mitre.org/) — mapeo de técnicas.

---

## Sobre este proyecto

Armé este lab como parte de mi camino hacia blue team / SOC. Cada decisión de arquitectura está justificada, y los problemas que encontré están registrados como *Lessons Learned*. El objetivo no fue seguir un tutorial, sino construir un entorno que entienda a fondo y pueda defender técnicamente.

Durante el desarrollo usé asistencia de IA (Claude) para debugging técnico, validación de decisiones arquitectónicas y armado de documentación. Las decisiones de diseño y la comprensión técnica son propias y verificables.

---

**Autor:** Thomas Coria
