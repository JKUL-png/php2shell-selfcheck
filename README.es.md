# php2shell-selfcheck (español)

**Revisa tu propio servidor o sitio web contra PHP2Shell** (CVE-2026-109618 / CVE-2026-109619), las fallas críticas de PHP corregidas el 21 de octubre de 2026.

[Read in English](README.md)

| Si tienes... | Usa |
|---|---|
| Un servidor al que entras por SSH (VPS, servidor dedicado, nube) | `php2shell-selfcheck.sh` |
| Hosting compartido donde solo puedes subir archivos | `php2shell-check.php` |

Las dos herramientas son **solo de lectura**, **no se conectan a internet** y **nunca prueban ni explotan** la falla. Solo leen la versión de PHP y te dicen cómo corregirla.

> ⚠️ Úsalas solo en sistemas que son tuyos o que administras con permiso. No las uses contra sitios de otras personas: no están hechas para eso, y escanear sistemas ajenos sin autorización puede ser ilegal.

## Versiones corregidas

| Rama de PHP | Corregida en |
|---|---|
| 8.5 | **8.5.12** |
| 8.4 | **8.4.27** |
| 8.3 | **8.3.36** |
| 8.2 | **8.2.35** |
| 8.1 o anterior | Sin versión oficial. Actualiza o usa un parche de tu distribución o proveedor. |

Algunas distribuciones corrigen la falla sin cambiar el número de versión. Por ejemplo, en Ubuntu 24.04 el paquete corregido es `8.3.6-0ubuntu0.24.04.13`. El script conoce las versiones corregidas exactas de Ubuntu 22.04, 24.04 y 26.04. En otras distribuciones (Debian, RHEL/Alma/Rocky, CloudLinux) busca las CVE en el registro de cambios (changelog) del paquete instalado. En la familia RHEL ese registro a veces solo dice "rebase", así que el script puede marcar "vulnerable" hasta que lo confirmes con `dnf updateinfo list --security`.

**Actualizar WordPress, Drupal, Joomla o los plugins no corrige esto. Hay que actualizar PHP.**

## 1. En tu servidor

```bash
curl -fsSLO https://raw.githubusercontent.com/jkul-png/php2shell-selfcheck/main/php2shell-selfcheck.sh
less php2shell-selfcheck.sh        # léelo antes de correrlo
sudo bash php2shell-selfcheck.sh
```

Córrelo con `sudo`. Sin `sudo` no puede revisar los procesos en ejecución, y el resultado queda como incompleto.

Para buscar señales de intrusión (son pistas, no pruebas):

```bash
sudo bash php2shell-selfcheck.sh --webroot /var/www/html --log /var/log/apache2/error.log
```

Códigos de salida: `0` todo lo revisado está corregido · `1` vulnerable o sin soporte · `2` incompleto (algo no se pudo revisar) · `3` corregido en disco, pero hay que reiniciar procesos.

Si usas Docker, copia el script al contenedor y córrelo ahí:

```bash
docker cp php2shell-selfcheck.sh <contenedor>:/tmp/
docker exec -it <contenedor> bash /tmp/php2shell-selfcheck.sh
```

## 2. En hosting compartido

1. Abre `php2shell-check.php` y cambia `SECRET` por una clave larga y aleatoria (mínimo 8 caracteres).
2. Súbelo a tu sitio con el administrador de archivos de tu hosting.
3. Abre `https://tu-sitio.com/php2shell-check.php?key=TU_CLAVE`
4. Lee el resultado y **borra el archivo**. Igual deja de funcionar solo 24 horas después de la última vez que se modificó (al subirlo o editarlo).

Si dice "probablemente vulnerable", pregúntale a tu hosting:

> ¿PHP en mi sitio ya tiene el parche para CVE-2026-109618 y CVE-2026-109619? ¿Qué versión tengo y cuándo se aplicó?

## Si estás afectado

1. Actualiza PHP, o pídele a tu hosting que lo haga. Si estás en 8.1 o anterior, pasa a 8.4 u 8.5.
2. Reinicia todos los procesos de PHP: PHP-FPM, `pkill lsphp` en LiteSpeed y los procesos en segundo plano (workers). Con Apache y `mod_php`, detén Apache por completo y vuelve a iniciarlo; `reload` o `graceful` dejan cargado el PHP viejo.
3. Vuelve a revisar.
4. Si no puedes actualizar ya, considera desconectar el sitio mientras tanto (recomendación de CISA).
5. Revisa señales de intrusión desde el 17 de octubre. Si encuentras algo, aísla el servidor, guarda los registros y cambia contraseñas, tokens y llaves de API que tuviera el servidor. En EE. UU. puedes reportarlo en [ic3.gov](https://www.ic3.gov).

## ¿Quieres ayudar a otros sitios?

No escanees internet buscando sitios vulnerables, aunque tengas buena intención: en EE. UU. puede violar la ley federal de acceso no autorizado a computadoras (CFAA) y leyes estatales. Mejor:

- Comparte esta herramienta y los avisos oficiales.
- Organizaciones como la [Shadowserver Foundation](https://www.shadowserver.org) y los equipos de respuesta de cada país (CERT) ya avisan a los dueños de redes, con autorización para hacerlo.
- Si encuentras una falla en un sitio, repórtala por su contacto de seguridad (`/.well-known/security.txt`) o su programa de recompensas, siguiendo sus reglas.

## Aviso

Se entrega tal cual, sin garantía. Que diga "corregido" significa que la versión es una versión corregida, no que el servidor nunca haya sido comprometido. No es asesoría legal ni de seguridad profesional.

## Licencia

MIT
