# php2shell-selfcheck

**Check your own server or website for PHP2Shell** ([CVE-2026-109618](https://nvd.nist.gov/vuln/detail/CVE-2026-109618) / [CVE-2026-109619](https://nvd.nist.gov/vuln/detail/CVE-2026-109619)), the critical PHP remote code execution bugs patched on October 21, 2026.

[Leer en español](README.es.md)

Two small tools, depending on how your site is hosted:

| You have... | Use |
|---|---|
| A server you can SSH into (VPS, dedicated, cloud VM) | `php2shell-selfcheck.sh` |
| Shared hosting where you can only upload files | `php2shell-check.php` |

Both are **read-only**, make **no network requests**, and **never test, trigger or exploit** the vulnerability. They only read version information and point you to the fix.

> ⚠️ Use these tools only on systems you own or are authorized to administer. Do not run them against other people's sites — they're not designed for that, and scanning systems without permission can be illegal.

## Fixed versions

| PHP branch | Fixed in |
|---|---|
| 8.5 | **8.5.12** |
| 8.4 | **8.4.27** |
| 8.3 | **8.3.36** |
| 8.2 | **8.2.35** |
| 8.1 and older | No official release. Upgrade, or use a vendor/distro backport. |

Some distributions fix the bug without changing the version number. For example, Ubuntu 24.04's patched package is `8.3.6-0ubuntu0.24.04.13`. The script knows the exact patched package versions for Ubuntu 22.04, 24.04 and 26.04. For other distributions (Debian, RHEL/Alma/Rocky, CloudLinux) it looks for the CVE in the installed package's changelog. RHEL-family changelogs sometimes only say "rebase", so the script may report "vulnerable" until you confirm with `dnf updateinfo list --security`.

**Updating WordPress, Drupal, Joomla or plugins does not fix this. PHP itself has to be updated.**

## 1. Server check: `php2shell-selfcheck.sh`

```bash
curl -fsSLO https://raw.githubusercontent.com/jkul-png/php2shell-selfcheck/main/php2shell-selfcheck.sh
less php2shell-selfcheck.sh        # read it first — it's short
sudo bash php2shell-selfcheck.sh
```

What it does:

- Finds PHP on the machine: CLI, PHP-FPM, CGI, LiteSpeed `lsphp`, cPanel EA-PHP, CloudLinux alt-php, Remi, Red Hat SCL, Bitnami, Plesk and FrankenPHP. It only runs binaries owned by root that other users can't modify, with a 5-second timeout.
- Compares each version against the fixed releases.
- Detects distro backports (see above). Pre-release builds (RC, beta, dev) are reported as unknown, never as patched.
- Warns if Apache `mod_php` is enabled (the most exposed setup) and reminds you that `reload` isn't enough.
- With `sudo`, checks running processes. It flags PHP that was updated on disk while the old copy is still running (so you need to restart), the Apache PHP module that's actually loaded, and running PHP it didn't check, for example inside a container.

Optional hints of compromise (not proof):

```bash
sudo bash php2shell-selfcheck.sh --webroot /var/www/html --log /var/log/apache2/error.log
```

- Lists `.php` files whose modification time or inode change time is after 2026-10-17, when the first exploitation attempt was reported. Using both catches files whose date was faked.
- Flags `.php` files inside `uploads` folders.
- Counts `Allowed memory size` errors in logs.

Exit codes: `0` everything checked is patched · `1` vulnerable / unsupported · `2` incomplete (something couldn't be checked, including running without `sudo`) · `3` patched on disk but a restart is needed.

Docker: copy the script into the container and run it there:

```bash
docker cp php2shell-selfcheck.sh <container>:/tmp/
docker exec -it <container> bash /tmp/php2shell-selfcheck.sh
```

Alpine-based images (like `php:*-alpine`) don't include bash. Install it first with `apk add bash coreutils findutils`, or just run `docker exec <container> php -v` and compare with the table above. To update, pull the new image and recreate the container.

## 2. Shared hosting check: `php2shell-check.php`

1. Open the file and change `SECRET` to a long random string (at least 8 characters; longer is better).
2. Upload it to your site with your hosting file manager.
3. Visit `https://your-site.com/php2shell-check.php?key=YOUR_SECRET`
4. Read the result, then **delete the file**.

Safety built in:

- Without the right key it returns 404.
- It refuses to run with the default key.
- It stops working 24 hours after the file was last modified (when you uploaded or edited it). Some FTP clients keep the original date, which can make it expire immediately. If that happens, edit and save it again on the server.
- It shows only the PHP version and status, never `phpinfo()`.

The key travels in the URL, so it can end up in your server's access logs. That's one more reason to delete the file when you're done.

The page can't see distro backports, so a "probably vulnerable" result means **ask your host**. You can use this message:

> Is PHP on my site patched for CVE-2026-109618 and CVE-2026-109619? Which PHP version am I on, and when was it patched?

## If you're vulnerable

1. Update PHP (or ask your host to). Prefer 8.4 or 8.5 if you're on 8.1 or older.
2. Restart every PHP process: PHP-FPM, a full Apache stop/start for `mod_php`, `pkill lsphp` for LiteSpeed, and queue workers.
3. Run the check again.
4. If you can't patch right away, consider taking the site offline until you can (CISA guidance).
5. Look for signs of compromise since 2026-10-17. If you find any, isolate the server, keep the logs, and rotate passwords, API keys and tokens the server held. In the US you can report it at [ic3.gov](https://www.ic3.gov).

## Want to help other sites?

Please don't scan the internet looking for vulnerable sites, even with good intentions. In the US that can violate the Computer Fraud and Abuse Act and state laws. Better options:

- Share this tool and the official advisories.
- Organizations like the [Shadowserver Foundation](https://www.shadowserver.org) and national CERTs already notify network owners about exposed systems, with legal authority to do so. Network owners can subscribe to their free reports.
- Report bugs you find through a site's own security contact (`/.well-known/security.txt`) or its bug bounty program, within its rules.

## Official sources

- [CISA alert (Oct 21, 2026)](https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching)
- [CERT-EU advisory 2026-018](https://cert.europa.eu/publications/security-advisories/2026-018/)
- [NCSC (UK)](https://www.ncsc.gov.uk/news/critical-security-issue-affecting-php)
- [NCSC-NL list of software that embeds PHP](https://github.com/NCSC-NL/php2shell)
- [Patching guide by distro (ma.ttias.be)](https://ma.ttias.be/php-cve-2026-109618-patch/)

## Tests

```bash
bash tests/run-tests.sh
```

## Disclaimer

Provided as-is, without warranty. A "patched" result means the version matches a fixed release. It does not mean the server was never compromised. This is not legal or professional security advice.

## License

MIT
