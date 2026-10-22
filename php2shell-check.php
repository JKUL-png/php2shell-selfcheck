<?php
/**
 * php2shell-check.php — check the PHP version that serves YOUR website
 * for PHP2Shell (CVE-2026-109618 / CVE-2026-109619).
 *
 * For shared hosting, where you can upload files but can't run commands.
 *
 * How to use:
 *   1. Change SECRET below to a long random string only you know (at least 8 characters).
 *   2. Upload this file to your site (e.g. with your hosting file manager).
 *   3. Open https://your-site.com/php2shell-check.php?key=YOUR_SECRET
 *   4. Read the result, then DELETE the file.
 *
 * Safety:
 *   - Only shows a result with the right key; anyone else gets a 404.
 *   - Stops working by itself 24 hours after the file was last modified
 *     (upload or edit). If your FTP client keeps old timestamps, it may expire at once.
 *   - Shows only the PHP version and status — no phpinfo(), paths or settings.
 *   - Makes no network requests and changes nothing.
 *
 * Written to run on PHP 5.6 and newer, so it can also report on very old servers.
 *
 * License: MIT. Use only on websites you own or administer.
 */

const SECRET = 'change-me';
const MAX_AGE_SECONDS = 86400; // 24 hours after upload

function not_found()
{
    http_response_code(404);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Not Found\n";
    exit;
}

// Refuse to run with the default secret, after it expires, or without the right key.
$age = time() - (int) @filemtime(__FILE__);
$key = (isset($_GET['key']) && is_string($_GET['key'])) ? $_GET['key'] : '';
if (SECRET === 'change' . '-me' || strlen(SECRET) < 8) {
    http_response_code(403);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Edit this file and set SECRET to a random word of at least 8 characters before uploading.\n";
    exit;
}
if ($age > MAX_AGE_SECONDS || $age < -300 || !hash_equals(SECRET, $key)) {
    not_found();
}

header('Content-Type: text/html; charset=utf-8');
header('Cache-Control: no-store');
header('X-Robots-Tag: noindex, nofollow');
header('Referrer-Policy: no-referrer');

$fixed = [
    '8.5' => '8.5.12',
    '8.4' => '8.4.27',
    '8.3' => '8.3.36',
    '8.2' => '8.2.35',
];

// Compare the plain x.y.z number; PHP_VERSION may carry a vendor suffix.
$version = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION . '.' . PHP_RELEASE_VERSION;
$branch  = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
$sapi    = PHP_SAPI;

if (isset($fixed[$branch]) && version_compare($version, $fixed[$branch], '>=')) {
    $status = 'patched';
    $title  = 'Patched';
    $text   = "PHP $version is at or above the fixed version {$fixed[$branch]}.";
} elseif (isset($fixed[$branch])) {
    $status = 'check';
    $title  = 'Probably vulnerable — confirm with your host';
    $text   = "PHP $version is below the fixed version {$fixed[$branch]}. "
            . "Some Linux distributions (Ubuntu, Debian, cPanel/CloudLinux) patch older version numbers without changing them, "
            . "so this site may still be fixed. Ask your hosting provider.";
} elseif (version_compare($branch, '8.5', '>')) {
    $status = 'patched';
    $title  = 'Newer than the fixed branches';
    $text   = "PHP $branch was released after the fix and should include it. Confirm in its release notes.";
} else {
    $status = 'eol';
    $title  = 'Unsupported PHP version';
    $text   = "PHP $branch no longer receives fixes from PHP. Unless your host installed a vendor backport, "
            . "this site is exposed. Ask your host to move you to PHP 8.4 or 8.5.";
}

$colors = ['patched' => '#1a7f37', 'check' => '#9a6700', 'eol' => '#cf222e'];
$color  = $colors[$status];
$hoursLeft = max(0, (int) floor((MAX_AGE_SECONDS - $age) / 3600));

function e($s)
{
    return htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
}
?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>PHP2Shell check</title>
<style>
  body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background: #f6f8fa; color: #1f2328; margin: 0; padding: 16px; }
  main { max-width: 640px; margin: 24px auto; background: #fff; border: 1px solid #d0d7de; border-radius: 12px; padding: 24px; }
  h1 { font-size: 20px; margin: 0 0 4px; }
  .sub { color: #59636e; margin: 0 0 20px; font-size: 14px; }
  .status { border-left: 6px solid <?= e($color) ?>; padding: 12px 16px; background: #f6f8fa; border-radius: 6px; }
  .status strong { color: <?= e($color) ?>; font-size: 18px; }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: 6px 16px; margin: 20px 0; font-size: 15px; }
  dt { color: #59636e; }
  dd { margin: 0; font-family: ui-monospace, Menlo, Consolas, monospace; }
  h2 { font-size: 16px; margin: 24px 0 8px; }
  li { margin: 6px 0; }
  .delete { margin-top: 24px; padding: 12px 16px; background: #fff8c5; border: 1px solid #d4a72c; border-radius: 6px; font-weight: 600; }
</style>
</head>
<body>
<main>
  <h1>PHP2Shell check</h1>
  <p class="sub">CVE-2026-109618 / CVE-2026-109619 · read-only</p>

  <div class="status">
    <strong><?= e($title) ?></strong>
    <p><?= e($text) ?></p>
  </div>

  <dl>
    <dt>PHP version</dt><dd><?= e(PHP_VERSION) ?></dd>
    <dt>Server API</dt><dd><?= e($sapi) ?></dd>
    <dt>Fixed in</dt><dd><?= e(isset($fixed[$branch]) ? $fixed[$branch] : 'no official fix for this branch') ?></dd>
  </dl>

  <?php if ($status !== 'patched'): ?>
  <h2>What to do</h2>
  <ol>
    <li>Ask your host: “Is PHP on my site patched for CVE-2026-109618 and CVE-2026-109619? Which version and when?”</li>
    <li>In your hosting panel, switch to PHP 8.4 or 8.5 if it's available (test your site afterwards).</li>
    <li>Updating WordPress or plugins does <em>not</em> fix this. PHP itself must be updated.</li>
    <li>If you run your own server, use <code>php2shell-selfcheck.sh</code> instead — it can detect distro backports.</li>
  </ol>
  <?php endif; ?>

  <div class="delete">Delete this file from your site now. It stops working on its own in about <?= (int) $hoursLeft ?> hour(s).</div>
</main>
</body>
</html>
