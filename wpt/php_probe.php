<?php
/**
 * wpt runtime probe (wpt/php_probe.php) — the diagnostic that still answers
 * when WordPress itself cannot load.
 *
 * NOT the bridge: this file loads no WordPress, includes no other file and
 * touches no database, PDO or wp-config.php.  It exists for the exact state a
 * bridge can never report: a broken WordPress loader, a dead database or a
 * missing PDO driver.  The Python client deploys ONE copy under a fresh
 * wpt-probe-<8hex>.php name at the webroot root, replacing the two string
 * literals below with:
 *   - a fresh 32-lowercase-hex token, compared with hash_equals();
 *   - a unix timestamp; after it every request is refused.
 *
 * Wire contract:
 *   expired              -> HTTP 410 text/plain "expired"
 *   missing/wrong token  -> HTTP 403 text/plain "forbidden"
 *   authenticated        -> HTTP 200 application/json (runtime facts)
 *
 * The authenticated answer is deliberately narrow: PHP's version/SAPI, the
 * loaded extensions, five extension booleans, a handful of ini values and the
 * session-cookie policy.  No credentials, no DB configuration, no PHP
 * configuration dump and no filesystem listing — a probe that leaks those
 * would be a backdoor wearing a diagnostic's name.
 */

$wpt_token = '__WPT_TOKEN__';
$wpt_expires = '__WPT_EXPIRES__';

// Expiry BEFORE auth: a dead probe must answer nothing, even to a leaked
// token.  Strict '>' matches the sweep's "embedded expiry < now" delete
// rule: at the exact expiry second both sides still treat the file as live.
if ( time() > $wpt_expires ) {
	http_response_code( 410 );
	header( 'Content-Type: text/plain' );
	echo 'expired';
	exit;
}

// The is_string() guard is part of the gate, not decoration: `?token[]=x`
// arrives as an array, and PHP 8's hash_equals() raises a TypeError for it
// instead of answering the 403 that every unauthenticated request is owed.
if ( ! isset( $_GET['token'] ) || ! is_string( $_GET['token'] )
	|| ! hash_equals( $wpt_token, $_GET['token'] ) ) {
	http_response_code( 403 );
	header( 'Content-Type: text/plain' );
	echo 'forbidden';
	exit;
}

$wpt_extensions = get_loaded_extensions();
sort( $wpt_extensions );

$wpt_ini = array(
	'display_errors'     => ini_get( 'display_errors' ),
	'allow_url_include'  => ini_get( 'allow_url_include' ),
	'open_basedir'       => ini_get( 'open_basedir' ),
	'disable_functions'  => ini_get( 'disable_functions' ),
	'memory_limit'       => ini_get( 'memory_limit' ),
	'max_execution_time' => ini_get( 'max_execution_time' ),
);

// Every value is ini_get()'s own answer.  A directive an older runtime does
// not know (cookie_samesite before 7.3) answers boolean false, which is the
// honest fact — never a fabricated empty string.
$wpt_session = array(
	'use_strict_mode'  => ini_get( 'session.use_strict_mode' ),
	'cookie_httponly'  => ini_get( 'session.cookie_httponly' ),
	'cookie_samesite'  => ini_get( 'session.cookie_samesite' ),
	'use_only_cookies' => ini_get( 'session.use_only_cookies' ),
	'use_trans_sid'    => ini_get( 'session.use_trans_sid' ),
);

$wpt_payload = array(
	'ok'          => true,
	'php_version' => PHP_VERSION,
	'php_sapi'    => PHP_SAPI,
	'extensions'  => $wpt_extensions,
	'pdo_mysql'   => extension_loaded( 'pdo_mysql' ),
	'mysqli'      => extension_loaded( 'mysqli' ),
	'mbstring'    => extension_loaded( 'mbstring' ),
	'curl'        => extension_loaded( 'curl' ),
	'openssl'     => extension_loaded( 'openssl' ),
	'ini'         => $wpt_ini,
	'session'     => $wpt_session,
	'time'        => time(),
	'expires'     => $wpt_expires,
);

header( 'Content-Type: application/json' );
$wpt_json = json_encode( $wpt_payload );
if ( false === $wpt_json ) {
	// An ini value can carry non-UTF-8 bytes on an old target.  Answer a JSON
	// object anyway, so the client's non-JSON branch is not what diagnoses it.
	$wpt_json = '{"ok":false,"error":"probe JSON encoding failed"}';
}
echo $wpt_json;

// Self-destruct AFTER the answer entered the SAPI buffer: a successful call
// must not leave an executable token-gated file behind.  destroy() covers a
// host that refuses unlink, and the stale sweep covers every call that never
// reached this line.  function_exists() is the gate, not decoration: a host
// with unlink in disable_functions raises a FATAL Error on the call (PHP 8),
// and the error HTML would corrupt a valid JSON answer.  Self-delete is
// optional; destroy/sweep are the lifecycle owners.
if ( function_exists( 'unlink' ) ) {
	@unlink( __FILE__ );
}
