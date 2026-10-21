<?php
/**
 * wpt bridge (wpt/wpbridge/bridge.php) — SPEC §Bridge protocol (W4).
 *
 * Single-file, token-guarded WordPress bridge. The Python client uploads it
 * under a fresh random name, substituting the two string placeholders below
 * at upload time:
 *   __WPT_TOKEN__     32-hex random token (compared with hash_equals)
 *   __WPT_EXPIRES__   unix timestamp; after it every request 404s
 *
 * Wire contract:
 *   auth fail   -> plain-text HTTP 404 "nf" (NOT a WordPress page)
 *   selfdestruct=1 (+valid token) -> plain-text "gone" (file unlinked)
 *   success     -> HTTP 200 {"ok":true,...}  Content-Type: application/json
 *   Throwable   -> HTTP 200 {"ok":false,"error":msg,"type":class,"line":n} [L4]
 *   db_dump, and the read mode of media_rewrite_refs
 *                    -> HTTP 200 NDJSON stream (application/x-ndjson)
 *
 * Extension surface: the $wpt_actions registry near the bottom of this file.
 * Adding an op = one registry entry + one small handler (plus one client
 * method). Never arbitrary SQL: identifiers are whitelisted against
 * information_schema, and only the named handlers below mutate anything.
 */

// Bootstrap exactly per docs/research/R2.md (binding for W4).
define( 'WP_USE_THEMES', false );
define( 'WP_DISABLE_FATAL_ERROR_HANDLER', true );   // BEFORE wp-load: stop WP masking hard fatals
require_once __DIR__ . '/wp-load.php';
error_reporting( E_ALL );                            // AFTER wp-load: WP rewrites these during load
ini_set( 'display_errors', '1' );                    //   for JSON requests otherwise
if ( ! function_exists( 'get_plugins' ) ) {          // WP <= 6.7 needs the admin include
	require_once ABSPATH . 'wp-admin/includes/plugin.php';
}

/**
 * Empty PHP arrays encode as [], but these payloads are maps: cast empties
 * to stdClass so the wire type is always a JSON object.
 */
function wpt_map( array $a ) {
	return $a ? $a : new stdClass();
}

/**
 * Remove a live plaintext secret from an error string.
 *
 * WordPress hooks receive the plaintext `user_pass` (user_register) and may
 * throw it into their own message; only this op knows the generated value,
 * so the scrub happens HERE, at the owner, on every error path/rethrow. The
 * client/report layers cannot recover a bare secret from free text.
 */
function wpt_scrub_secret( $text, $secret ) {
	if ( ! is_string( $text ) || '' === $text ) {
		return (string) $text;
	}
	if ( ! is_string( $secret ) || '' === $secret ) {
		return $text;
	}
	// FAIL CLOSED.  A hook receives the just-generated plaintext and may
	// put ANY reversible spelling of it into its message: htmlspecialchars
	// with either quote policy (esc_html/esc_js), htmlentities, urlencode,
	// rawurlencode, json_encode, esc_url's numeric entities, an escape
	// sequence — and arbitrary combinations of them.  No finite variant
	// list can prove the text is clean, and a missed form is a live
	// credential in the envelope/log/report.  When a generated password
	// exists, the only provably safe diagnostic is a fixed one that never
	// echoes hook-derived text.  Callers still name the operation/class
	// around it, so the failure is actionable without the secret.
	return '[redacted] diagnostic withheld because a generated password exists';
}

/**
 * Plain-text 404 used for every failed auth check (must not look like a WP page).
 */
function wpt_bridge_not_found() {
	header( 'HTTP/1.1 404 Not Found' );
	header( 'Content-Type: text/plain' );
	echo 'nf';
	exit;
}

/**
 * Emit the JSON envelope and stop. $lenient (error path) substitutes invalid
 * UTF-8 instead of throwing, so error reporting can never itself fatal.
 *
 * The Content-Type is set ONLY while headers can still be set. A Throwable
 * raised after a streaming op already put rows on the wire reaches this
 * function with output sent, and PHP then emits "Warning: Cannot modify
 * header information - headers already sent by …" — with the bridge's
 * display_errors on, that warning is PRINTED, so it becomes the client's
 * FIRST NDJSON line and the client's own diagnosis ("malformed NDJSON line:
 * Warning: …") replaces the server's real reason. The envelope below is
 * still emitted either way: the body is the diagnosis, the header is only a
 * hint the streaming op already set.
 */
function wpt_bridge_send( array $payload, $lenient = false ) {
	$flags = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES;
	if ( $lenient ) {
		$json = json_encode( $payload, $flags | JSON_INVALID_UTF8_SUBSTITUTE );
		if ( false === $json ) {
			$json = '{"ok":false,"error":"response encoding failed"}';
		}
	} else {
		$json = json_encode( $payload, $flags | JSON_THROW_ON_ERROR );
	}
	if ( ! headers_sent() ) {
		header( 'Content-Type: application/json' );
	}
	echo $json, "\n";
	exit;
}

/**
 * Require/extract a list param. $required=false tolerates a missing key.
 */
function wpt_param_list( array $params, $key, $required = true ) {
	if ( ! isset( $params[ $key ] ) ) {
		if ( $required ) {
			throw new InvalidArgumentException( 'missing or non-array param: ' . $key );
		}
		return array();
	}
	if ( ! is_array( $params[ $key ] ) ) {
		throw new InvalidArgumentException( 'missing or non-array param: ' . $key );
	}
	return array_values( $params[ $key ] );
}

/**
 * List param coerced to strings.
 */
function wpt_param_str_list( array $params, $key, $required = true ) {
	$out = array();
	foreach ( wpt_param_list( $params, $key, $required ) as $v ) {
		if ( is_string( $v ) || is_int( $v ) || is_float( $v ) ) {
			$out[] = (string) $v;
		}
	}
	return $out;
}

/**
 * List param intval-cast to positive attachment/post IDs (0 and garbage dropped).
 */
function wpt_param_int_list( array $params, $key, $required = true ) {
	$out = array();
	foreach ( wpt_param_list( $params, $key, $required ) as $v ) {
		if ( is_int( $v ) || is_string( $v ) || is_float( $v ) ) {
			$iv = (int) $v;
			if ( $iv > 0 ) {
				$out[] = $iv;
			}
		}
	}
	return $out;
}

/**
 * How many chained size suffixes ``wpt_file_stem`` strips at most ('-300x233',
 * '-scaled', '-1024x768-scaled' …).  Mirrored, not chosen:
 * wpt/audit/media.py's _STEM_PASSES owns the same number for the offline
 * half, and tests/test_media_refs.py reads THIS constant out of the
 * deployed file and fails the suite if the two ever differ — a chained
 * suffix one side strips and the other keeps is a keep-set sibling the two
 * modes disagree about (the live half deletes what the offline half
 * protects).  Named for the same reason every other WPT_MEDIA_* bound is:
 * a bare literal in a loop condition is a fact nothing can pin.
 */
define( 'WPT_MEDIA_STEM_PASSES', 5 );

/**
 * Basename stem with WP size suffixes stripped repeatedly (L5): '-300x233',
 * '-scaled', including chained forms like 'img-scaled-1024x768'.
 * '2023/10/pic-300x233.jpg' -> 'pic'; 'pic.jpg' -> 'pic'.
 */
function wpt_file_stem( $name ) {
	$base = basename( (string) $name );
	$dot  = strrpos( $base, '.' );
	$stem = ( false === $dot ) ? $base : substr( $base, 0, $dot );
	for ( $i = 0; $i < WPT_MEDIA_STEM_PASSES; $i++ ) {
		$stripped = preg_replace( '/-(?:\d+x\d+|scaled)$/', '', $stem );
		if ( $stripped === $stem ) {
			break;
		}
		$stem = $stripped;
	}
	return $stem;
}

/**
 * "0644"-style permission string, or null when the path cannot be stat'ed.
 * R2 verdict 6: check for false FIRST (sprintf('%o', false) === '0' silently).
 */
function wpt_perms_str( $path ) {
	$p = @fileperms( $path );
	return ( false === $p ) ? null : substr( sprintf( '%o', $p ), -4 );
}

/**
 * Escape a backtick inside an SQL identifier (identifiers come from
 * information_schema; escaping keeps interpolation total, not hopeful).
 */
function wpt_backtick( $name ) {
	return str_replace( '`', '``', (string) $name );
}

/**
 * Base tables of the current schema — the whitelist for every identifier the
 * bridge interpolates (dump/restore/optimize).
 *
 * The atomic-restore scratch names are RESERVED and filtered out: they are
 * owned by db_restore_table, so they can never be a legitimate dump/restore/
 * optimize target, and exposing them would let a caller address (and, via a
 * first-call staging drop, destroy) a table it does not own.
 */
function wpt_table_whitelist() {
	global $wpdb;
	$rows = $wpdb->get_col( "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE'" );
	if ( ! is_array( $rows ) ) {
		return array();
	}
	$out = array();
	foreach ( $rows as $name ) {
		if ( is_string( $name ) && ! wpt_restore_scratch_name( $name ) ) {
			$out[] = $name;
		}
	}
	return $out;
}

/**
 * True for a name the atomic-restore swap reserves for its own scratch tables
 * ("<table>__wpt_<hex-token>__s" / "__o"). Only the bridge generates a name
 * matching this exact token pattern, so reserving it is safe.
 */
function wpt_restore_scratch_name( $name ) {
	return (bool) preg_match( '/__wpt_[0-9a-f]{8,16}__[so]$/', (string) $name );
}

/**
 * Shared core of the expired-transient count (db_audit) and delete (db_clean):
 * transients (_transient_ and _site_transient_) joined to their _timeout_
 * companion rows whose value is in the past.
 */
function wpt_expired_transients_sql( $head ) {
	global $wpdb;
	return $head . " FROM {$wpdb->options} t"
		. " INNER JOIN {$wpdb->options} s ON s.option_name = REPLACE( t.option_name, '_transient_', '_transient_timeout_' )"
		. " WHERE ( t.option_name LIKE '\\_transient\\_%' OR t.option_name LIKE '\\_site_transient\\_%' )"
		. " AND t.option_name NOT LIKE '%\\_transient\\_timeout\\_%'"
		. " AND s.option_value < UNIX_TIMESTAMP()";
}

/**
 * Run one mutating statement; surface wpdb failures instead of swallowing them.
 */
function wpt_db_delete_count( $sql ) {
	global $wpdb;
	$r = $wpdb->query( $sql );
	if ( false === $r ) {
		throw new RuntimeException( 'db error: ' . $wpdb->last_error );
	}
	return (int) $r;
}

/**
 * One NDJSON value, binary-safe: invalid-UTF-8 strings (BLOB columns) become
 * ["__wpt_b64__", "<base64>"] so every emitted line is valid JSON. W7 decodes
 * any 2-element array whose first element is that marker.
 */
function wpt_json_safe_cell( $v ) {
	if ( is_string( $v ) && 1 !== @preg_match( '//u', $v ) ) {
		return array( '__wpt_b64__', base64_encode( $v ) );
	}
	return $v;
}

/**
 * One NDJSON line. $lenient (a diagnostic's own line) substitutes invalid
 * UTF-8 instead of throwing, for the reason wpt_bridge_send carries it: a
 * failure line that cannot be ENCODED is not a failure line at all — the
 * encode throws INSIDE the handler, the stream ends with no answer, and the
 * real cause is gone behind a truncated stream and a PHP fatal on the
 * operator's live site. Row lines keep the strict encoder on purpose: a row
 * that cannot be encoded is a stream whose shape the client cannot trust,
 * and refusing it is the client's job, not something to paper over.
 */
function wpt_json_line( array $line, $lenient = false ) {
	$flags = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES;
	if ( $lenient ) {
		$json = json_encode( $line, $flags | JSON_INVALID_UTF8_SUBSTITUTE );
		if ( false === $json ) {
			$json = '{"ok":false,"error":"response encoding failed"}';
		}
		return $json . "\n";
	}
	return json_encode( $line, $flags | JSON_THROW_ON_ERROR ) . "\n";
}

function wpt_ndjson_out( array $line, $lenient = false ) {
	echo wpt_json_line( $line, $lenient );
	flush();
}

// ---------------------------------------------------------------------------
// Action handlers — one small function per registry entry.
// Contract: f( array $params ) -> array payload (dispatcher wraps it in
// {"ok":true,...}; a handler may set its own 'ok' => false for action-level
// refusals), or null for the one streaming op (db_dump) that emits its own
// headers and NDJSON output.
// ---------------------------------------------------------------------------

/**
 * info: site identity + plugin inventory + environment facts (all cheap,
 * side-effect-free reads — the audit's PHP/EOL report). Payload: wp_version,
 * siteurl, home, template, stylesheet, blog_public, permalink_structure
 * ('' = the site uses plain ?p=N permalinks — the harden action's
 * pretty-permalink gate reads it), locale (get_locale() — the SITE
 * locale: $wp_local_package from a localized build, overridden by the
 * WPLANG option when its row exists; the integrity check's
 * locale-resolution fallback tier), plugins
 * {file:{name,version,active}}, mu_plugins, uploads_basedir
 * (wp_upload_dir(null,false) — no mkdir side effect), uploads_error, abspath,
 * php_version, php_version_id, memory_limit, max_execution_time, sapi,
 * server_software, mysql_version (wpdb db_version(), null when unavailable),
 * db_version (the WordPress DATABASE SCHEMA version — the stored
 * ``db_version`` option, NOT the engine version above: it is what a core
 * update must advance, and null means the option is unreadable, which is
 * never the same as "0" — note the deliberate STRING cast: a stored
 * option is not an int in PHP, so every consumer normalizes it through
 * the client's own wire_int()), upgrade_marker (the pre-migration marker
 * ``core_upgrade`` writes before it migrates: {started, from_db_version,
 * target_db_version, wp_version, finished} — null when no migration ever
 * ran. It is what tells an operator the state a migration that FATALed
 * began in, the one failure that cannot report anything itself),
 * multisite (is_multisite() — the update-core
 * action's refusal gate, a fact no other consumer reads yet) and
 * wp_debug (bool WP_DEBUG, null when undefined).  Asked with
 * ``core_upgrade=1`` it also answers ``filesystem_method`` and
 * ``zip_library`` ({filesystem_method, zip_library}) — the two
 * preconditions WordPress's OWN core updader needs before it can be
 * driven without an interactive credential prompt and without a zip
 * library; on request only, because get_filesystem_method() writes a
 * probe file into the webroot (see wpt_core_upgrade_facts).
 */
function wpt_action_info( array $params ) {
	global $wpdb;
	$active = get_option( 'active_plugins' );
	$active = array_flip( wpt_option_string_list( $active, 'active_plugins' ) );
	$plugins = array();
	foreach ( get_plugins() as $file => $data ) {
		$file = (string) $file;
		$plugins[ $file ] = array(
			'name'    => isset( $data['Name'] ) ? (string) $data['Name'] : '',
			'version' => isset( $data['Version'] ) ? (string) $data['Version'] : '',
			'active'  => isset( $active[ $file ] ),
		);
	}
	// WordPress LOADS an active_plugins entry when its main file EXISTS
	// (wp_get_active_and_valid_plugins) even when get_plugins() cannot read
	// its header (truncated/unreadable/failed update) and therefore omits
	// it.  The inventory is used as a deletion guard, so an omitted entry
	// made a loaded plugin look inactive and clean-files deleted its whole
	// unit.  Merge every raw active entry missing from the inventory as an
	// ACTIVE unit (name/version unknown): the guard must fail closed.
	foreach ( $active as $file => $unused ) {
		$file = (string) $file;
		if ( '' === $file || isset( $plugins[ $file ] ) ) {
			continue;
		}
		$plugins[ $file ] = array(
			'name'    => '',
			'version' => '',
			'active'  => true,
		);
	}
	$mu = 0;
	if ( defined( 'WPMU_PLUGIN_DIR' ) && is_dir( WPMU_PLUGIN_DIR ) ) {
		$entries = @scandir( WPMU_PLUGIN_DIR );
		if ( is_array( $entries ) ) {
			$mu = count( preg_grep( '/\.php$/i', $entries ) );
		}
	}
	$ud = wp_upload_dir( null, false );
	$mysql_version = null;
	if ( isset( $wpdb ) && method_exists( $wpdb, 'db_version' ) ) {
		$v = $wpdb->db_version();
		if ( is_string( $v ) && '' !== $v ) {
			$mysql_version = $v;
		}
	}
	// The SCHEMA version is a stored OPTION and can be absent, empty or a
	// non-string (the same corrupt-row exposure the permalink_structure
	// read below handles); all three are UNKNOWN (null), never a 0 that
	// would read as "needs migrating from scratch".
	$db_version = get_option( 'db_version' );
	if ( ! is_scalar( $db_version ) || '' === (string) $db_version ) {
		$db_version = null;
	} else {
		$db_version = (string) $db_version;
	}
	// permalink_structure and locale: a corrupt option value (an array or
	// an object out of the options table) must not be string-cast. A
	// plain (string) cast raises "Array to string conversion", and this
	// file runs with display_errors=1, so the notice would be printed
	// BEFORE the JSON and corrupt the whole info answer (SPEC R12) —
	// taking every audit fact down with one bad option row. A non-string
	// value answers '' instead, which each consumer already reads as
	// "unknown": the harden gate treats '' as plain ?p=N permalinks, and
	// an empty locale resolves to en_US. The get_locale() call has the
	// same exposure through the WPLANG option it returns.
	$permalink_structure = get_option( 'permalink_structure' );
	// A corrupt option row can be an object/array.  Casting one to int
	// emits "Object of class stdClass could not be converted to int" before
	// the JSON under display_errors (SPEC R12), taking every audit fact down
	// with one bad row.  Scalar-gate first; unknown => 0 (the same value a
	// missing option has always produced).
	$blog_public        = get_option( 'blog_public' );
	$locale             = get_locale();
	// The marker core_upgrade writes BEFORE it migrates (see that op).
	// It is an ordinary option, so it is read with the same tolerance as
	// every other option here: a missing, non-array or garbled value is
	// null ("no marker"), never a fabricated one.
	$marker = get_option( 'wpt_core_upgrade' );
	if ( ! is_array( $marker ) ) {
		$marker = null;
	} else {
		$marker = array(
			'started'           => isset( $marker['started'] ) ? wpt_option_int( $marker['started'] ) : null,
			'from_db_version'   => ( isset( $marker['from_db_version'] ) && is_scalar( $marker['from_db_version'] ) ) ? (string) $marker['from_db_version'] : null,
			'target_db_version' => ( isset( $marker['target_db_version'] ) && is_scalar( $marker['target_db_version'] ) ) ? (string) $marker['target_db_version'] : null,
			'wp_version'        => ( isset( $marker['wp_version'] ) && is_string( $marker['wp_version'] ) ) ? $marker['wp_version'] : null,
			'finished'          => isset( $marker['finished'] ) ? wpt_option_int( $marker['finished'] ) : null,
		);
	}
	$payload = array(
		'wp_version'      => (string) get_bloginfo( 'version' ),
		'siteurl'          => (string) wpt_option_scalar( get_option( 'siteurl' ) ),
		'home'             => (string) wpt_option_scalar( get_option( 'home' ) ),
		'template'         => (string) wpt_option_scalar( get_option( 'template' ) ),
		'stylesheet'       => (string) wpt_option_scalar( get_option( 'stylesheet' ) ),
		'blog_public'     => is_scalar( $blog_public ) ? (int) $blog_public : 0,
		'permalink_structure' => is_string( $permalink_structure ) ? $permalink_structure : '',
		'locale'          => is_string( $locale ) ? $locale : '',
		'plugins'          => wpt_map( $plugins ),
		'mu_plugins'       => $mu,
		'uploads_basedir'  => isset( $ud['basedir'] ) ? (string) $ud['basedir'] : '',
		'uploads_error'    => isset( $ud['error'] ) ? (string) $ud['error'] : '',
		'abspath'          => defined( 'ABSPATH' ) ? (string) ABSPATH : '',
		'php_version'       => (string) PHP_VERSION,
		'php_version_id'    => (int) PHP_VERSION_ID,
		'memory_limit'      => (string) ini_get( 'memory_limit' ),
		'max_execution_time' => (string) ini_get( 'max_execution_time' ),
		'sapi'              => (string) php_sapi_name(),
		'server_software'   => isset( $_SERVER['SERVER_SOFTWARE'] ) ? (string) $_SERVER['SERVER_SOFTWARE'] : '',
		'mysql_version'     => $mysql_version,
		'db_version'        => $db_version,
		'upgrade_marker'    => $marker,
		'multisite'         => function_exists( 'is_multisite' ) ? is_multisite() : false,
		'wp_debug'          => defined( 'WP_DEBUG' ) ? (bool) WP_DEBUG : null,
	);
	// THE TWO CORE-UPDATE FACTS, ON REQUEST ONLY.  ``core_upgrade_files``
	// needs to know whether THIS site can run WordPress's own updater before
	// a plan may name that driver, and both facts cost something to read:
	// get_filesystem_method() WRITES a probe file into the webroot to compare
	// file ownership, and the zip answer needs wp-admin/includes/file.php
	// loaded (PclZip lives at the bottom of it).  An audit's ``info`` must
	// stay a cheap, side-effect-free read, so the update-core action asks for
	// them with core_upgrade=1 and every other consumer never pays.
	//   filesystem_method: 'direct' is the ONLY method core's updater can be
	//     driven with blind (anything else blocks on an interactive credential
	//     prompt); '' means the answer could not be read at all.
	//   zip_library: 'ZipArchive' | 'PclZip' | '' — '' means neither, so core's
	//     own unzip_file() cannot extract the release.
	if ( ! empty( $params['core_upgrade'] ) ) {
		$payload['filesystem_method'] = wpt_core_upgrade_facts();
	}
	return $payload;
}

/**
 * The driver's two preconditions, read from the RUNNING site, as
 * {filesystem_method, zip_library}.  Both answers are '' when they cannot be
 * read — UNKNOWN, which the update-core action reads as "this driver is not
 * available here" (the safe direction: the swap driver needs neither).
 */
function wpt_core_upgrade_facts() {
	$method = '';
	$zip    = '';
	if ( is_readable( ABSPATH . 'wp-admin/includes/file.php' ) ) {
		require_once ABSPATH . 'wp-admin/includes/file.php';
		$method = get_filesystem_method( array(), ABSPATH, false );
		$method = is_string( $method ) ? $method : '';
		$zip    = wpt_core_upgrade_zip_library();
	}
	return array(
		'filesystem_method' => $method,
		'zip_library'       => $zip,
	);
}


/**
 * A COUNT/SUM scalar read that stays UNKNOWN (null) when the query fails
 * instead of collapsing to a measured 0. get_var() returns null on failure
 * (and on an empty-string cell, which COUNT/SUM never produce), so a null
 * here means the query failed — the audit must report unknown, not a false
 * zero, so a broken/unreadable table is never read as a clean database.
 */
function wpt_audit_count( $sql ) {
	global $wpdb;
	$v = $wpdb->get_var( $sql );
	return ( null === $v ) ? null : (int) $v;
}

/**
 * db_audit (read-only): posts by type+status, revision count, expired
 * transient count, orphan postmeta/termmeta/commentmeta counts, table stats
 * from information_schema (rows/size/data_free estimates plus
 * TABLE_COLLATION, "" on the wire when NULL), autoload total bytes,
 * attachment + nav_menu_item counts, and the admin-user facts (users
 * check): "users" lists {login, registered (datetime str|null), admin:true}
 * for ADMINS ONLY — every account whose {prefix}user_level usermeta value
 * is '10' (WP's legacy but core-maintained admin marker), ORDER BY
 * user_login. The users/usermeta table names and prefix are discovered the
 * same way the queries above find posts/options ($wpdb's table-name
 * properties); anything missing or a failed query leaves users null —
 * UNKNOWN, never [] (a present-but-empty result IS the real measured []).
 */
function wpt_action_db_audit( array $params ) {
	global $wpdb;

	$posts = array();
	$rows  = $wpdb->get_results( "SELECT post_type, post_status, COUNT(*) AS n FROM {$wpdb->posts} GROUP BY post_type, post_status", ARRAY_A );
	if ( is_array( $rows ) ) {
		foreach ( $rows as $r ) {
			$posts[] = array(
				'post_type'   => isset( $r['post_type'] ) ? (string) $r['post_type'] : '',
				'post_status' => isset( $r['post_status'] ) ? (string) $r['post_status'] : '',
				'count'       => isset( $r['n'] ) ? (int) $r['n'] : 0,
			);
		}
	}

	$special = array( 'attachment' => 0, 'nav_menu_item' => 0 );
	$rows    = $wpdb->get_results( "SELECT post_type, COUNT(*) AS n FROM {$wpdb->posts} WHERE post_type IN ( 'attachment', 'nav_menu_item' ) GROUP BY post_type", ARRAY_A );
	if ( is_array( $rows ) ) {
		foreach ( $rows as $r ) {
			if ( isset( $r['post_type'] ) && isset( $special[ $r['post_type'] ] ) ) {
				$special[ $r['post_type'] ] = (int) $r['n'];
			}
		}
	}

	$tables = array();
	$rows   = $wpdb->get_results(
		"SELECT TABLE_NAME AS name, TABLE_ROWS AS row_count, ( DATA_LENGTH + INDEX_LENGTH ) / 1024 / 1024 AS size_mb, DATA_FREE / 1024 AS data_free_kb, TABLE_COLLATION AS collation FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE' ORDER BY TABLE_NAME",
		ARRAY_A
	);
	if ( is_array( $rows ) ) {
		foreach ( $rows as $r ) {
			$name = isset( $r['name'] ) ? (string) $r['name'] : '';
			// Reserved atomic-restore scratch tables are not the site's
			// tables; they are bridge-owned plumbing and must not appear in
			// an audit result.
			if ( wpt_restore_scratch_name( $name ) ) {
				continue;
			}
			$tables[] = array(
				'name'         => $name,
				'rows'         => isset( $r['row_count'] ) ? (int) $r['row_count'] : 0,
				'size_mb'      => isset( $r['size_mb'] ) ? round( (float) $r['size_mb'], 3 ) : 0.0,
				'data_free_kb' => isset( $r['data_free_kb'] ) ? round( (float) $r['data_free_kb'], 1 ) : 0.0,
				'collation'    => isset( $r['collation'] ) ? (string) $r['collation'] : '',
			);
		}
	}

	$users = null;
	if ( isset( $wpdb->prefix ) && is_string( $wpdb->prefix )
		&& isset( $wpdb->users ) && is_string( $wpdb->users ) && '' !== $wpdb->users
		&& isset( $wpdb->usermeta ) && is_string( $wpdb->usermeta ) && '' !== $wpdb->usermeta ) {
		$rows = $wpdb->get_results( $wpdb->prepare(
			"SELECT u.user_login AS login, u.user_registered AS registered"
			. " FROM {$wpdb->users} u"
			. " INNER JOIN {$wpdb->usermeta} um ON um.user_id = u.ID"
			. " AND um.meta_key = %s AND um.meta_value = '10'"
			. " ORDER BY u.user_login",
			$wpdb->prefix . 'user_level'
		), ARRAY_A );
		if ( is_array( $rows ) ) {
			$users = array();
			foreach ( $rows as $r ) {
				$users[] = array(
					'login'      => isset( $r['login'] ) ? (string) $r['login'] : '',
					'registered' => isset( $r['registered'] ) ? (string) $r['registered'] : null,
					'admin'      => true,
				);
			}
		}
	}

	return array(
		'posts'              => $posts,
		'revisions'          => wpt_audit_count( "SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type = 'revision' OR post_status = 'auto-draft'" ),
		'expired_transients' => wpt_audit_count( wpt_expired_transients_sql( 'SELECT COUNT(*)' ) ),
		'orphan_meta'        => wpt_map( array(
			'postmeta'    => wpt_audit_count( "SELECT COUNT(*) FROM {$wpdb->postmeta} pm LEFT JOIN {$wpdb->posts} p ON p.ID = pm.post_id WHERE p.ID IS NULL" ),
			'termmeta'    => wpt_audit_count( "SELECT COUNT(*) FROM {$wpdb->termmeta} tm LEFT JOIN {$wpdb->terms} t ON t.term_id = tm.term_id WHERE t.term_id IS NULL" ),
			'commentmeta' => wpt_audit_count( "SELECT COUNT(*) FROM {$wpdb->commentmeta} cm LEFT JOIN {$wpdb->comments} c ON c.comment_ID = cm.comment_id WHERE c.comment_ID IS NULL" ),
		) ),
		'tables'             => $tables,
		'autoload_bytes'     => wpt_audit_count( "SELECT COALESCE( SUM( LENGTH( option_value ) ), 0 ) FROM {$wpdb->options} WHERE autoload IN ( 'yes', 'on', 'auto-on', 'auto' )" ),
		'attachments'        => $special['attachment'],
		'nav_menu_items'     => $special['nav_menu_item'],
		'users'              => $users,
	);
}

/**
 * All variant paths of one attachment: metadata size files UNIONed with every
 * same-directory on-disk file whose basename stem matches (L5: migrated sites
 * lack attachment metadata, so on-disk stem scanning is what finds variants).
 */
function wpt_media_variants( $basedir, $file, $id ) {
	global $wpdb;
	if ( '' === $file ) {
		return array();
	}
	$dir_rel = dirname( $file );
	$dir_rel = ( '.' === $dir_rel || '' === $dir_rel ) ? '' : $dir_rel;
	$prefix  = ( '' === $dir_rel ) ? '' : $dir_rel . '/';

	$variants = array();
	$raw      = $wpdb->get_var( $wpdb->prepare( "SELECT meta_value FROM {$wpdb->postmeta} WHERE post_id = %d AND meta_key = '_wp_attachment_metadata' LIMIT 1", $id ) );
	if ( is_string( $raw ) && '' !== $raw ) {
		$meta = @unserialize( $raw );
		if ( is_array( $meta ) && isset( $meta['sizes'] ) && is_array( $meta['sizes'] ) ) {
			foreach ( $meta['sizes'] as $size ) {
				if ( is_array( $size ) && isset( $size['file'] ) && is_string( $size['file'] ) && '' !== $size['file'] ) {
					// Core stores size files as dir-relative basenames; tolerate
					// full uploads-relative values too.
					$variants[] = ( false !== strpos( $size['file'], '/' ) ) ? ltrim( $size['file'], '/' ) : $prefix . $size['file'];
				}
			}
		}
	}

	$abs_dir = $basedir . '/' . $prefix;
	$entries = @scandir( $abs_dir );
	if ( is_array( $entries ) ) {
		$stem = wpt_file_stem( basename( $file ) );
		foreach ( $entries as $e ) {
			if ( '.' === $e || '..' === $e ) {
				continue;
			}
			if ( wpt_file_stem( $e ) === $stem && is_file( $abs_dir . $e ) ) {
				$variants[] = $prefix . $e;
			}
		}
	}

	$variants = array_values( array_unique( $variants ) );
	sort( $variants );
	return $variants;
}

/**
 * Characters that END an uploads path inside stored TEXT (HTML attributes,
 * JSON, CSS url(), PHP-serialized strings, prose). Matched set-for-set with
 * wpt/media_refs.py's _TEXT_DELIMITERS — the two implementations MUST stay
 * in lockstep, exactly like wpt_file_stem / _file_stem.
 */
function wpt_media_ref_delims() {
	return " \t\r\n\f\v\0" . '"' . "'" . '<>()[]{}' . '?#;,|&=`$*!' . '\\';
}

/**
 * Trailing punctuation STRIPPED from a captured path tail.
 *
 * ONE rule, two implementations: this is the PHP half, wpt/media_refs.py's
 * ``_TRAILING_PUNCTUATION`` is the Python half, and they MUST name the same
 * SET.  It has its own function (like wpt_media_ref_delims above) precisely
 * so tests/test_media_refs.py can lift it out of the deployed file by name
 * and compare the two as sets — the drift that matters is the PHP side
 * trimming a character the Python side keeps, which LOSES a keep-set
 * reference and is therefore a DELETION.
 *
 * Not a parameter and not a profile key, unlike the extension family above:
 * this is a fixed RULE about how a captured tail ends, not an operator's
 * choice, and widening it can only cut references off.  WordPress's own
 * sanitize_file_name strips these from real filenames, so stripping them
 * here can only help a real file match.
 */
function wpt_media_ref_trailing_punct() {
	return ".,;:!\xe2\x80\x99\xe2\x80\x9d";
}

/**
 * Every uploads-relative path NAMED anywhere in one stored text blob.
 *
 * A ref is a REFERENCE, not a file: it protects its on-disk same-directory
 * stem siblings client-side (the L5 rule in wpt/audit/media.py), so this
 * only has to name the file exactly as the database stores it.
 */
function wpt_media_refs_in_text( $text ) {
	$marker = 'wp-content/uploads/';
	$refs   = array();
	if ( ! is_string( $text ) || false === strpos( $text, $marker ) ) {
		return $refs;
	}
	$delims = wpt_media_ref_delims();
	$offset = 0;
	while ( false !== ( $at = strpos( $text, $marker, $offset ) ) ) {
		$offset = $at + strlen( $marker );
		$tail   = substr( $text, $offset );
		$stop   = strcspn( $tail, $delims );
		$tail   = substr( $tail, 0, $stop );
		$tail   = trim( rawurldecode( $tail ) );
		$tail   = rtrim( $tail, wpt_media_ref_trailing_punct() );
		if ( '' === $tail || '/' === substr( $tail, -1 ) ) {
			continue;
		}
		$ok = true;
		foreach ( explode( '/', $tail ) as $segment ) {
			if ( '' === $segment || '.' === $segment || '..' === $segment ) {
				$ok = false;
				break;
			}
		}
		if ( $ok ) {
			$refs[ $tail ] = true;
		}
	}
	return array_keys( $refs );
}

/**
 * One _wp_attached_file value -> its uploads-relative path (null when
 * unusable). A value carrying the uploads marker (very old sites store the
 * full URL there) is read through wpt_media_refs_in_text.
 */
function wpt_media_attached_ref( $value ) {
	if ( ! is_string( $value ) ) {
		return null;
	}
	if ( false !== strpos( $value, 'wp-content/uploads/' ) ) {
		$refs = wpt_media_refs_in_text( $value );
		return $refs ? $refs[0] : null;
	}
	$value = trim( $value );
	if ( '' === $value || '/' === substr( $value, 0, 1 ) || '/' === substr( $value, -1 ) ) {
		return null;
	}
	foreach ( explode( '/', $value ) as $segment ) {
		if ( '' === $segment || '.' === $segment || '..' === $segment ) {
			return null;
		}
	}
	return $value;
}

/**
 * The FILE NAMES one attachment-metadata value carries: its own `file`
 * key plus every sizes[*].file, in both stored forms (a bare basename, or
 * a full uploads-relative path). An empty list means the value is
 * UNREADABLE — an unreadable size map is UNKNOWN, never "this attachment
 * has no other files" (the fail direction that deletes live thumbnails).
 * Accepts the PHP-serialized form core writes and the JSON form some
 * plugins store.
 */
function wpt_media_meta_names( $raw ) {
	$names = array();
	if ( ! is_string( $raw ) || '' === $raw ) {
		return $names;
	}
	$meta = @unserialize( $raw );
	if ( ! is_array( $meta ) ) {
		$meta = json_decode( $raw, true );
	}
	if ( ! is_array( $meta ) ) {
		return $names;
	}
	if ( isset( $meta['file'] ) && is_string( $meta['file'] ) && '' !== $meta['file'] ) {
		$names[] = $meta['file'];
	}
	if ( isset( $meta['sizes'] ) && is_array( $meta['sizes'] ) ) {
		foreach ( $meta['sizes'] as $size ) {
			if ( is_array( $size ) && isset( $size['file'] ) && is_string( $size['file'] ) && '' !== $size['file'] ) {
				$names[] = $size['file'];
			}
		}
	}
	return $names;
}

/**
 * The files ONE attachment-metadata value names, as a LIST of
 * uploads-relative paths: every name in both stored forms — a bare
 * basename joined to $dir_prefix (the bridge's wpt_media_variants rule)
 * and a full uploads-relative path taken as-is.  A list, not a map: a
 * path used as an array key is silently renumbered when it looks numeric
 * (PHP array-key coercion), so the caller dedupes the returned paths.
 */
function wpt_media_meta_refs( $raw, $dir_prefix ) {
	$refs = array();
	foreach ( wpt_media_meta_names( $raw ) as $name ) {
		if ( false !== strpos( $name, '/' ) ) {
			$candidate = wpt_media_attached_ref( ltrim( $name, '/' ) );
		} else {
			$candidate = wpt_media_attached_ref( $dir_prefix . $name );
		}
		if ( null !== $candidate ) {
			$refs[ $candidate ] = true;
		}
	}
	return array_keys( $refs );
}

/**
 * Structural bound on a requested media extension family (NOT an operator
 * tunable: the family is an allowlist of file suffixes, and the shipped
 * default is 39 of them).  A request larger than this is refused whole,
 * so a malformed or hostile payload cannot spend the gate's time.
 */
define( 'WPT_MEDIA_REF_EXT_MAX', 512 );

/**
 * The extension family a media keep-set REF can carry — the shipped
 * wpt/data/profiles/default.json "media.extensions" list (no dots), which is
 * the same allowlist wpt/audit/media.py's is_media() and the trim-media
 * plan gate files by.  Mirrored here because this file is DEPLOYED on a
 * host that cannot read the operator's profile, exactly like the
 * _wp_attachment_metadata key names and wpt_media_ref_delims() above;
 * tests/test_media_refs.py parses this literal and fails when the
 * profile's shipped default changes without it, so the two cannot drift.
 *
 * A ref must be in the family for ONE reason: a path with no usable
 * extension is not a file reference at all.  A stale
 * ``_transient_dirsize_cache`` option on a real site (measured
 * an observed run) held many absolute paths to the site's PREVIOUS host,
 * several of which were bare YEAR DIRECTORIES ("2018".."2023") — the extractor took
 * them as file references, and one such row was enough to make the client
 * reject the whole answer and disable the union keep-set for the site.
 *
 * THE READ CARRIES THE CALLER'S FAMILY.  ``media.extensions`` is a
 * set-reachable profile key, so a WIDENED profile used to break the one
 * guarantee the keep-set rests on: the gate answered from THIS literal
 * while the enumeration answered from the profile, so a file whose
 * extension only the profile knew (--set media.extensions=[..., "psd"])
 * was invisible to the gate, absent from the union and therefore a
 * deletion CANDIDATE — a database-referenced attachment removed by a
 * compliant apply.  ``media_map`` mode=db therefore takes the caller's
 * list, and the effective family is THIS DEFAULT UNION the request.
 *
 * THE DEFAULT IS A FLOOR, NEVER A CEILING.  The wire can only WIDEN the
 * gate, and a wider gate can only protect more, so no request — a widened
 * profile, a narrowed one, or a hand-written one that omits, empties or
 * garbles the list — can make the live gate NARROWER than the shipped
 * family, and the invariant a deletion rests on holds for every profile:
 * the gate always CONTAINS the enumeration's family.  A request that is
 * not a well-formed list of plain tokens is REFUSED WHOLE ($refused), the
 * default answers alone, and the client turns the refusal into a
 * fail-closed error instead of a quietly narrowed keep-set.
 *
 * $refused is an out-parameter (the same idiom wpt_media_ref_add's
 * $dropped uses): true means the caller's list was NOT honored.
 */
function wpt_media_ref_extensions( $requested = null, &$refused = null ) {
	$refused = false;
	$default = array(
		'jpg', 'jpeg', 'jpe', 'png', 'gif', 'webp', 'avif', 'bmp', 'ico', 'svg',
		'tiff', 'mp3', 'm4a', 'ogg', 'oga', 'wav', 'flac', 'mp4', 'm4v', 'webm',
		'mov', 'avi', 'ogv', '3gp', '3g2', 'pdf', 'doc', 'docx', 'xls', 'xlsx',
		'ppt', 'pptx', 'odt', 'key', 'txt', 'csv', 'zip', 'gz', 'tar',
	);
	if ( null === $requested ) {
		return $default;
	}
	// An empty list is a REFUSAL, never an accepted "gate nothing": the
	// family that keeps no extension is a keep-set that protects nothing
	// while looking measured, which is how a whole site reads as orphan.
	if ( ! is_array( $requested ) || ! $requested
		|| count( $requested ) > WPT_MEDIA_REF_EXT_MAX ) {
		$refused = true;
		return $default;
	}
	$family = $default;
	foreach ( $requested as $value ) {
		if ( ! is_string( $value ) ) {
			$refused = true;
			return $default;
		}
		$token = strtolower( trim( $value ) );
		if ( ! preg_match( '/^[a-z0-9][a-z0-9_-]{0,31}$/', $token ) ) {
			$refused = true;
			return $default;
		}
		if ( ! in_array( $token, $family, true ) ) {
			$family[] = $token;
		}
	}
	return $family;
}

/**
 * One raw reference source -> its uploads-RELATIVE path, or null when the
 * value cannot name an uploads file at all.
 *
 * Normalization, in order, so that every source (the text scanner, an
 * _wp_attached_file value, a sizes[*].file entry) is anchored the same
 * way:
 *   - NUL bytes stripped, trimmed, backslashes folded to '/' (a Windows-
 *     shaped stored path is still a path),
 *   - a value carrying the uploads MARKER is cut to the tail after it —
 *     this is what maps a site migrated from ANOTHER host
 *     ("/home/olduser/public_html/wp-content/uploads/2018/03/photo.jpg")
 *     to its uploads-relative tail, which is host-independent,
 *   - an absolute value with no marker is refused: nothing anchors it to
 *     this site's uploads tree,
 *   - empty / "." / ".." segments refused.
 */
function wpt_media_ref_normalize( $raw ) {
	if ( ! is_string( $raw ) ) {
		return null;
	}
	$value = trim( str_replace( array( "\0", '\\' ), array( '', '/' ), $raw ) );
	if ( '' === $value ) {
		return null;
	}
	$marker = 'wp-content/uploads/';
	$at     = strpos( $value, $marker );
	if ( false !== $at ) {
		$value = substr( $value, $at + strlen( $marker ) );
	} elseif ( '/' === substr( $value, 0, 1 ) ) {
		return null;
	}
	$value = preg_replace( '#/+#', '/', $value );
	foreach ( explode( '/', $value ) as $segment ) {
		if ( '' === $segment || '.' === $segment || '..' === $segment ) {
			return null;
		}
	}
	return $value;
}

/**
 * Is this normalized ref a FILE the keep-set can honour?
 *
 * True only when the basename carries an extension from the family
 * (wpt_media_ref_extensions(), or the one the caller carried) and the path
 * is not an existing DIRECTORY under the uploads basedir.  The directory
 * test is the belt to the extension's braces: a directory can carry a
 * media-looking name ("2023/thumbs.cache", a plugin's own "cache.png"
 * folder), and a directory in a keep-set protects nothing while making the
 * answer unreadable.  An unreadable basedir ('' — wp_upload_dir unavailable)
 * skips the test rather than dropping references.
 */
function wpt_media_ref_is_kept( $ref, $basedir, $extensions = null ) {
	$name = basename( $ref );
	$dot  = strrpos( $name, '.' );
	if ( false === $dot || 0 === $dot ) {
		return false;
	}
	if ( null === $extensions ) {
		$extensions = wpt_media_ref_extensions();
	}
	if ( ! in_array( strtolower( substr( $name, $dot + 1 ) ), $extensions, true ) ) {
		return false;
	}
	if ( '' !== $basedir && is_dir( $basedir . '/' . $ref ) ) {
		return false;
	}
	return true;
}

/**
 * The ONE collection point of the database media map: normalize, gate,
 * then record.  $dropped counts every reference a site's stored data
 * offered that the gate refused, and rides the answer as
 * "db_refs_dropped" so the client can report a lossy keep-set once
 * instead of losing the whole union over it.  $extensions is the
 * effective family (see wpt_media_ref_extensions), threaded from the
 * one resolution at the top of wpt_media_db_map.
 */
function wpt_media_ref_add( array &$refs, $raw, $basedir, &$dropped, $extensions = null ) {
	$ref = wpt_media_ref_normalize( $raw );
	if ( null === $ref || ! wpt_media_ref_is_kept( $ref, $basedir, $extensions ) ) {
		$dropped++;
		return;
	}
	$refs[ $ref ] = true;
}

/**
 * media_map (mode=db): every uploads file the DATABASE references.
 *
 * The second half of the media keep-set (the live walk sees only the
 * fraction of attachments a page actually renders — measured live: most
 * files and most of the media bytes were database-referenced and
 * invisible to the walk, and a walk-only trim would have deleted them).
 * Sources, all read-only SELECTs over whitelisted $wpdb tables with no
 * LIMIT (a truncated keep-set is a deletion bug):
 *
 *   1. _wp_attached_file  — every attachment's own path
 *   2. _wp_attachment_metadata + the legacy _wp_attachment_backup_sizes
 *      — the `file` key and every sizes[*].file, bare basenames anchored
 *      to the attachment's own directory
 *   3. every other postmeta value naming an uploads path (elementor JSON,
 *      page-builder data, nav-menu item meta, ...)
 *   4. post content / excerpt / guid (gallery templates, linked PDFs)
 *   5. option values naming an uploads path (theme options, widgets)
 *   6. termmeta values naming an uploads path (category media)
 *
 * Every source is collected through wpt_media_ref_add(), so the answer
 * holds only entries that are a normalized, extension-bearing,
 * non-directory uploads-relative FILE path; the count of what the gate
 * refused rides along as "db_refs_dropped" (the client's contract is to
 * report a lossy keep-set, never to lose the whole union over it).
 *
 * $extensions is the EFFECTIVE family the gate answers with (see
 * wpt_media_ref_extensions): the caller resolves it ONCE — the mirrored
 * default UNION the extension list the read carried — and threads it
 * through every collection point, so all six sources are judged by one
 * family.  null resolves the mirrored default on its own.
 *
 * Returns {"db_refs": [uploads-relative paths, sorted], "db_refs_dropped":
 * <int>}. On-disk size VARIANTS of a referenced file are not this op's
 * job: the client keeps every same-directory stem sibling (the L5 rule),
 * the same shape wpt_media_variants() applies for refs.
 */
function wpt_media_db_map( $basedir = '', $extensions = null ) {
	global $wpdb;
	if ( null === $extensions ) {
		$extensions = wpt_media_ref_extensions();
	}
	$refs    = array();
	$dropped = 0;
	$anchors = array();   // post_id => directory of the attachment
	$pending = array();   // post_id => bare size basenames awaiting an anchor

	$rows = $wpdb->get_results( "SELECT post_id, meta_value FROM {$wpdb->postmeta} WHERE meta_key = '_wp_attached_file'", ARRAY_A );
	if ( is_array( $rows ) ) {
		foreach ( $rows as $row ) {
			$ref  = wpt_media_attached_ref( isset( $row['meta_value'] ) ? $row['meta_value'] : '' );
			$norm = ( null === $ref ) ? null : wpt_media_ref_normalize( $ref );
			wpt_media_ref_add( $refs, $ref, $basedir, $dropped, $extensions );
			// The anchor comes from the NORMALIZED value, not from the
			// gate's verdict: a metadata row's bare size basenames are
			// still resolved into the attachment's own directory.
			if ( null === $norm ) {
				continue;
			}
			$post_id = isset( $row['post_id'] ) ? (string) $row['post_id'] : '';
			if ( '' === $post_id ) {
				continue;
			}
			$at  = strrpos( $norm, '/' );
			$dir = ( false === $at ) ? '' : substr( $norm, 0, $at + 1 );
			$anchors[ $post_id ] = $dir;
			if ( isset( $pending[ $post_id ] ) ) {
				foreach ( $pending[ $post_id ] as $name ) {
					wpt_media_ref_add( $refs, wpt_media_attached_ref( $dir . $name ), $basedir, $dropped, $extensions );
				}
				unset( $pending[ $post_id ] );
			}
		}
	}

	$keys = "'_wp_attachment_metadata','_wp_attachment_backup_sizes'";
	$rows = $wpdb->get_results( "SELECT post_id, meta_value FROM {$wpdb->postmeta} WHERE meta_key IN ({$keys})", ARRAY_A );
	if ( is_array( $rows ) ) {
		foreach ( $rows as $row ) {
			$post_id  = isset( $row['post_id'] ) ? (string) $row['post_id'] : '';
			$raw      = isset( $row['meta_value'] ) ? $row['meta_value'] : '';
			$dir      = isset( $anchors[ $post_id ] ) ? $anchors[ $post_id ] : null;
			$found    = wpt_media_meta_refs( $raw, null === $dir ? '' : $dir );
			$deferred = array();
			if ( null === $dir ) {
				// The anchor row has not been read (post_id order is
				// arbitrary): park the bare basenames rather than
				// anchoring them to the wrong directory, and resolve them
				// at the end of the pass.
				foreach ( wpt_media_meta_names( $raw ) as $name ) {
					if ( false === strpos( $name, '/' ) ) {
						$deferred[] = $name;
					}
				}
			}
			foreach ( $found as $ref ) {
				wpt_media_ref_add( $refs, $ref, $basedir, $dropped, $extensions );
			}
			if ( $deferred ) {
				$pending[ $post_id ] = array_merge( isset( $pending[ $post_id ] ) ? $pending[ $post_id ] : array(), $deferred );
			}
		}
	}
	foreach ( $pending as $post_id => $names ) {
		$dir = isset( $anchors[ $post_id ] ) ? $anchors[ $post_id ] : '';
		foreach ( $names as $name ) {
			$resolved = wpt_media_attached_ref( $dir . $name );
			if ( null !== $resolved ) {
				wpt_media_ref_add( $refs, $resolved, $basedir, $dropped, $extensions );
			}
		}
	}

	$rows = $wpdb->get_results( "SELECT meta_value FROM {$wpdb->postmeta} WHERE meta_value LIKE '%wp-content/uploads/%'", ARRAY_A );
	if ( is_array( $rows ) ) {
		foreach ( $rows as $row ) {
			foreach ( wpt_media_refs_in_text( isset( $row['meta_value'] ) ? $row['meta_value'] : '' ) as $ref ) {
				wpt_media_ref_add( $refs, $ref, $basedir, $dropped, $extensions );
			}
		}
	}

	$rows = $wpdb->get_results( "SELECT post_content, post_excerpt, post_guid FROM {$wpdb->posts}", ARRAY_A );
	if ( is_array( $rows ) ) {
		foreach ( $rows as $row ) {
			foreach ( array( 'post_content', 'post_excerpt', 'post_guid' ) as $column ) {
				foreach ( wpt_media_refs_in_text( isset( $row[ $column ] ) ? $row[ $column ] : '' ) as $ref ) {
					wpt_media_ref_add( $refs, $ref, $basedir, $dropped, $extensions );
				}
			}
		}
	}

	$rows = $wpdb->get_results( "SELECT option_value FROM {$wpdb->options} WHERE option_value LIKE '%wp-content/uploads/%'", ARRAY_A );
	if ( is_array( $rows ) ) {
		foreach ( $rows as $row ) {
			foreach ( wpt_media_refs_in_text( isset( $row['option_value'] ) ? $row['option_value'] : '' ) as $ref ) {
				wpt_media_ref_add( $refs, $ref, $basedir, $dropped, $extensions );
			}
		}
	}

	$rows = $wpdb->get_results( "SELECT meta_value FROM {$wpdb->termmeta} WHERE meta_value LIKE '%wp-content/uploads/%'", ARRAY_A );
	if ( is_array( $rows ) ) {
		foreach ( $rows as $row ) {
			foreach ( wpt_media_refs_in_text( isset( $row['meta_value'] ) ? $row['meta_value'] : '' ) as $ref ) {
				wpt_media_ref_add( $refs, $ref, $basedir, $dropped, $extensions );
			}
		}
	}

	// A plain LIST, and every key forced back to a string: a PHP array key
	// that looks like an integer is silently renumbered, so a map keyed by
	// path would encode as {"2018": ...} and the client would read the
	// whole answer as untrustworthy.  The gate already refuses the
	// extension-less paths that can look numeric; this is the backstop
	// that makes the wire shape structural rather than incidental.
	$out = array_map( 'strval', array_keys( $refs ) );
	sort( $out );
	return array( 'db_refs' => $out, 'db_refs_dropped' => (int) $dropped );
}

/**
 * media_map (L5): resolve uploads-relative refs to attachment IDs — exact
 * _wp_attached_file match, then basename match, then stem match with -WxH /
 * -scaled stripped. Payload: refs {ref: {id, file}}, attachments
 * {"id": {file, variants: [uploads-relative]}} for every resolved ID.
 *
 * ``mode=db`` instead answers the OTHER half of the media keep-set (see
 * wpt_media_db_map): params {"mode":"db", "extensions": [...]}, payload
 * {"db_refs": [...], "db_refs_dropped": <int>, "db_refs_gate": <int>,
 * "db_refs_gate_fallback": true?}, and no refs are required. ``extensions``
 * is the caller's media family, optional and validated against the
 * mirrored default (a floor, so it can only widen the gate). One op, two
 * read-only shapes — the refs->ids map and the database media map — so the
 * whitelist grows by a mode and one parameter, not by an op.
 */
function wpt_action_media_map( array $params ) {
	global $wpdb;
	$mode = isset( $params['mode'] ) && is_string( $params['mode'] ) ? (string) $params['mode'] : '';
	if ( '' !== $mode && 'db' !== $mode ) {
		throw new InvalidArgumentException( 'unknown media_map mode: ' . $mode );
	}
	$refs    = array();
	$ud      = wp_upload_dir( null, false );
	$basedir = empty( $ud['basedir'] ) ? '' : (string) $ud['basedir'];
	if ( 'db' === $mode ) {
		// An unreadable basedir does not refuse the map: the DIRECTORY half
		// of the ref gate is then skipped (wpt_media_ref_is_kept), while
		// the extension gate still holds.
		//
		// The read CARRIES the caller's extension family (the profile's),
		// because the enumeration files uploads media by that same list:
		// a gate that answered from the mirrored default alone made a
		// profile-widened extension invisible here and therefore DELETABLE
		// while the database referenced it.  The mirrored default is the
		// FLOOR (wpt_media_ref_extensions), the answer reports the
		// effective family size, and a request the bridge refused is
		// flagged so the client fails closed instead of keeping a set
		// measured with a family this run never asked for.
		$requested = isset( $params['extensions'] ) ? $params['extensions'] : null;
		$refused   = false;
		$family    = wpt_media_ref_extensions( $requested, $refused );
		$answer    = wpt_media_db_map( $basedir, $family );
		$answer['db_refs_gate'] = count( $family );
		if ( $refused ) {
			$answer['db_refs_gate_fallback'] = true;
		}
		return $answer;
	}
	if ( '' === $basedir ) {
		throw new RuntimeException( 'uploads basedir unavailable' );
	}
	// The refs->ids shape is the only one that takes a reference list
	// (mode=db replaces it entirely).
	$refs = wpt_param_str_list( $params, 'refs' );

	$by_exact   = array();
	$by_base    = array();
	$by_stem    = array();
	$file_by_id = array();
	$rows = $wpdb->get_results( "SELECT post_id, meta_value FROM {$wpdb->postmeta} WHERE meta_key = '_wp_attached_file' ORDER BY post_id", ARRAY_A );
	if ( is_array( $rows ) ) {
		foreach ( $rows as $r ) {
			$pid = isset( $r['post_id'] ) ? (int) $r['post_id'] : 0;
			$val = isset( $r['meta_value'] ) ? (string) $r['meta_value'] : '';
			if ( $pid < 1 || '' === $val ) {
				continue;
			}
			if ( ! isset( $by_exact[ $val ] ) ) {
				$by_exact[ $val ] = $pid;
			}
			$base = basename( $val );
			if ( ! isset( $by_base[ $base ] ) ) {
				$by_base[ $base ] = $pid;
			}
			$stem = wpt_file_stem( $base );
			if ( ! isset( $by_stem[ $stem ] ) ) {
				$by_stem[ $stem ] = $pid;
			}
			$file_by_id[ $pid ] = $val;
		}
	}

	$refs_out    = array();
	$wanted      = array();
	foreach ( $refs as $ref ) {
		$id = null;
		if ( isset( $by_exact[ $ref ] ) ) {
			$id = $by_exact[ $ref ];
		} elseif ( isset( $by_base[ basename( $ref ) ] ) ) {
			$id = $by_base[ basename( $ref ) ];
		} else {
			$stem = wpt_file_stem( basename( $ref ) );
			if ( isset( $by_stem[ $stem ] ) ) {
				$id = $by_stem[ $stem ];
			}
		}
		$refs_out[ $ref ] = array(
			'id'   => ( null === $id ) ? null : (int) $id,
			'file' => ( null === $id || ! isset( $file_by_id[ $id ] ) ) ? null : $file_by_id[ $id ],
		);
		if ( null !== $id ) {
			$wanted[ (int) $id ] = true;
		}
	}

	$attachments = array();
	foreach ( array_keys( $wanted ) as $id ) {
		$file = isset( $file_by_id[ $id ] ) ? $file_by_id[ $id ] : '';
		$attachments[ (string) $id ] = array(
			'file'     => $file,
			'variants' => wpt_media_variants( $basedir, $file, $id ),
		);
	}
	return array( 'refs' => wpt_map( $refs_out ), 'attachments' => wpt_map( $attachments ) );
}

/**
 * The database SURFACES the webp-media reference rewrite reads, by
 * table-name SUFFIX -> (primary-key column, rewritable value column,
 * gated columns).  Mirrored from wpt/actions/images_webp.py's
 * _REWRITABLE_TABLES + _GATED_TABLES (suffix match, the clean-db /
 * trim-media convention), and tests/test_bridge_php.py compares the two
 * structures so this op and the action can never drift: the action sends
 * back exactly the ``key`` column named here, and a rewrite that reached
 * a different column than the plan measured would be a wrong write.
 *
 * A rewritable surface is the only one whose value the op will ever
 * change; the gated columns are READ so the caller can hold the images
 * they reference out of any conversion the rewrite cannot reach.
 */
function wpt_media_rewrite_tables() {
	return array(
		'posts'    => array( 'key' => 'ID',         'value' => 'post_content', 'gated' => array( 'post_excerpt' ) ),
		'postmeta' => array( 'key' => 'meta_id',    'value' => 'meta_value',   'gated' => array() ),
		'options'  => array( 'key' => 'option_id',  'value' => 'option_value', 'gated' => array() ),
		'comments' => array( 'key' => 'comment_ID', 'value' => '',             'gated' => array( 'comment_content', 'comment_author_url' ) ),
		'users'    => array( 'key' => 'ID',         'value' => '',             'gated' => array( 'user_url' ) ),
		'usermeta' => array( 'key' => 'umeta_id',   'value' => '',             'gated' => array( 'meta_value' ) ),
		'termmeta' => array( 'key' => 'meta_id',    'value' => '',             'gated' => array( 'meta_value' ) ),
	);
}

/**
 * A table's real column names, from information_schema (the identifier
 * whitelist db_restore_table already uses — this op interpolates no
 * identifier that did not come from the schema).
 */
function wpt_table_columns( $table ) {
	global $wpdb;
	$cols = $wpdb->get_col( $wpdb->prepare(
		"SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s ORDER BY ORDINAL_POSITION",
		$table
	) );
	return is_array( $cols ) ? $cols : array();
}

/**
 * The SITE'S OWN table for a surface suffix, as WordPress itself resolves
 * it, or '' when this install does not name one.
 *
 * A suffix match alone is ambiguous: a plugin's "wp_myoptions" ends with
 * "options" too, and a suffix-first resolution would rewrite the WRONG
 * table's rows (or scan the wrong posts). WordPress already resolved the
 * real name for every surface but termmeta, which is derived from the
 * PREFIX the options table names (the analyzer's rule — ``wp_`` is never
 * assumed) and only used when that table really exists.
 */
function wpt_media_rewrite_own_table( $suffix ) {
	global $wpdb;
	$property = array(
		'posts'    => 'posts',
		'postmeta' => 'postmeta',
		'options'  => 'options',
		'comments' => 'comments',
		'users'    => 'users',
		'usermeta' => 'usermeta',
	);
	if ( isset( $property[ $suffix ] ) && isset( $wpdb->{$property[ $suffix ]} )
		&& is_string( $wpdb->{$property[ $suffix ]} ) ) {
		return $wpdb->{$property[ $suffix ] };
	}
	if ( isset( $wpdb->options ) && is_string( $wpdb->options )
		&& strlen( $wpdb->options ) > strlen( 'options' )
		&& substr( $wpdb->options, -strlen( 'options' ) ) === 'options' ) {
		return substr( $wpdb->options, 0, strlen( $wpdb->options ) - strlen( 'options' ) ) . $suffix;
	}
	return '';
}

/**
 * Resolve the surfaces above against the LIVE schema: real table name =>
 * spec, and a surface is only used when every column the op reads
 * actually exists (a stripped-down or heavily modified site simply
 * contributes fewer surfaces). The site's own table is considered FIRST,
 * then any same-suffix table, so a look-alike never displaces it.
 * $rewritable_only keeps the apply's addressable set.
 */
function wpt_media_rewrite_surfaces( $rewritable_only = false ) {
	$whitelist = wpt_table_whitelist();
	$out       = array();
	foreach ( wpt_media_rewrite_tables() as $suffix => $spec ) {
		if ( $rewritable_only && '' === $spec['value'] ) {
			continue;
		}
		$candidates = array();
		$own        = wpt_media_rewrite_own_table( $suffix );
		if ( '' !== $own && in_array( $own, $whitelist, true ) ) {
			$candidates[] = $own;
		}
		foreach ( $whitelist as $name ) {
			if ( strlen( $name ) < strlen( $suffix )
				|| substr( $name, -strlen( $suffix ) ) !== $suffix
				|| in_array( $name, $candidates, true ) ) {
				continue;
			}
			$candidates[] = $name;
		}
		foreach ( $candidates as $name ) {
			$columns = wpt_table_columns( $name );
			if ( ! $columns ) {
				continue;
			}
			$needed = array( $spec['key'], $spec['value'] );
			foreach ( $spec['gated'] as $column ) {
				$needed[] = $column;
			}
			$needed = array_filter( $needed, 'strlen' );
			if ( array_diff( $needed, $columns ) ) {
				continue;
			}
			$out[ $name ] = $spec;
			break;
		}
	}
	// Deterministic order: the whitelist comes from information_schema, so
	// without this the same site would stream its rows in a different order
	// per query plan, and an answer worth reading is worth reproducing.
	ksort( $out );
	return $out;
}

/**
 * The pre-filter half of one surface's SELECT: the columns whose value
 * can hold a convertible raster reference. It is a TRANSFER filter, and
 * both error directions are safe — a row it lets through that holds no
 * reference costs one line, and a reference it cannot match is not a
 * raster reference the rewrite could ever move (the raster family is
 * exactly the webp twin family, wpt/actions/images_webp.py's
 * _RASTER_SUFFIXES).
 */
function wpt_media_rewrite_filter( $column ) {
	$clauses = array();
	foreach ( array( '.jpg', '.jpeg', '.png' ) as $extension ) {
		// LOWER() makes the match collation-independent: a case-SENSITIVE
		// collation must still find IMG.JPG.
		$clauses[] = 'LOWER(`' . wpt_backtick( $column ) . "`) LIKE '%" . $extension . "%'";
	}
	return $clauses;
}

/**
 * The DEFAULT bound on ONE reference scan: the point past which the op
 * refuses to answer rather than hand back a half-measured reference set
 * (the client's contract treats a truncated scan as a refusal — a
 * conversion nobody can prove safe is exactly what webp-media must not
 * plan). No real site's image-bearing rows come near it; mirrored by
 * wpt.wpbridge.client.REWRITE_REF_SCAN_CAP.
 *
 * A site that really does exceed it is not left with no door: the read
 * mode takes a ``scan_cap`` parameter (wpt_action_media_rewrite_refs, and
 * wpt.wpbridge.client.Bridge.iter_rewrite_refs, which forwards it), and
 * this value is what it gets when it asks for none.
 */
define( 'WPT_MEDIA_REWRITE_SCAN_CAP', 100000 );

/**
 * The CEILING on the ``scan_cap`` a caller may ask for, and the one bound
 * the op never crosses whatever the request says.
 *
 * Ten times the default, which is the door for a genuinely oversized site;
 * beyond it the op clamps and says so on the answer rather than attempting
 * a result set no stock ``memory_limit`` holds (the scan loads one
 * surface's rows into memory as PHP arrays, roughly a kilobyte per row, so
 * a million is a gigabyte-scale operation the operator must have arranged
 * for). Past the ceiling the op does not silently honour the request and
 * does not refuse the scan either: it truncates at the ceiling exactly as
 * it would at the default, which the client already refuses. Mirrored by
 * wpt.wpbridge.client.REWRITE_REF_SCAN_CAP_MAX.
 */
define( 'WPT_MEDIA_REWRITE_SCAN_CAP_MAX', 1000000 );

/**
 * Resolve the ``scan_cap`` parameter of the read mode: the row count at
 * which the scan truncates. $clamped (out) is set once when the request
 * asked for more than the ceiling, and only then — a request inside the
 * bounds is answered with no trace of itself.
 *
 * Fail-closed on a MALFORMED request (a non-integer, a bool, a count below
 * one): it throws, so the caller gets a structured refusal instead of a
 * scan quietly measured against a number nobody chose. A cap too LARGE is
 * not a refusal — it is clamped, because the operator's intent (measure
 * more) is still served as far as the op is willing to go.
 */
function wpt_media_rewrite_scan_cap( $requested, &$clamped = null ) {
	$clamped = false;
	if ( null === $requested ) {
		return WPT_MEDIA_REWRITE_SCAN_CAP;
	}
	if ( is_bool( $requested ) || ! is_int( $requested ) || $requested < 1 ) {
		throw new InvalidArgumentException( 'invalid scan_cap (expected a positive integer)' );
	}
	if ( $requested > WPT_MEDIA_REWRITE_SCAN_CAP_MAX ) {
		$clamped = true;
		return WPT_MEDIA_REWRITE_SCAN_CAP_MAX;
	}
	return $requested;
}

/**
 * The rows one reference UPDATE is allowed to carry, and the hard ceiling
 * the op refuses beyond (the caller batches at 100). Mirrored by
 * wpt.wpbridge.client.REWRITE_REF_ROW_MAX.
 */
define( 'WPT_MEDIA_REWRITE_ROW_MAX', 5000 );

/**
 * media_rewrite_refs: the database half of the webp-media reference
 * rewrite, in two modes over one op.
 *
 * READ (``apply=false``, the default and the only mode that writes
 * nothing) streams NDJSON, one object per row that may hold a raster
 * reference:
 *
 *   {"table":"wp_postmeta","key":"meta_id","id":123,"value":"<the cell>",
 *    "gated":["<a gated cell in the same row>", ...]}
 *   {"table":"wp_comments","key":"comment_ID","id":9,
 *    "gated":["<comment_content>"]}
 *
 * ``value`` is present only for a REWRITABLE surface; ``gated`` only when
 * the row carries one. The stream ends with
 * ``{"ok":true,"rows":N,"gated_cells":M,"truncated":false}`` — the client's
 * proof that the scan finished — or, at the cap, with
 * ``{"truncated":true}`` and nothing else, which the client REFUSES. A
 * scan that FAILS part way through ends with the terminal
 * ``{"ok":false,"error":…,"type":…,"line":…}`` line instead, which the
 * client also refuses (there is no completion marker).
 *
 * Optional ``scan_cap`` (a positive integer) moves the truncation point
 * for a site that really does exceed the default. It is CLAMPED to
 * WPT_MEDIA_REWRITE_SCAN_CAP_MAX and never above it, and a clamped request
 * says so ONCE, on the completion line:
 * ``{"ok":true,…,"truncated":false,"scan_cap_clamped":1000000}``. A cap
 * inside the bounds leaves that line byte-identical to one without. The
 * parameter is REACHABLE from the tool, not only from a hand-written
 * request: wpt.wpbridge.client.Bridge.iter_rewrite_refs(scan_cap=…)
 * forwards it, logs that clamp as a WARNING, and a malformed cap is a
 * structured refusal rather than a silent default.
 *
 * A site carrying NONE of these surfaces answers an empty stream. That is
 * a real measurement, and the safe direction: the caller plans no
 * conversion from an empty reference set, and it is the ABSENCE of the
 * completion line — not the row count — that says "unproven".
 *
 * APPLY (``apply=true``) writes. Params: ``mapping`` {old ref: new ref}
 * and ``rows`` [{table, key, id, value?}]. A row carrying ``value`` is
 * written verbatim (the client computed it); a row without one is
 * rewritten SERVER-SIDE through WordPress's own
 * maybe_unserialize -> recursive string-leaf replace -> maybe_serialize,
 * which is the only thing that can rewrite a length-prefixed
 * ``s:NN:`` value correctly. Every row is re-read after its write and the
 * answer carries the value the server READ BACK, so the caller's
 * verification is the server's own proof and not an assumption:
 *
 *   {"ok":true,"rows":[{"table":..,"id":..,"value":"<re-read>"}],
 *    "failed":["wp_postmeta[7] (did not verify)"]}
 *
 * A row the rewrite cannot carry out COMPLETELY lands in ``failed`` and is
 * left exactly as it was: the value is serialized-but-unreadable, two of
 * its array keys rewrite onto the same value (a PHP array would silently
 * drop one of them — the label names the key), or it FAILS one of the two
 * shape proofs in wpt_media_rewrite_shape_proof and re-storing it would
 * make a lost member permanent — the label names the level, the key, and
 * WHICH proof failed, so an operator can tell a loss already in the row (no
 * reference this run holds can recover it) from one the write would
 * introduce. What is NOT in that list, because it is not a loss this op can
 * see: a collapse confined inside a serialized OBJECT's properties. Such a
 * row is still rewritten, as it always was, and NO proof is claimed over it
 * (SPEC R28) — the second proof does not extend the reach of the first
 * there, it only covers what the first cannot read at all.
 *
 * Fail-closed, in db_restore_table's discipline: every row is validated
 * (whitelisted rewritable table, the op's OWN key column for it, a
 * positive integer id, a string value) BEFORE the first write, so a
 * malformed request writes nothing at all. There is no arbitrary SQL and
 * no arbitrary identifier: the table, the key column, the value column
 * and the gated columns all come from information_schema.
 */
function wpt_action_media_rewrite_refs( array $params ) {
	// Strict booleans: !empty() would treat the string "false" as true.
	$apply = isset( $params['apply'] ) && true === $params['apply'];
	if ( $apply ) {
		return wpt_media_rewrite_apply( $params );
	}
	// ``scan_cap`` is a READ-mode parameter (the apply never scans); the
	// resolver validates it and decides whether the ceiling applies.
	return wpt_media_rewrite_scan(
		array_key_exists( 'scan_cap', $params ) ? $params['scan_cap'] : null
	);
}

/**
 * The read-only half: stream every reference-bearing row (see
 * wpt_action_media_rewrite_refs for the wire shapes).
 *
 * The op answers its OWN failures. Once the first row is on the wire this
 * function can no longer hand a clean envelope back: the global Throwable
 * handler runs after output, and every header it would set is too late.
 * So the failure line is written here, as the LAST line of the stream, in
 * the same ``{"ok":false,"error":…,"type":…,"line":…}`` shape the handler
 * uses — a client that reads the last line gets the server's real reason
 * instead of a PHP warning it never asked for.
 */
function wpt_media_rewrite_scan( $cap = null ) {
	global $wpdb;
	$surfaces  = wpt_media_rewrite_surfaces();
	$effective = wpt_media_rewrite_scan_cap( $cap, $clamped );
	// Same rule as wpt_bridge_send: a Content-Type set after output has
	// started only buys a PHP warning in front of the stream.
	if ( ! headers_sent() ) {
		header( 'Content-Type: application/x-ndjson' );
	}
	$emitted   = 0;
	$gated     = 0;
	$truncated = false;
	try {
		foreach ( $surfaces as $table => $spec ) {
			$columns = array( $spec['key'] );
			$clauses = array();
			if ( '' !== $spec['value'] ) {
				$columns[] = $spec['value'];
				$clauses   = array_merge( $clauses, wpt_media_rewrite_filter( $spec['value'] ) );
			}
			foreach ( $spec['gated'] as $column ) {
				$columns[] = $column;
				$clauses   = array_merge( $clauses, wpt_media_rewrite_filter( $column ) );
			}
			$select = 'SELECT ' . implode( ', ', array_map(
				function ( $column ) { return '`' . wpt_backtick( $column ) . '`'; },
				$columns
			) ) . ' FROM `' . wpt_backtick( $table ) . '` WHERE ' . implode( ' OR ', $clauses );
			$rows   = $wpdb->get_results( $select, ARRAY_A );
			if ( ! is_array( $rows ) ) {
				throw new RuntimeException( 'reference scan failed for ' . $table );
			}
			foreach ( $rows as $row ) {
				$id   = isset( $row[ $spec['key'] ] ) ? (int) $row[ $spec['key'] ] : 0;
				$line = array( 'table' => $table, 'key' => $spec['key'], 'id' => $id );
				if ( '' !== $spec['value'] ) {
					$cell = isset( $row[ $spec['value'] ] ) ? $row[ $spec['value'] ] : null;
					if ( is_string( $cell ) && '' !== $cell ) {
						$line['value'] = wpt_json_safe_cell( $cell );
					}
				}
				$cells = array();
				foreach ( $spec['gated'] as $column ) {
					$cell = isset( $row[ $column ] ) ? $row[ $column ] : null;
					if ( is_string( $cell ) && '' !== $cell ) {
						$cells[] = wpt_json_safe_cell( $cell );
					}
				}
				if ( $cells ) {
					$line['gated'] = $cells;
					$gated         += count( $cells );
				}
				wpt_ndjson_out( $line );
				$emitted++;
				if ( $emitted >= $effective ) {
					$truncated = true;
					break 2;
				}
			}
		}
	} catch ( Throwable $e ) {
		// The rows above are already on the wire, so this IS the answer:
		// the same shape the dispatcher's Throwable handler would have
		// written, and it never runs header() (wpt_bridge_send skips it
		// once output is out) so no PHP warning can precede it.
		//
		// LENIENT, like the collided-key label: an exception message is
		// arbitrary bytes (a database error carrying a latin1 column, a
		// path from a mis-encoded row), and the strict encoder THROWS on
		// invalid UTF-8 — inside this catch, so the line below was never
		// written, the client saw a stream that simply stopped, and the
		// one answer that carries the real reason was replaced by a PHP
		// fatal on the production site. A diagnostic must never be able to
		// take down the diagnostic.
		wpt_ndjson_out( array(
			'ok'    => false,
			'error' => $e->getMessage(),
			'type'  => get_class( $e ),
			'line'  => $e->getLine(),
		), true );
		return null;
	}
	if ( $truncated ) {
		wpt_ndjson_out( array( 'truncated' => true ) );
		return null;
	}
	$done = array( 'ok' => true, 'rows' => $emitted, 'gated_cells' => $gated, 'truncated' => false );
	if ( $clamped ) {
		// ONCE, on the one line the client already reads as "the scan
		// finished": the operator asked for a cap the op will not honour,
		// and the answer they get is the ceiling.
		$done['scan_cap_clamped'] = $effective;
	}
	wpt_ndjson_out( $done );
	return null;
}

/**
 * A {string: string} param (the rewrite mapping), validated entry by
 * entry. A JSON object with a numeric key decodes to an int key in PHP,
 * which a rewrite reference can never be, so it is refused rather than
 * silently renumbered.
 */
function wpt_param_str_map( array $params, $key ) {
	if ( ! isset( $params[ $key ] ) || ! is_array( $params[ $key ] ) ) {
		throw new InvalidArgumentException( 'missing or non-array param: ' . $key );
	}
	$out = array();
	foreach ( $params[ $key ] as $name => $value ) {
		if ( ! is_string( $name ) || ! is_string( $value ) ) {
			throw new InvalidArgumentException( 'invalid ' . $key . ' entry' );
		}
		if ( '' === $name || '' === $value || strlen( $name ) > 1024 || strlen( $value ) > 1024 ) {
			throw new InvalidArgumentException( 'invalid ' . $key . ' entry' );
		}
		if ( false !== strpos( $name, "\0" ) || false !== strpos( $value, "\0" ) ) {
			throw new InvalidArgumentException( 'invalid ' . $key . ' entry' );
		}
		if ( preg_match( '#(?:^|/)\.\.(?:/|$)#', $name ) || preg_match( '#(?:^|/)\.\.(?:/|$)#', $value ) ) {
			throw new InvalidArgumentException( 'invalid ' . $key . ' entry (traversal)' );
		}
		$out[ $name ] = $value;
	}
	return $out;
}

/**
 * The rewriting half (see wpt_action_media_rewrite_refs for the wire
 * shapes). Every row is validated before the first write; a row that
 * cannot be read, written or re-read lands in ``failed`` with the reason
 * and never as a rewritten row.
 *
 * NOTHING ABORTS THE BATCH.  A row is processed inside a per-row
 * ``try``/``catch ( Throwable )``, so every reason a row can be refused —
 * unreadable, unrewritable, unverifiable, or a THROW from a shape proof
 * that cannot be spent within its work budget (WPT_MEDIA_SHAPE_WORK_BUDGET)
 * — travels on the one per-row channel the contract already has, and the
 * answer is always a complete ``{rows, failed}`` pair.  The alternative
 * was measured: the budget throw escaped the loop, so the rows before it
 * were already UPDATEd, the op answered an op-level error naming no row,
 * and the client could not tell a partial write from a whole one.  A
 * per-file answer is the only answer that survives a refusal, so the
 * refusal is per-file.
 */
function wpt_media_rewrite_apply( array $params ) {
	global $wpdb;
	$mapping = wpt_param_str_map( $params, 'mapping' );
	if ( ! $mapping ) {
		throw new InvalidArgumentException( 'empty mapping' );
	}
	$rows = wpt_param_list( $params, 'rows' );
	if ( count( $rows ) > WPT_MEDIA_REWRITE_ROW_MAX ) {
		throw new InvalidArgumentException( 'too many rows (max ' . WPT_MEDIA_REWRITE_ROW_MAX . ' per call)' );
	}
	$surfaces = wpt_media_rewrite_surfaces( true );

	// Validate EVERY row first: a request that names a table this op may
	// not rewrite, a key column that is not the op's own, a non-integer
	// id or a non-string value writes NOTHING.
	$plan = array();
	foreach ( $rows as $row ) {
		if ( ! is_array( $row ) ) {
			throw new InvalidArgumentException( 'rows must be an array of objects' );
		}
		$table = ( isset( $row['table'] ) && is_string( $row['table'] ) ) ? $row['table'] : '';
		if ( ! isset( $surfaces[ $table ] ) ) {
			throw new InvalidArgumentException( 'table not rewritable: ' . $table );
		}
		$key = ( isset( $row['key'] ) && is_string( $row['key'] ) ) ? $row['key'] : '';
		if ( $key !== $surfaces[ $table ]['key'] ) {
			throw new InvalidArgumentException( 'unexpected key column for ' . $table . ': ' . $key );
		}
		$id = isset( $row['id'] ) ? $row['id'] : null;
		if ( is_bool( $id ) || ( ! is_int( $id ) && ! ( is_string( $id ) && ctype_digit( $id ) ) ) ) {
			throw new InvalidArgumentException( 'invalid row id for ' . $table );
		}
		$id = (int) $id;
		if ( $id < 1 ) {
			throw new InvalidArgumentException( 'invalid row id for ' . $table );
		}
		$has_value = array_key_exists( 'value', $row );
		if ( $has_value && ! is_string( $row['value'] ) ) {
			throw new InvalidArgumentException( 'row value must be a string for ' . $table );
		}
		$plan[] = array(
			'table'     => $table,
			'id'        => $id,
			'has_value' => $has_value,
			'value'     => $has_value ? $row['value'] : null,
		);
	}

	$written = array();
	$failed  = array();
	foreach ( $plan as $edit ) {
		$table = $edit['table'];
		$spec  = $surfaces[ $table ];
		$label = $table . '[' . $edit['id'] . ']';
		// EVERY row is processed inside this catch, so a THROW travels on
		// the per-row channel that already exists for "this row must not be
		// written" and never becomes an op-level error.  A shape proof that
		// cannot be spent (wpt_media_rewrite_array_shape throws past its
		// work budget) is exactly that: the row is named, the reason is
		// carried, the row is left exactly as it is — and the batch still
		// completes, so the answer states precisely which rows WERE
		// written.  Before this catch a budget refusal aborted the whole
		// batch: the rows before it were already UPDATEd, and the client
		// was handed an error naming no row at all, so it could not tell a
		// partial write from a whole one.  Nothing may abort a batch: the
		// per-file answer is the contract, and an op-level throw is the one
		// answer that loses it.
		try {
			$read  = $wpdb->prepare(
				'SELECT `' . wpt_backtick( $spec['value'] ) . '` FROM `' . wpt_backtick( $table ) . '`'
				. ' WHERE `' . wpt_backtick( $spec['key'] ) . '` = %d',
				$edit['id']
			);
			$current_row = $wpdb->get_row( $read, ARRAY_A );
			if ( ! is_array( $current_row ) || ! array_key_exists( $spec['value'], $current_row ) ) {
				$failed[] = $label . ' (row not found)';
				continue;
			}
			$current = (string) $current_row[ $spec['value'] ];
			if ( $edit['has_value'] ) {
				$new = $edit['value'];
			} else {
				$reason  = '';
				$new     = wpt_media_rewrite_value( $current, $mapping, $reason );
				if ( null === $new ) {
					// A value that cannot be rewritten COMPLETELY is never
					// rewritten partially: the row is named, the reason is
					// carried, and the row is left exactly as it was.
					$failed[] = $label . ' (' . $reason . ')';
					continue;
				}
			}
			if ( $new !== $current ) {
				$written_rows = $wpdb->query( $wpdb->prepare(
					'UPDATE `' . wpt_backtick( $table ) . '` SET `' . wpt_backtick( $spec['value'] ) . '` = %s'
					. ' WHERE `' . wpt_backtick( $spec['key'] ) . '` = %d',
					$new,
					$edit['id']
				) );
				if ( false === $written_rows ) {
					$failed[] = $label . ' (write failed)';
					continue;
				}
				wpt_media_rewrite_invalidate( $table, $spec, $edit['id'] );
			}
			// The RE-READ is the proof: the answer carries what the server
			// reads back, never what it was asked to write.
			$fresh  = $wpdb->get_row( $read, ARRAY_A );
			$stored = ( is_array( $fresh ) && array_key_exists( $spec['value'], $fresh ) )
				? (string) $fresh[ $spec['value'] ]
				: null;
			if ( null === $stored || $stored !== $new ) {
				$failed[] = $label . ' (did not verify)';
				continue;
			}
			$written[] = array( 'table' => $table, 'id' => $edit['id'], 'value' => wpt_json_safe_cell( $stored ) );
		} catch ( Throwable $e ) {
			// The SAME single-line-safe treatment the key labels get (a
			// diagnostic must never take the diagnostic down: an exception
			// message is arbitrary bytes, and the strict answer encoder
			// THROWS on invalid UTF-8, which inside this catch would take
			// the whole answer with it).
			//
			// The BARE message, and nothing else: this channel is ASSEMBLED
			// HERE and READ by one client, and the operator-facing refusal
			// marker is that client's to write (wpt/wpbridge/client.py
			// _refusal_label adds it exactly once).  Prefixing it here made
			// the marker a SECOND producer for the same fact, and every
			// reason this catch carries already opens with it — the shape
			// proofs word their refusals that way on purpose, so a caller
			// reading a refusal string always finds the marker — so the
			// operator read "refused: refused: this value is nested too
			// deeply …".  The three fixed status labels above are not
			// reasons and are spelled without a marker; the client leaves
			// those alone.
			$failed[] = $label . ' ('
				. wpt_media_rewrite_label_key( $e->getMessage() ) . ')';
		}
	}
	return array( 'rows' => $written, 'failed' => $failed );
}

/**
 * The refusal marker wpt_media_rewrite_leaves returns INSTEAD of a
 * rewritten structure whose array keys collided (see that function). A
 * unique OBJECT instance, not null and not a sentinel string: `null` is a
 * legal leaf of a serialized payload ("N;") and any string could be real
 * site data, so neither could be told apart from a refusal.
 */
final class WPT_Media_Rewrite_Refused {
	/** @var string The key the collision landed on (already bounded). */
	public $key;

	/**
	 * @param string $key The rewritten key a second key also rewrote to.
	 */
	public function __construct( $key ) {
		$this->key = wpt_media_rewrite_label_key( $key );
	}
}

/**
 * The collided key, rendered for the one ``failed`` label it travels in.
 * All three properties are load-bearing, not tidiness: a control character
 * would break the line the label travels in, bytes the answer's encoder
 * refuses would make its json_encode() THROW (a refusal must never turn
 * into a fatal with no answer at all), and an unbounded key would turn one
 * label into a data dump. The key is an uploads-relative path or a size
 * name, never a credential — naming it is the whole point, since a bare
 * "refused" leaves the operator nothing to act on.
 */
function wpt_media_rewrite_label_key( $key ) {
	$text = preg_replace( '/[\x00-\x1F\x7F]+/', ' ', (string) $key );
	// The SAME encoder the answer itself uses, asked the SAME question:
	// a latin1 column really does hand over bytes it refuses (the bridge
	// already answers such a CELL through wpt_json_safe_cell), and one
	// unencodable byte in a label must not take the whole answer down with
	// it. Folding the non-ASCII bytes keeps the label single-line ASCII,
	// which is what an operator-facing line wants anyway.
	try {
		json_encode( $text, JSON_THROW_ON_ERROR );
	} catch ( JsonException $e ) {
		$text = preg_replace( '/[\x80-\xFF]/', '?', $text );
	}
	if ( preg_match( '/^.{1,200}/us', $text, $cut ) ) {
		return $cut[0];   // CHARACTERS, so a multi-byte key is never cut in half
	}
	return substr( $text, 0, 200 );
}

/**
 * Is this the refusal marker (rather than a rewritten structure)?
 */
function wpt_media_rewrite_refused( $data ) {
	return $data instanceof WPT_Media_Rewrite_Refused;
}

/**
 * One stored DB value with every convertible reference moved to its twin,
 * through WordPress's own serialization helpers: maybe_unserialize,
 * a recursive string-leaf replace, maybe_serialize. A plain value passes
 * through the helpers unchanged, so the same call serves both shapes —
 * and only PHP can rewrite the ``s:NN:`` byte-length prefixes a
 * serialized string carries, which is why a serialized row travels
 * without a precomputed value.
 *
 * NULL means "this value must not be written", and $refusal (an out
 * parameter) carries WHY. Both fail directions matter, and both are
 * silent-data-loss directions if they are not refused:
 *
 *  - UNREADABLE. A value that LOOKS serialized but cannot be
 *    unserialized makes maybe_unserialize() return false, and serializing
 *    that would store an EMPTY value — silently blanking a post body. The
 *    op reports the row as failed instead, which is also what the caller
 *    already decided on its own side (an unparseable value is GATED
 *    there, never rewritten). ``b:0;`` is the one serialized value that
 *    legitimately unserializes to false, so it is not mistaken for the
 *    failure.
 *  - KEY COLLISION. A PHP array is a MAP: when two of its keys rewrite
 *    onto the same value the array COLLAPSES and one member is silently
 *    dropped. Storing the collapse would return ``ok:true`` with an empty
 *    ``failed`` list — the re-read compares against what was just written,
 *    so it "proves" the loss — and the caller's verification only looks
 *    for SURVIVING stale references, so a lost sibling passes. The whole
 *    value is refused instead, and the label names the key.
 *  - LOSS ALREADY IN THE STORED VALUE (wpt_media_rewrite_shape_proof). The
 *    collapse the key-collision rule above catches is the one the REWRITE
 *    makes; PHP makes another one BEFORE the rewrite is even offered, while
 *    unserializing: a payload that declares ``s:3:"foo"`` twice, or a
 *    string key ``"1"`` beside the integer key ``1``, already reads back as
 *    ONE member. Re-serializing that array PERSISTS the loss — the bytes are
 *    gone from the row for good, and a snapshot taken after the write can no
 *    longer restore them — while the answer says ``ok:true``, ``failed:[]``,
 *    and the re-read "verifies" the smaller value it just wrote. So the
 *    value is proved TWICE before it is touched, and refused if EITHER proof
 *    fails: the stored bytes against the value PHP reads out of them (that
 *    is the only view of a loss PHP made while READING the row, because both
 *    sides of any comparison downstream of ``unserialize()`` are already
 *    post-loss), and the value against the one PHP's OWN ``serialize()``
 *    produces, which is the only view of a value its own encoder cannot
 *    reproduce. Both compare STRUCTURALLY, level by level — never
 *    byte-for-byte, because a re-encoding is legitimately not byte-stable
 *    (``"0"`` becomes ``i:0;``) and comparing bytes would refuse every
 *    healthy rewrite. This is a property of the VALUE, so it is checked on
 *    every serialized row, including one whose mapping rewrites nothing at
 *    all. What is NOT proven, and is deliberately not refused either: a
 *    collapse confined inside a serialized OBJECT's properties (SPEC R28) —
 *    the row is rewritten as it always was, and no proof is claimed over it.
 */
function wpt_media_rewrite_value( $value, array $mapping, &$refusal = null ) {
	$refusal = null;
	if ( is_serialized( $value ) ) {
		$data = maybe_unserialize( $value );
		if ( false === $data && 'b:0;' !== trim( $value ) ) {
			$refusal = 'value is serialized but unreadable';
			return null;
		}
		if ( ! is_array( $data ) && ! is_object( $data ) ) {
			// A SCALAR payload ("i:5;", "b:0;", "d:1.5;", "N;") holds no
			// string leaf, and maybe_serialize() hands a scalar back
			// UNSERIALIZED — storing that would replace the value with the
			// two characters "0" or "5".  Nothing to rewrite, so the value
			// is returned exactly as it is.
			return $value;
		}
		if ( is_array( $data ) ) {
			// The value as it is ON DISK against the value PHP reads out of
			// it, and the value against the one PHP's OWN encoder produces.
			// This is the one thing the key-collision rule above cannot see,
			// and it is decided BEFORE the rewrite: a rewrite changes key
			// TEXT (that is its job) but must never change how many members
			// a level holds, and the value that would be stored is the one
			// PHP already read.  Two proofs, one verdict
			// (wpt_media_rewrite_shape_proof); a value it cannot prove is
			// rewritten exactly as it always was, and a value it refuses is
			// not written at all.
			$proof = wpt_media_rewrite_shape_proof( $value, $data );
			if ( 'refused' === $proof['verdict'] ) {
				$refusal = wpt_media_rewrite_shape_refusal( $proof );
				return null;
			}
		}
	} else {
		$data = $value;
	}
	$rewritten = wpt_media_rewrite_leaves( $data, $mapping, 0 );
	if ( wpt_media_rewrite_refused( $rewritten ) ) {
		$refusal = 'refused: two keys of this value both rewrite to "'
			. $rewritten->key . '", and a PHP array would drop one of them';
		return null;
	}
	return (string) maybe_serialize( $rewritten );
}

/**
 * Every string inside an unserialized structure, rewritten, depth-bounded
 * (12 levels, the same structural bound wpt/actions/images_webp.py's
 * _string_leaves uses: an adversarially deep payload must not turn a
 * rewrite into a recursion crash). Array KEYS are rewritten too — a
 * serialized map keyed by an uploads path is real site data. A payload
 * OBJECT is returned untouched (its properties are not string leaves this
 * rule can rewrite without instantiating its class): a reference inside
 * one keeps its original bytes and the caller's post-write verification
 * still sees it, which is the fail direction.
 *
 * Rewriting a KEY can make two keys of the SAME array equal, and a PHP
 * array then holds one member instead of two. That collapse is DETECTED
 * (array_key_exists against what this loop has already placed, which is
 * exactly the condition under which ``$out[$new_key] =`` would overwrite)
 * and reported as a WPT_Media_Rewrite_Refused marker instead of being
 * performed — a rewritten structure is never returned smaller than the one
 * it came from. Only KEYS collide: two VALUES that rewrite to the same text
 * are two members of a list and both are kept.
 *
 * This is the REWRITE-INDUCED half of that guarantee, and it is the only
 * half that can be a key-collision: it is checked on the value as it is
 * being rebuilt, so it sees exactly the collapse it is about to perform. The
 * other half — a collapse already in the STORED bytes, made by PHP's own key
 * cast while the row was read — is invisible here and belongs to
 * wpt_media_rewrite_shape_proof. Both are kept: neither subsumes the other,
 * and the one that was INERT is the one with a test that asks it for a
 * verdict on a real value.
 */
function wpt_media_rewrite_leaves( $data, array $mapping, $depth ) {
	if ( $depth > 12 ) {
		return $data;
	}
	if ( wpt_media_rewrite_refused( $data ) ) {
		return $data;
	}
	if ( is_string( $data ) ) {
		return wpt_media_rewrite_text( $data, $mapping );
	}
	if ( is_array( $data ) ) {
		$out = array();
		foreach ( $data as $key => $value ) {
			$new_key = is_string( $key ) ? wpt_media_rewrite_text( $key, $mapping ) : $key;
			if ( array_key_exists( $new_key, $out ) ) {
				return new WPT_Media_Rewrite_Refused( $new_key );
			}
			$new_value = wpt_media_rewrite_leaves( $value, $mapping, $depth + 1 );
			if ( wpt_media_rewrite_refused( $new_value ) ) {
				return $new_value;
			}
			$out[ $new_key ] = $new_value;
		}
		return $out;
	}
	return $data;
}

/**
 * One PHP array key reduced to the ONE form the shape proofs speak, on
 * every side of both comparisons.
 *
 * This is where a collapse happens: a PHP array is a map, so ``s:1:"1"`` and
 * ``i:1;`` are ONE key of it and the second member written under it is gone.
 * PHP's own cast is therefore reproduced exactly, not approximated —
 * a CANONICAL decimal integer inside the platform's int range becomes an
 * integer key, and nothing else does. The round trip through ``(int)`` is
 * what makes "inside the range" exact on any build, and the four forms PHP
 * keeps as strings anyway (``01``, ``-0``, ``+1``, ``1.0``) stay distinct
 * keys here too, exactly as they are distinct members of the array it
 * builds. The rule is asked of real PHP by
 * test_media_rewrite_refs_key_shape_is_php_own_array_key_cast, because a
 * table of what "looks numeric" means would be an approximation of the very
 * rule that has to be exact.
 */
function wpt_media_rewrite_key_shape( $key ) {
	if ( is_int( $key ) ) {
		return 'i:' . $key;
	}
	$text = (string) $key;
	// The first-byte test is not the rule, only the cheap half of it: no
	// canonical decimal integer starts with anything else, and a level of a
	// real option value is mostly size names and paths, so this keeps the
	// regex off the hot path of a walk over every level of every value.
	if ( '' !== $text && ( '-' === $text[0] || ( $text[0] >= '0' && $text[0] <= '9' ) )
		&& preg_match( '/\A(?:0|-?[1-9][0-9]*)\z/', $text )
		&& (string) (int) $text === $text ) {
		return 'i:' . (int) $text;
	}
	return 's:' . $text;
}

/**
 * Read the ``<digits>:`` length/count header a token starts with. NULL when
 * the bytes at $pos are not one — which is how the caller learns the stream
 * is not describable rather than guessing at it.
 */
function wpt_media_rewrite_declared_length( $text, &$pos, $end ) {
	$start  = $pos;
	$cursor = $pos;
	while ( $cursor < $end && $text[ $cursor ] >= '0' && $text[ $cursor ] <= '9' ) {
		$cursor++;
	}
	if ( $cursor === $start || $cursor >= $end || ':' !== $text[ $cursor ] ) {
		return null;
	}
	$pos = $cursor + 1;
	return (int) substr( $text, $start, $cursor - $start );
}

/**
 * ONE token of a serialized stream, and the offset just past it.
 *
 * Returns ``array( type, value )`` — the type character, plus the payload
 * that matters for it: the integer of an ``i:`` token, the BYTES of an
 * ``s:`` token (a member key is one), the declared count of an ``a:``/``O:``
 * token. NULL when the bytes at $pos are not a token this reader knows.
 *
 * Deliberately a reader of the SERIALIZATION GRAMMAR and not a second
 * unserialize: the whole point is to see the members the bytes DECLARE,
 * which is precisely what unserialize() drops. A value it cannot read is
 * reported as unreadable rather than half-believed, so the caller skips the
 * proof instead of proving the wrong thing.
 *
 * ``C:`` (Serializable) and ``E:`` (enum) carry raw data and a case name
 * where members would be, so they are NOT read: a value containing one is
 * reported as not describable. ``R:``/``r:`` are a back-reference to a value
 * serialized earlier — still a MEMBER of the array that holds them, so the
 * member is counted and its key compared, and the referenced value is proved
 * at the position where it was written.
 */
function wpt_media_rewrite_declared_token( $text, &$pos, $end ) {
	if ( $pos >= $end ) {
		return null;
	}
	$type = $text[ $pos ];
	if ( 'N' === $type ) {
		if ( 'N;' !== substr( $text, $pos, 2 ) ) {
			return null;
		}
		$pos += 2;
		return array( 'N', null );
	}
	if ( 'b' === $type || 'd' === $type || 'R' === $type || 'r' === $type ) {
		$stop = strpos( $text, ';', $pos );
		if ( false === $stop || $stop < $pos + 3 ) {
			return null;
		}
		$pos = $stop + 1;
		return array( $type, null );
	}
	if ( 'i' === $type ) {
		$stop = strpos( $text, ';', $pos );
		if ( false === $stop || ':' !== substr( $text, $pos + 1, 1 ) ) {
			return null;
		}
		$body = substr( $text, $pos + 2, $stop - $pos - 2 );
		if ( ! preg_match( '/\A-?[0-9]+\z/', $body ) ) {
			return null;
		}
		$pos = $stop + 1;
		return array( 'i', (int) $body );
	}
	if ( 's' !== $type && 'a' !== $type && 'O' !== $type && 'o' !== $type ) {
		return null;
	}
	// Every remaining token is "<type>:<number>:…" — the type's own colon
	// first, then the length/count header.
	if ( ':' !== substr( $text, $pos + 1, 1 ) ) {
		return null;
	}
	$cursor = $pos + 2;
	if ( 's' === $type ) {
		$length = wpt_media_rewrite_declared_length( $text, $cursor, $end );
		if ( null === $length || '"' !== substr( $text, $cursor, 1 ) ) {
			return null;
		}
		$cursor++;
		if ( $cursor + $length + 2 > $end
			|| '"' !== substr( $text, $cursor + $length, 1 )
			|| ';' !== substr( $text, $cursor + $length + 1, 1 ) ) {
			return null;
		}
		$value = substr( $text, $cursor, $length );
		$pos   = $cursor + $length + 2;
		return array( 's', $value );
	}
	// 'a' (array), 'O'/'o' (object): both open a member list. The object
	// forms carry a class name first, consumed here so the members that
	// follow are read as ordinary key/value pairs.
	if ( 'a' !== $type ) {
		$name = wpt_media_rewrite_declared_length( $text, $cursor, $end );
		if ( null === $name || '"' !== substr( $text, $cursor, 1 ) ) {
			return null;
		}
		$cursor++;
		if ( $cursor + $name + 2 > $end
			|| '"' !== substr( $text, $cursor + $name, 1 )
			|| ':' !== substr( $text, $cursor + $name + 1, 1 ) ) {
			return null;
		}
		$cursor += $name + 2;
	}
	$count = wpt_media_rewrite_declared_length( $text, $cursor, $end );
	if ( null === $count || '{' !== substr( $text, $cursor, 1 ) ) {
		return null;
	}
	$pos = $cursor + 1;
	// Each member costs at least two bytes ("0;"), so a count the bytes
	// cannot possibly hold is a header this reader does not believe.
	// Bounded here rather than by a member counter: the caller's loop is
	// then bounded by the size of the value itself.
	if ( $count * 2 > $end - $pos ) {
		return null;
	}
	return array( $type, $count );
}

/**
 * The structure a serialized value DECLARES: every ARRAY level, as
 * ``member path => the keys of that level, in the order they are written``,
 * with the path being the member POSITIONS from the root ("" is the value
 * itself, "0." its first member, "0.1." the first member of that).
 *
 * The counterpart of wpt_media_rewrite_array_shape, and the ONLY way to see
 * a loss PHP makes BEFORE wpt is offered the value: a payload may declare a
 * member the array PHP builds cannot hold (``s:3:"foo"`` twice, ``s:1:"1"``
 * beside ``i:1;``), and by the time ``unserialize()`` has run that member is
 * already gone. It is therefore not the re-store that loses it — the stored
 * bytes no longer hold it either — but the loss is not visible to anything
 * downstream of ``unserialize()``, and re-serializing the value is what
 * makes it permanent: the re-read compares against what was just written and
 * so "proves" it, and the caller's verification only looks for SURVIVING
 * stale references, so the lost sibling passes. PHP's own round trip
 * (wpt_media_rewrite_round_trip) CANNOT stand in for this: it compares two
 * values that are both already post-unserialize, and they always agree.
 * Positions, not keys, are the path because a collapse also SHIFTS the keys
 * that survive it; the comparison is level by level, so the shallowest
 * divergence is the one reported, which is the one an operator can go and
 * look at.
 *
 * Iterative, with the open levels on an explicit stack: a payload nested
 * deeper than any PHP recursion could follow (unserialize() itself accepts
 * 4096) is read without touching the C stack, and the rewrite's own 12-level
 * bound is irrelevant here — this reads what is STORED, not what the
 * rewrite touched.
 *
 * A LEVEL IS CLOSED BY ITS OWN "}", AND THAT BYTE IS CONSUMED.  This is not
 * tidiness; it is the whole defect the previous version of this function
 * had.  It popped a level the moment its declared member count was spent
 * WITHOUT consuming the "}" that closes it, and then asked the level ABOVE
 * for a member key — at a "}", which is not a key, so it gave up and
 * returned NULL.  An EMPTY level made it worse, because that one pushed no
 * frame at all, so its own "}" was read as a member key of its parent.
 * Measured against the pre-fix reader: every value holding a nested array
 * that is not the last member of its level came back "no proof", and a
 * healthy ``_wp_attachment_metadata`` is ``file``, ``sizes``, ``image_meta``
 * — so the guarantee this family documents was never exercised on any real
 * WordPress value.  Fail-OPEN, and silently so, because a reader that
 * declines to describe something looks exactly like a reader that has
 * nothing to report.  (That is also why the frame protocol is spelled out
 * here rather than left to the code: a proof whose failure mode is "I did
 * not look" needs its liveness pinned by a test that asks for a verdict on
 * a REAL value, which test_media_rewrite_shape_proof_reads_a_real_value
 * does, level by level.)
 *
 * An OBJECT level, and everything inside it, is walked (its members are
 * ordinary pairs, so the bytes after it are still read exactly) but never
 * recorded: an object's properties are not string leaves this rule
 * rewrites, and the names PHP materializes for them are not the ones the
 * bytes declare (a private property is stored mangled, with NUL bytes in
 * the name), so a key comparison there would refuse real payloads. A value
 * whose shape cannot be read at all — a ``C:``/``E:`` token, a header this
 * reader does not believe — returns NULL, and the caller then performs the
 * OTHER proof (PHP's own round trip) rather than none; the rewrite-induced
 * collapse is still caught, independently, by wpt_media_rewrite_leaves.
 */
function wpt_media_rewrite_declared_shape( $serialized ) {
	$text = trim( (string) $serialized );
	$end  = strlen( $text );
	$out  = array();
	$pos  = 0;
	// Each open level: array( path, members left, members read, recorded ).
	// No per-level KEY LIST is kept here: the keys of a recorded level are
	// accumulated in $out as they are read, and a frame that held them too
	// would be copied (copy-on-write) on every member it gained, which is
	// quadratic in the size of the level.
	$frames = array();
	$rooted = false;
	while ( true ) {
		$open = count( $frames );
		if ( 0 === $open ) {
			if ( $rooted ) {
				break;          // trailing bytes, which unserialize ignores too
			}
			$path   = '';        // the value itself
			$parent = null;
		} else {
			$parent = $frames[ $open - 1 ];
			if ( $parent['read'] < $parent['left'] ) {
				$path = $parent['path'] . $parent['read'] . '.';
				$frames[ $open - 1 ]['read']++;
				$member = wpt_media_rewrite_declared_token( $text, $pos, $end );
				if ( null === $member || ( 'i' !== $member[0] && 's' !== $member[0] ) ) {
					return null;   // a member key is an int or a string, always
				}
				if ( $parent['recorded'] ) {
					$out[ $parent['path'] ][] = wpt_media_rewrite_key_shape( $member[1] );
				}
			} else {
				// Every member of this level is read, so the byte that closes
				// it is next.  Consuming it is what keeps the level above
				// reading MEMBER KEYS rather than a brace (see the note
				// above); a stream that does not close a level it opened
				// declares more members than it carries, which
				// unserialize() rejects outright, so this is unreachable
				// from the op and a reader that ends early must not report a
				// shape it did not finish reading.
				if ( '}' !== substr( $text, $pos, 1 ) ) {
					return null;
				}
				$pos++;
				array_pop( $frames );
				continue;
			}
		}
		$token = wpt_media_rewrite_declared_token( $text, $pos, $end );
		if ( null === $token ) {
			return null;
		}
		if ( ! $parent ) {
			$rooted = true;
		}
		if ( 'a' === $token[0] || 'O' === $token[0] || 'o' === $token[0] ) {
			$record = ( 'a' === $token[0] );
			if ( $record ) {
				$out[ $path ] = array();
			}
			if ( $token[1] > 0 ) {
				$frames[] = array(
					'path'     => $path,
					'left'     => (int) $token[1],
					'read'     => 0,
					'recorded' => $record,
				);
			} elseif ( '}' !== substr( $text, $pos, 1 ) ) {
				return null;   // a level the bytes opened is closed by "}"
			} else {
				// A level with no members opens no frame, so its own "}" has
				// to be consumed HERE or the level above reads it as a member
				// key.  This is the whole of the pre-fix defect on a real
				// value: ``sizes`` is ``a:0:{}`` on every attachment whose
				// extra sizes were never generated, ``image_meta`` follows
				// it, and the reader gave up on the value from there — so no
				// proof was performed on the very rows the op rewrites most.
				$pos++;
			}
		}
	}
	// Every frame is closed by the only exit above, so the stack is empty
	// here: a shape that was not read to its end is never reported.
	return $out;
}

/**
 * The WORK the actual-value shape walker may spend, and how many ENCLOSING
 * arrays one level is compared against to recognize its own. Structural
 * bounds, not operator tunables (exactly like WPT_MEDIA_REF_EXT_MAX): this
 * file is DEPLOYED on a host that cannot read the operator's profile, and a
 * proof that can be talked into spending the host's memory is not a proof.
 *
 * The work is a count of LEVELS OPENED — one unit per array the walk
 * visits — and it replaces the DEPTH CAP this used to carry, because a
 * depth cap does not bound the walk: it bounds it at PHP's own nesting
 * limit, and the walk's cost is not linear in the depth.  Every level's
 * path is a string that grows with the depth, and the shape this returns
 * is one entry per level, so a chain d levels deep costs Theta(d^2) in
 * both time and memory.  Measured on PHP 8.4 through the real op with one
 * 40 KB row value: 300 levels 0.05 s, 1 000 levels 0.71 s, 2 000 levels
 * 2.88 s, and past that the op outran the client's own timeout on a
 * single row — a stored cell (which needs no privilege beyond a row write
 * to plant) turning every run of the rewrite into a hang.  The cap made
 * that a bound of 4096 levels, which is 24 MB and 4.6 s of transient
 * string per walk, and the proof runs three of them per serialized row.
 *
 * A ceiling on LEVELS bounds the whole cost with it: the deepest walk is
 * this many levels and the whole shape is then at most this-squared path
 * characters — measured at the ceiling, about a megabyte of path strings
 * and 0.2 s per walk, and the proof makes three walks per serialized row
 * (the actual value, and the value PHP's own round trip reads back), so
 * the worst case is bounded and small whatever the value is.  1024 is
 * five times the deepest structure any WordPress row holds (the pinned
 * healthy fixture is 200 levels; an ``_wp_attachment_metadata`` is about
 * four), and a quarter of PHP's own 4096, so it refuses values no real row
 * carries and it is never the reason a real rewrite is refused.  A value
 * that exceeds it is REFUSED, with this number in the message, by the walk
 * throwing — the op's own ``catch ( Throwable )`` turns that into one
 * structured answer naming the reason, which is the fail-closed
 * direction: the row is not written, and the caller is told why instead of
 * being handed a shape cut off mid-walk.
 *
 * The scan window is how far back a self-reference is looked for. A cycle
 * LENGTH is caught as soon as the walk descends one level past the array it
 * loops to, so a window of 64 catches every cycle a real payload can express
 * (a back-reference names a value PHP stored earlier in the same stream, and
 * 64 levels of nesting is already far past anything a WordPress row holds);
 * a longer one is not caught by the window, and the work budget is what ends
 * that walk — the same refusal, one bound lower.
 */
define( 'WPT_MEDIA_SHAPE_WORK_BUDGET', 1024 );
define( 'WPT_MEDIA_SHAPE_CYCLE_SCAN', 64 );

/**
 * The same shape, read off the PHP array that is about to be stored
 * (wpt_media_rewrite_array_shape's declared twin). Iterative for the same
 * reason, and over the REWRITTEN structure: the proof is about the bytes
 * that will land in the row, not about the value that came out of the
 * database.
 *
 * THE WALK IS BOUNDED, because the value it walks can be CYCLIC.  A PHP
 * array holds no identity of its own — the same array reached through a
 * back-reference (``a:2:{s:1:"k";R:1;...}``, which PHP materializes as
 * ``$d['k'] === $d``) is re-entered by this loop at a FRESH path every
 * time, and the unbounded version of it therefore never ended: it pushed
 * the same value at "0.", "0.0.", "0.0.0." ... until the process ran out
 * of memory.  That is the one failure the op's own ``catch ( Throwable )``
 * cannot see, so the op answered nothing at all: every row before it in
 * the batch was already written and the client read a truncated stream.
 *
 * Two bounds, and the second is what actually terminates a cycle:
 *
 *  - the ancestors open at each depth are kept as the walk descends, and a
 *    child that is ``===`` to one of them is NOT descended into.  PHP's
 *    ``===`` on arrays is a VALUE comparison, so this is exact rather than
 *    heuristic: for a finite array no member can be value-equal to one of
 *    its own ancestors without being that ancestor (two SIBLINGS that
 *    happen to be equal are not ancestors, and are both walked), and the
 *    ``count()`` pre-test keeps the comparison off the hot path of a walk
 *    over a large option array.  A cycle the window does not reach, and a
 *    comparison PHP's own nesting limit refuses, both stop the descent.
 *  - the WORK BUDGET (WPT_MEDIA_SHAPE_WORK_BUDGET), which no walk may spend
 *    past, whatever shape the value has.  A cyclic value never reaches it
 *    in practice, and that is worth writing down because it was MEASURED
 *    rather than assumed: PHP's own ``===`` on a recursive pair RAISES
 *    ("Nesting level too deep - recursive dependency?"), so the FIRST
 *    comparison of a level whose member loops back refuses the descent and
 *    the catch below turns it into the same verdict.  Every cycle length
 *    from 1 to 200 therefore stops within one level.  The value that spent
 *    the host's memory was not a cyclic one — it was a DEEP one, where the
 *    guard has nothing to complain about, every comparison walks the whole
 *    sub-chain to its bottom, and the walk runs to the old depth cap at a
 *    cost quadratic in the depth (see the budget's own note).  The budget
 *    is the bound that holds for the shapes the cycle guard cannot see.
 *
 * THE WALK IS O(1) PER LEVEL, and the path is built AFTER it.  A node is
 * held as ``(parent, slot)`` — two integers — while the walk runs, so a
 * level costs what the level itself costs (its members' key shapes and its
 * cycle test) and nothing that grows with its depth.  The strings are
 * materialized in one pass over the node table once the walk is over,
 * each from its own parent chain, and the total is the SIZE OF THE ANSWER
 * — which is what the work budget bounds.  The previous version built
 * ``$path . $slot . '.'`` inside the member loop, so a chain d deep
 * allocated d strings totalling Theta(d^2) bytes and copied them again at
 * every level: a walk whose cost grew with the square of its input, on a
 * value read out of a database cell.
 *
 * A level the walk does not descend into is still RECORDED, with its own
 * keys: the array PHP reads back holds a level at that path which the
 * stored bytes declare no level for — a back-reference is one member where
 * the value re-stored would be a whole subtree — and the comparison
 * (wpt_media_rewrite_shape_loss) reports that as a disagreement, so a
 * cyclic value is REFUSED with a key to go and look at.  The failure
 * direction is the one the proof exists for: never a silent write of a
 * value whose structure cannot be proven, and never a hang.
 *
 * ``$complete`` (an out parameter) is the ONE thing this walk cannot decide
 * on its own: it is set to false when a level holds an OBJECT, whose
 * properties are not array levels and are therefore never read, let alone
 * compared.  A key multiset that ignores them is a real answer to a
 * question nobody asked, so a value that holds an object anywhere is NOT
 * reported as proven — the caller turns this into "no proof", which is what
 * this op has always done with an object payload (SPEC R28).  It is
 * deliberately not a refusal: the rewrite leaves an object untouched by
 * contract, so refusing every row a plugin serialized an object into would
 * be a false refusal on real site data, and the loss it cannot see was
 * already lost before wpt read the row.
 *
 * A value that cannot be read within the budget THROWS, and the message
 * names the budget.  A throw is the right channel and not a return value:
 * a "shape read up to here" would be indistinguishable from a whole one at
 * every caller, and the only two answers a caller could give it — a
 * refusal that names nothing, or a proof of a value nobody read — are the
 * two lies this function exists to prevent.  The op catches it like any
 * other Throwable and answers one structured line carrying the reason, so
 * the client reads an answer rather than a truncated stream.
 */
/**
 * True when a decoded value contains a PHP reference (a serialized ``R:`` or
 * ``r:`` anywhere in its tree).
 *
 * PHP 8.3 raises an uncatchable "Nesting level too deep - recursive
 * dependency?" from array identity comparison on a recursive pair; 8.4
 * surfaces it as a Throwable.  The shape walk cannot rely on the version:
 * a child that contains a reference is conservatively NOT descended into,
 * which is the same refusal as the ancestor comparison and works on both
 * builds.  A reference to a non-ancestor is also not descended into; the
 * proof is fail-closed, never a claim about a structure it did not read.
 */
function wpt_media_rewrite_has_reference( $value ) {
	try {
		$encoded = serialize( $value );
	} catch ( Throwable $e ) {
		return true;
	}
	return 1 === preg_match( '/(?:^|[;{}])(?:R|r):[0-9]+;/', $encoded );
}

function wpt_media_rewrite_array_shape( $data, &$complete = true ) {
	// $nodes[ id ] = array( parent id or null, slot, recorded keys or null )
	// — the shape under construction, without a single path string in it.
	$nodes = array();
	$order = array();   // the ids in the order their path enters the answer
	$stack = array( array( 0, $data, 0 ) );
	$nodes[0] = array( null, '', array() );
	// $chain[ depth ] is the array open at that depth, so a node's whole
	// ancestry is $chain[ 0 ] .. $chain[ $depth ].  The stack is
	// depth-first, so a node is only ever reached with its ancestors'
	// entries in place.
	$chain = array();
	$work  = WPT_MEDIA_SHAPE_WORK_BUDGET;
	$next  = 1;
	while ( $stack ) {
		if ( 0 === $work ) {
			throw new RuntimeException(
				'refused: this value is nested too deeply to prove — the shape'
				. ' walk spent its work budget of '
				. WPT_MEDIA_SHAPE_WORK_BUDGET . ' levels on it, and a proof that'
				. ' can be talked into spending the host memory and clock is not'
				. ' a proof; the row is left exactly as it is'
			);
		}
		$work--;
		list( $id, $value, $depth ) = array_pop( $stack );
		if ( ! is_array( $value ) ) {
			continue;   // a member that is not an array opens no level
		}
		$chain[ $depth ] = $value;
		$keys = array();
		$slot = 0;
		$from = max( 0, $depth - WPT_MEDIA_SHAPE_CYCLE_SCAN + 1 );
		foreach ( $value as $key => $child ) {
			$keys[] = wpt_media_rewrite_key_shape( $key );
			// The slot counts EVERY member, not only the arrays: a path
			// names a member POSITION, so a scalar and an object between two
			// levels must shift the levels below it by the same amount.
			$here = $slot . '.';
			$slot++;
			if ( is_object( $child ) ) {
				$complete = false;   // its properties are not levels we read
			}
			if ( ! is_array( $child ) ) {
				continue;
			}
			$open = true;
			$size = count( $child );
			if ( wpt_media_rewrite_has_reference( $child ) ) {
				// Never ask PHP to compare recursive arrays: 8.3 raises
				// an uncatchable fatal from that comparison.  A reference
				// anywhere below this child is a cycle candidate, so the
				// fail-closed answer is the same as an ancestor match.
				$open = false;
			}
			for ( $at = $depth; $open && $at >= $from; $at-- ) {
				if ( count( $chain[ $at ] ) !== $size ) {
					continue;
				}
				try {
					if ( $chain[ $at ] === $child ) {
						$open = false;
						break;
					}
				} catch ( Throwable $e ) {
					// PHP's own array comparison has a nesting limit
					// of its own and RAISES on a deep one.  A proof
					// must not raise: the level is recorded and not
					// walked, which is the same refusal.
					$open = false;
					break;
				}
			}
			$nodes[ $next ] = array( $id, $here, null );
			if ( $open ) {
				$stack[] = array( $next, $child, $depth + 1 );
			} else {
				$nodes[ $next ][2] = array_map( 'wpt_media_rewrite_key_shape', array_keys( $child ) );
				$order[] = $next;
			}
			$next++;
		}
		$nodes[ $id ][2] = $keys;
		$order[] = $id;
	}
	// The paths, in one pass over the node table, AFTER the walk: a node's
	// path is its own parent's path plus one slot, so the total is the size
	// of the answer — and the answer's size is what the work budget bounds.
	// The order the entries are added in is the order the walk recorded
	// them in, which is what the comparison below walks level by level.
	$out = array();
	foreach ( $order as $id ) {
		$slots = array();
		for ( $at = $id; null !== $at; $at = $nodes[ $at ][0] ) {
			$slots[] = $nodes[ $at ][1];
		}
		$out[ implode( '', array_reverse( $slots ) ) ] = $nodes[ $id ][2];
	}
	return $out;
}

/**
 * The SECOND proof, and the only one that is not a hand-written grammar:
 * let PHP ITSELF encode the value again and read it back, then compare the
 * two structures with the same hardened pair the byte side uses.  No
 * serialization grammar is written down here, so none of it can rot: the
 * encoder that decides the question is the encoder PHP will use for the
 * write, on this build.
 *
 * ``array( 'verdict' => …, 'proof' => …, 'level' => …, 'key' => … )``:
 * ``"agrees"`` (the value survives PHP's own round trip with the same
 * members at every level), ``"refused"`` with the level and key of the
 * shallowest disagreement, or ``"no proof"`` when there is nothing to
 * compare — a value that is not an array, or one that holds an object
 * anywhere (``$complete`` false: its properties are not levels this proof
 * reads, exactly as on the byte side).
 *
 * What this catches, and what it cannot.  It catches a value PHP cannot
 * re-encode at all: a self-reference its own ``unserialize()`` produced
 * (``a:1:{s:1:"k";R:1;}``) materializes as a VALUE that holds itself, and
 * ``serialize()`` walks it until the stack is exhausted and raises
 * ``Error: Maximum call stack size … reached. Infinite recursion?``.  That
 * Error is a Throwable, so it is caught here and REFUSED rather than
 * re-raised into the op — a proof must not take the op down, and
 * re-storing such a value is not possible at all.  Note that
 * ``maybe_serialize()`` would raise the same Error at the write, so without
 * this the row's whole batch would be lost to an op-level failure.
 *
 * What it CANNOT catch is the loss PHP makes while READING the row: both
 * sides of this comparison are already post-``unserialize()``, so a payload
 * that declared ``s:3:"foo"`` twice has lost its member before the first
 * one exists, and the two values agree perfectly.  That is
 * wpt_media_rewrite_declared_shape's job, and the two are complementary
 * rather than redundant — which is why the caller runs BOTH and refuses if
 * either refuses.
 */
function wpt_media_rewrite_round_trip( array $value ) {
	try {
		$bytes = serialize( $value );
	} catch ( Throwable $e ) {
		// PHP's own encoder cannot write this value a second time, so the
		// row cannot be re-stored whatever the rewrite decides.  No level
		// and no key: there is no disagreement to point at, the value simply
		// has no second encoding.
		return array(
			'verdict' => 'refused',
			'proof'   => 'round trip',
			'level'   => null,
			'key'     => null,
		);
	}
	$again = @unserialize( $bytes );
	if ( ! is_array( $again ) ) {
		return array(
			'verdict' => 'no proof',
			'proof'   => 'round trip',
			'level'   => null,
			'key'     => null,
		);
	}
	$before = true;
	$after  = true;
	$left   = wpt_media_rewrite_array_shape( $value, $before );
	$right  = wpt_media_rewrite_array_shape( $again, $after );
	if ( ! $before || ! $after ) {
		return array(
			'verdict' => 'no proof',
			'proof'   => 'round trip',
			'level'   => null,
			'key'     => null,
		);
	}
	$loss = wpt_media_rewrite_shape_loss( $left, $right );
	return array(
		'verdict' => ( null === $loss ) ? 'agrees' : 'refused',
		'proof'   => 'round trip',
		'level'   => ( null === $loss ) ? null : $loss[0],
		'key'     => ( null === $loss ) ? null : $loss[1],
	);
}

/**
 * The verdict the rewrite acts on, and the one place the two proofs are
 * composed — so the answer cannot be "both were run and nobody looked".
 * ``$value`` is the array PHP read out of ``$raw`` (the caller already has
 * it for the rewrite; this function does not decode twice).
 *
 * BOTH proofs, and the first refusal wins.  The byte side answers what
 * ``unserialize()`` threw away; PHP's own round trip answers what its
 * ENCODER cannot reproduce.  Running it on the values the byte side CAN
 * describe costs one ``serialize()``, one ``unserialize()`` and one extra
 * walk, and buys a proof that the encoder which is about to write the row
 * can re-read its own output — on every row, not only the exotic ones.
 *
 * The round trip is also what a value the byte side DECLINES would be proved
 * by (``null === $declared``), which on the values a real site holds never
 * happens: a payload the byte reader cannot read is one whose array levels
 * are already covered by the OBJECT rule below, or one ``unserialize()``
 * rejects too.  It is kept as the net under both rather than as a claim
 * about what a real site stores.
 *
 * A value that holds an OBJECT is "no proof" from either side (the object's
 * properties are not levels either proof reads) and is NOT refused: see
 * wpt_media_rewrite_array_shape's ``$complete`` and SPEC R28.
 */
function wpt_media_rewrite_shape_proof( $raw, array $value ) {
	$quiet = array(
		'verdict' => 'no proof',
		'proof'   => '',
		'level'   => null,
		'key'     => null,
	);
	$complete = true;
	$actual   = wpt_media_rewrite_array_shape( $value, $complete );
	if ( ! $complete ) {
		return $quiet;
	}
	$declared = wpt_media_rewrite_declared_shape( $raw );
	if ( null !== $declared ) {
		$loss = wpt_media_rewrite_shape_loss( $declared, $actual );
		if ( null !== $loss ) {
			return array(
				'verdict' => 'refused',
				'proof'   => 'stored form',
				'level'   => $loss[0],
				'key'     => $loss[1],
			);
		}
	}
	$round = wpt_media_rewrite_round_trip( $value );
	if ( 'refused' === $round['verdict'] || null === $declared ) {
		return $round;
	}
	return array(
		'verdict' => 'agrees',
		'proof'   => 'stored form',
		'level'   => null,
		'key'     => null,
	);
}

/**
 * The one ``failed`` label a refused shape proof travels in, carrying which
 * of the two proofs spoke — an operator who is told "a member would be
 * lost" needs to know whether the loss is already IN THE ROW (nothing this
 * run does can recover it; restore the row from a snapshot) or would be
 * introduced by re-storing it.
 */
function wpt_media_rewrite_shape_refusal( array $proof ) {
	if ( null === $proof['level'] ) {
		return 'refused: this value cannot be re-stored at all — PHP cannot encode it'
			. ' for storage a second time (a self-reference its own unserialize()'
			. ' produced), and the row is left exactly as it is';
	}
	$stored = ( 'stored form' === $proof['proof'] );
	$why    = $stored
		? 'its stored form and the array PHP reads back disagree on the key "'
		: 'its own serialize()/unserialize() round trip loses the key "';
	$tail   = $stored ? ' (a PHP array holds each key once)' : '';
	return 'refused: this value cannot be re-stored without losing a member — at level '
		. $proof['level'] . ' ' . $why
		. wpt_media_rewrite_label_key( $proof['key'] ) . '"' . $tail;
}

/**
 * Compare two shapes — the shape the stored bytes DECLARE against the array
 * PHP reads out of them, or the shape of a value against the shape PHP's own
 * ``serialize()``/``unserialize()`` round trip produces. NULL when the two
 * agree; otherwise ``array( level, key )`` — the shallowest level at which
 * they disagree, and the key they disagree on. The level is 1 for the value's
 * own array, 2 for the arrays inside it, so the label points at the nesting
 * an operator has to open.
 *
 * Structure, never bytes. A re-encoding is legitimately not byte-stable
 * (``"0"`` becomes ``i:0;``, an object is re-encoded entirely, a
 * double-wrapped string is not), so comparing the two strings would refuse
 * every healthy value; comparing the two SHAPES refuses exactly the case
 * that loses data and nothing else.
 *
 * Per level it is a MULTISET comparison, not a set one: the collapse this
 * exists for is the same key DECLARED twice, so two occurrences on one side
 * and one on the other is the loss. It runs in one pass per level over
 * key -> occurrence counts, because a level is bounded only by the size of
 * the value and an O(n^2) scan of a large option array is a denial of
 * service the rewrite itself would not have caused.
 *
 * Both directions, so a level only ONE side has is a loss too: reading a
 * value cannot invent a member either, so the two shapes are the same
 * structure or one of them is wrong.
 */
function wpt_media_rewrite_shape_loss( array $declared, array $actual ) {
	$levels = array();
	foreach ( array_keys( $declared ) as $path ) {
		$levels[ substr_count( $path, '.' ) ][] = $path;
	}
	foreach ( array_keys( $actual ) as $path ) {
		if ( ! array_key_exists( $path, $declared ) ) {
			$levels[ substr_count( $path, '.' ) ][] = $path;
		}
	}
	ksort( $levels );
	foreach ( $levels as $depth => $paths ) {
		foreach ( $paths as $path ) {
			$want = array_key_exists( $path, $declared ) ? $declared[ $path ] : array();
			$got  = array_key_exists( $path, $actual ) ? $actual[ $path ] : array();
			$gap  = wpt_media_rewrite_shape_gap( $want, $got );
			if ( null === $gap ) {
				$gap = wpt_media_rewrite_shape_gap( $got, $want );
			}
			if ( null !== $gap ) {
				return array( $depth + 1, $gap );
			}
		}
	}
	return null;
}

/**
 * The first key of $from that $against does not hold as often — the member
 * one side declares and the other lost. NULL when the two hold the same keys
 * the same number of times.
 */
function wpt_media_rewrite_shape_gap( array $from, array $against ) {
	$counts = array();
	foreach ( $against as $key ) {
		$counts[ $key ] = isset( $counts[ $key ] ) ? $counts[ $key ] + 1 : 1;
	}
	foreach ( $from as $key ) {
		if ( isset( $counts[ $key ] ) && $counts[ $key ] > 0 ) {
			$counts[ $key ]--;
			continue;
		}
		return $key;
	}
	return null;
}

/**
 * The extension of an uploads-relative path, lowercase ('' when it has
 * none) — the mirror of wpt/actions/images_webp.py's suffix_of.
 */
function wpt_media_ref_suffix( $path ) {
	$name = basename( (string) $path );
	$dot  = strrpos( $name, '.' );
	return ( false === $dot ) ? '' : strtolower( substr( $name, $dot + 1 ) );
}

/**
 * One text with every reference the mapping holds moved to its twin: the
 * mirror of wpt/actions/images_webp.py's rewrite_text, so a rewrite
 * computed in PHP and one computed in Python cannot disagree about what
 * a reference is.
 *
 * Only the EXTENSION is spliced, so the directory part keeps its original
 * percent-encoding. A token whose raw bytes do not end in the extension
 * its decoded form claims is left ALONE (never mangled — a mangled path
 * is a 404), which is the fail direction: the caller's post-write
 * verification still sees the old reference and refuses the run.
 */
function wpt_media_rewrite_text( $text, array $mapping ) {
	if ( '' === $text || false === strpos( $text, '.' ) ) {
		return $text;
	}
	// RFC 3986 pchar + "/" + "%", matched set-for-set with
	// wpt/actions/images_webp.py's _PATH_TOKEN_RE: the quoting
	// delimiters, whitespace, "?" and "#" are excluded, so a token ends
	// where the surrounding syntax starts and a "?ver=" cache-busting
	// query survives the rewrite untouched.
	$tokens = array();
	preg_match_all(
		'#[A-Za-z0-9._~%!$&\'()*+,;=:@/\\-]+#',
		$text,
		$tokens,
		PREG_OFFSET_CAPTURE
	);
	$out     = '';
	$pos     = 0;
	$changed = false;
	foreach ( $tokens[0] as $token ) {
		$raw   = $token[0];
		$start = $token[1];
		$at    = strpos( $raw, 'wp-content/uploads/' );
		$tail  = ( false === $at ) ? $raw : substr( $raw, $at + strlen( 'wp-content/uploads/' ) );
		$base  = ( false === $at ) ? 0 : $at + strlen( 'wp-content/uploads/' );
		$cut   = strlen( $tail );
		while ( $cut > 0 ) {
			$span_start = $start + $base;
			$span_end   = $span_start + $cut;
			if ( $span_end <= $pos ) {
				break;
			}
			$raw_span = substr( $text, $span_start, $cut );
			$ref      = rawurldecode( $raw_span );
			$new      = isset( $mapping[ $ref ] ) ? $mapping[ $ref ] : null;
			if ( null !== $new ) {
				$old_ext = wpt_media_ref_suffix( $ref );
				$new_ext = wpt_media_ref_suffix( $new );
				if ( '' !== $old_ext && $old_ext !== $new_ext
					&& substr( $raw_span, -strlen( $old_ext ) - 1 ) === '.' . $old_ext ) {
					$out      .= substr( $text, $pos, $span_start - $pos )
						. substr( $raw_span, 0, strlen( $raw_span ) - strlen( $old_ext ) - 1 )
						. '.' . $new_ext;
					$pos       = $span_end;
					$changed   = true;
					break;
				}
			}
			// Retry the same token with one more trailing container
			// character stripped ("photo.jpg," in JSON, "photo.jpg)" in
			// an url()) — the Python scanner offers the same candidates.
			if ( false === strpos( ')]}>;,"' . "'", $tail[ $cut - 1 ] ) ) {
				break;
			}
			$cut--;
		}
	}
	if ( ! $changed ) {
		return $text;
	}
	return $out . substr( $text, $pos );
}

/**
 * Invalidate exactly what core's own update path would have, after a
 * raw SQL write. Without it the object cache (and any PERSISTENT one)
 * keeps serving the pre-rewrite value, so a page rendered after the
 * rewrite still points at the original the caller is about to purge.
 *
 * Every lookup reads from the SAME table the write touched, on the key
 * column the surface spec names; the family is chosen by suffix only to
 * know WHICH cache group the row belongs to. One indexed read each.
 */
function wpt_media_rewrite_invalidate( $table, array $spec, $id ) {
	global $wpdb;
	$name = '`' . wpt_backtick( $table ) . '`';
	$key  = '`' . wpt_backtick( $spec['key'] ) . '`';
	if ( substr( $table, -strlen( 'posts' ) ) === 'posts' ) {
		if ( function_exists( 'clean_post_cache' ) ) {
			clean_post_cache( (int) $id );
		}
		return;
	}
	if ( substr( $table, -strlen( 'options' ) ) === 'options' ) {
		// An autoloaded option is served from the `alloptions` cache, so
		// both keys have to go or the site keeps rendering the old value.
		$row = $wpdb->get_row( $wpdb->prepare(
			"SELECT `option_name`, `autoload` FROM {$name} WHERE {$key} = %d",
			$id
		), ARRAY_A );
		if ( is_array( $row ) && isset( $row['option_name'] ) ) {
			wp_cache_delete( $row['option_name'], 'options' );
			if ( isset( $row['autoload'] ) && 'yes' === $row['autoload'] ) {
				wp_cache_delete( 'alloptions', 'options' );
			}
		}
		return;
	}
	if ( substr( $table, -strlen( 'postmeta' ) ) === 'postmeta' ) {
		$post_id = $wpdb->get_var( $wpdb->prepare(
			"SELECT `post_id` FROM {$name} WHERE {$key} = %d",
			$id
		) );
		if ( $post_id ) {
			wp_cache_delete( (int) $post_id, 'post_meta' );
			if ( function_exists( 'clean_post_cache' ) ) {
				clean_post_cache( (int) $post_id );
			}
		}
		return;
	}
	if ( substr( $table, -strlen( 'termmeta' ) ) === 'termmeta' ) {
		$term_id = $wpdb->get_var( $wpdb->prepare(
			"SELECT `term_id` FROM {$name} WHERE {$key} = %d",
			$id
		) );
		if ( $term_id ) {
			wp_cache_delete( (int) $term_id, 'termmeta' );
		}
	}
}

/**
 * Re-prove, immediately before an unlink, that a validated uploads path
 * still names the very file the validation pass approved.
 *
 * Returns 'ok'     — the path still resolves to the same location INSIDE
 *                    the uploads basedir and is the same device+inode:
 *                    safe to unlink.
 *         'gone'   — the file no longer exists (removed concurrently, or
 *                    by an earlier entry of the same request): the
 *                    pre-validation `skipped_missing` case, tolerated.
 *         'refused'— the path moved (a parent directory inside uploads was
 *                    replaced by a symlink) or the file at it was replaced.
 *                    Never unlinked: the caller reports it and the whole
 *                    apply fails closed.
 *
 * clearstatcache(true) first, deliberately: PHP's realpath/stat caches
 * would otherwise be free to answer from the validation pass, which is
 * exactly the staleness this function exists to disprove.
 */
function wpt_media_delete_recheck( $target, $basedir, $dev, $ino ) {
	clearstatcache( true );
	// The FINAL component must still be the validated directory entry,
	// never a link that replaced it.  is_link() inspects the link itself;
	// realpath() below would follow it and could compare equal only after
	// resolving an attacker path.
	if ( is_link( $target ) ) {
		return 'refused';
	}
	$fresh = realpath( $target );
	if ( false === $fresh ) {
		return 'gone';
	}
	if ( $fresh !== $target
		|| 0 !== strpos( $fresh, $basedir . DIRECTORY_SEPARATOR ) ) {
		return 'refused';
	}
	$now = lstat( $target );
	if ( false === $now || $now['dev'] !== $dev || $now['ino'] !== $ino ) {
		return 'refused';
	}
	return 'ok';
}

/**
 * media_delete: delete posts/postmeta/term_relationships for the given
 * attachment IDs and unlink the given uploads-relative files.
 *
 * Anti-traversal, fail-closed: every file path is validated BEFORE anything
 * is deleted, and any violation refuses the whole request without unlinking
 * a single file. The accepted shape is "inside the uploads basedir":
 *   - NUL bytes stripped, empty / absolute ("/...") paths refused,
 *   - any ".." path SEGMENT refused (lexical, before touching the disk,
 *     on BOTH separator flavours: a Windows-shaped "..\\..\\x" would
 *     otherwise slip past the lexical pass and rely on realpath alone),
 *   - the PARENT must resolve inside the resolved uploads basedir (this is
 *     the symlink-escape layer: a link inside uploads pointing elsewhere
 *     resolves outside and is refused). The containment test compares
 *     against $basedir . DIRECTORY_SEPARATOR, never a bare string prefix,
 *     so a sibling "uploads-evil/" can never be mistaken for uploads.
 *   - the FINAL component is inspected UNRESOLVED and a symbolic link is
 *     refused.  The old code realpath()'d the whole request, so
 *     "files=['2023/10/link.jpg']" where link.jpg -> pic.jpg unlinked the
 *     TARGET and left the link: a planned file replaced by a link after the
 *     plan could delete a media file the keep-gate protected.  A link is
 *     never followed; the link itself is not unlinked either (the caller
 *     reports it and the apply fails closed).
 *
 * There is deliberately NO path-SHAPE restriction (the former "must be
 * under YYYY/" rule): the uploads tree is not only year dirs — plugins
 * (bb-plugin/cache/...), theme asset dirs, pre-3.5 root-level uploads and
 * "current year" flat layouts all live under basedir. That rule was a
 * LAYOUT assumption presented as a safety one, and it failed a real
 * production trim closed: many planned unreferenced uploads
 * were all refused, so EVERY apply deleted nothing. The bridge already
 * resolved the basedir, so "under uploads" is the whole safety claim — and
 * it is exactly the set of paths the media layer can round-trip.
 *
 * Time-of-check to time-of-use (the one accepted limit): PHP has no
 * unlinkat()-style directory-relative unlink, so a validated path cannot be
 * unlinked "through" a directory handle. The window between the
 * validation pass and the unlink() therefore spans the ENTIRE database
 * transaction (START TRANSACTION -> chunked DELETEs -> COMMIT: hundreds of
 * milliseconds to seconds on a real site), and anyone who can write inside
 * uploads — an authenticated uploader, a plugin with a file-write bug — can
 * in that window rename a validated parent directory aside and drop a
 * symlink in its place, turning "unlink /uploads/2023/10/x.jpg" into an
 * unlink of an arbitrary outside file. That was reproduced, not
 * theorised. The window is closed to its irreducible minimum by
 * wpt_media_delete_recheck() above, which re-proves containment AND the
 * file's identity (device + inode) immediately before every unlink; what
 * remains is the microseconds between that re-proof and the unlink syscall
 * itself, which no PHP API can close. See the SPEC residual register.
 */
function wpt_action_media_delete( array $params ) {
	global $wpdb;
	$ids   = wpt_param_int_list( $params, 'ids', false );
	$files = wpt_param_str_list( $params, 'files', false );
	$ud    = wp_upload_dir( null, false );
	if ( empty( $ud['basedir'] ) ) {
		throw new RuntimeException( 'uploads basedir unavailable' );
	}
	$basedir = realpath( (string) $ud['basedir'] );
	if ( false === $basedir ) {
		throw new RuntimeException( 'uploads basedir not on disk' );
	}

	$unlink_targets = array();
	$skipped        = 0;
	foreach ( $files as $rel ) {
		$rel = str_replace( "\0", '', (string) $rel );
		if ( '' === $rel ) {
			throw new InvalidArgumentException( 'refused path (empty)' );
		}
		if ( '/' === $rel[0] || '\\' === $rel[0] ) {
			throw new InvalidArgumentException( 'refused path (absolute): ' . $rel );
		}
		if ( preg_match( '#(?:^|[/\\\\])\.\.(?:[/\\\\]|$)#', $rel ) ) {
			throw new InvalidArgumentException( 'refused path (traversal): ' . $rel );
		}
		// Resolve the PARENT only: the final component is validated as
		// the directory entry it is, never as whatever a link points at.
		$parent = realpath( dirname( $basedir . DIRECTORY_SEPARATOR . $rel ) );
		if ( false === $parent ) {
			$skipped++; // already gone — tolerate
			continue;
		}
		if ( $parent !== $basedir
			&& 0 !== strpos( $parent, $basedir . DIRECTORY_SEPARATOR ) ) {
			throw new InvalidArgumentException( 'refused path (outside uploads): ' . $rel );
		}
		$target = $parent . DIRECTORY_SEPARATOR . basename( $rel );
		if ( is_link( $target ) ) {
			throw new InvalidArgumentException( 'refused path (symlink): ' . $rel );
		}
		// The directory entry's identity at validation time:
		// wpt_media_delete_recheck() compares it again just before the unlink.
		$stat = lstat( $target );
		if ( false === $stat ) {
			$skipped++; // vanished between the parent resolution and the stat
			continue;
		}
		$unlink_targets[ $target ] = array( 'rel' => $rel, 'dev' => $stat['dev'], 'ino' => $stat['ino'] );
	}

	$n_posts = 0;
	$n_meta  = 0;
	$n_rel   = 0;
	if ( $ids ) {
		$wpdb->query( 'START TRANSACTION' );
		try {
			foreach ( array_chunk( $ids, 200 ) as $chunk ) {
				$ph = implode( ', ', array_fill( 0, count( $chunk ), '%d' ) );
				$r  = $wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->posts} WHERE ID IN ( {$ph} )", ...$chunk ) );
				if ( false === $r ) {
					throw new RuntimeException( 'db error: ' . $wpdb->last_error );
				}
				$n_posts += (int) $r;
				$r = $wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->postmeta} WHERE post_id IN ( {$ph} )", ...$chunk ) );
				if ( false === $r ) {
					throw new RuntimeException( 'db error: ' . $wpdb->last_error );
				}
				$n_meta += (int) $r;
				$r = $wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->term_relationships} WHERE object_id IN ( {$ph} )", ...$chunk ) );
				if ( false === $r ) {
					throw new RuntimeException( 'db error: ' . $wpdb->last_error );
				}
				$n_rel += (int) $r;
			}
			$wpdb->query( 'COMMIT' );
		} catch ( Throwable $e ) {
			$wpdb->query( 'ROLLBACK' );
			throw $e;
		}
	}

	$n_files = 0;
	$unlink_failures = array();
	foreach ( $unlink_targets as $target => $entry ) {
		// Re-prove the invariant at the LAST possible moment (see the
		// time-of-check note in this function's docblock): the caller
		// refuses the whole apply on any entry named here, so a refused
		// re-check is loud, never a silent partial deletion.
		$verdict = wpt_media_delete_recheck( $target, $basedir, $entry['dev'], $entry['ino'] );
		if ( 'gone' === $verdict ) {
			$skipped++;
			continue;
		}
		if ( 'refused' === $verdict ) {
			$unlink_failures[] = $entry['rel'];
			continue;
		}
		if ( @unlink( $target ) ) {
			$n_files++;
		} else {
			// Report the uploads-relative path the server could NOT remove
			// so the caller can verify the deletion instead of assuming it.
			$unlink_failures[] = $entry['rel'];
		}
	}
	return array(
		'deleted_posts'     => $n_posts,
		'deleted_meta'      => $n_meta,
		'deleted_termrels'  => $n_rel,
		'deleted_files'     => $n_files,
		'skipped_missing'   => $skipped,
		'unlink_failures'   => array_values( $unlink_failures ),
	);
}

/**
 * db_clean: named ops ONLY — revisions, expired_transients, orphan_meta,
 * optimize_tables. Per-op try/catch: every requested op runs; failures are
 * collected and flip the envelope to ok:false.
 */
function wpt_action_db_clean( array $params ) {
	global $wpdb;
	$ops     = wpt_param_str_list( $params, 'ops' );
	$allowed = array( 'revisions', 'expired_transients', 'orphan_meta', 'optimize_tables' );
	$unknown = array_values( array_diff( $ops, $allowed ) );
	if ( $unknown ) {
		throw new InvalidArgumentException( 'unknown op' );
	}
	$results = array();
	$errors  = array();
	foreach ( array_unique( $ops ) as $op ) {
		try {
			switch ( $op ) {
				case 'revisions':
					$results[ $op ] = wpt_db_delete_count( "DELETE FROM {$wpdb->posts} WHERE post_type = 'revision' OR post_status = 'auto-draft'" );
					break;
				case 'expired_transients':
					$results[ $op ] = wpt_db_delete_count( wpt_expired_transients_sql( 'DELETE t, s' ) );
					break;
				case 'orphan_meta':
					$results[ $op ] =
						wpt_db_delete_count( "DELETE pm FROM {$wpdb->postmeta} pm LEFT JOIN {$wpdb->posts} p ON p.ID = pm.post_id WHERE p.ID IS NULL" ) +
						wpt_db_delete_count( "DELETE tm FROM {$wpdb->termmeta} tm LEFT JOIN {$wpdb->terms} t ON t.term_id = tm.term_id WHERE t.term_id IS NULL" ) +
						wpt_db_delete_count( "DELETE cm FROM {$wpdb->commentmeta} cm LEFT JOIN {$wpdb->comments} c ON c.comment_ID = cm.comment_id WHERE c.comment_ID IS NULL" );
					break;
				case 'optimize_tables':
					$n = 0;
					foreach ( wpt_table_whitelist() as $t ) {
						if ( false !== $wpdb->query( 'OPTIMIZE TABLE `' . wpt_backtick( $t ) . '`' ) ) {
							$n++;
						}
					}
					$results[ $op ] = $n;
					break;
			}
		} catch ( Throwable $e ) {
			$errors[ $op ] = $e->getMessage();
		}
	}
	$payload = array( 'results' => wpt_map( $results ), 'errors' => wpt_map( $errors ) );
	if ( $errors ) {
		$payload['ok']    = false; // overrides the dispatcher's ok:true
		$payload['error'] = 'failed ops: ' . implode( ', ', array_keys( $errors ) );
	}
	return $payload;
}

/**
 * plugin_deactivate: rewrite active_plugins removing dirname matches. Never
 * deletes files. Core-faithful 2-arg update_option() keeps the autoload flag
 * untouched (a third arg of false would set autoload=off on WP 6.6+ — an
 * unwanted per-request query regression; core's deactivate_plugins() also
 * uses the 2-arg form).
 */
function wpt_action_plugin_deactivate( array $params ) {
	$slugs  = wpt_param_str_list( $params, 'slugs' );
	$active = get_option( 'active_plugins' );
	$before = wpt_option_string_list( $active, 'active_plugins' );
	$dirs   = array();
	foreach ( $slugs as $slug ) {
		if ( false !== strpos( $slug, '/' ) ) {
			$slug = dirname( $slug ); // accept "folder/file.php" too
		}
		if ( '' !== $slug ) {
			$dirs[ $slug ] = true;
		}
	}
	$keep    = array();
	$removed = array();
	foreach ( $before as $plugin_file ) {
		$dirname     = dirname( $plugin_file );
		// Dirless single-file plugins ("hello.php") are matched by filename.
		$hit = isset( $dirs[ $dirname ] ) || ( '.' === $dirname && isset( $dirs[ $plugin_file ] ) );
		if ( $hit ) {
			$removed[] = $plugin_file;
		} else {
			$keep[] = $plugin_file;
		}
	}
	$updated = null;
	if ( $removed ) {
		$updated = update_option( 'active_plugins', array_values( $keep ) );
	}
	return array(
		'before'  => count( $before ),
		'after'   => count( $keep ),
		'removed' => $removed,
		'updated' => $updated,
	);
}

/**
 * Classify ONE active_plugins entry exactly as core's own repair does.
 *
 * This is wp-admin's validate_plugin() (wp-admin/includes/plugin.php),
 * criterion for criterion — the function validate_active_plugins() acts on,
 * i.e. the repair this op performs headlessly — and in the same order:
 *
 *   1. an empty entry, or one carrying a NUL byte (core cannot even ask
 *      about a NUL path: file_exists() raises a ValueError on PHP 8, and
 *      this function must answer, not fatal);
 *   2. a path validate_file() rejects ("..", a drive letter, ...);
 *   3. a main file that is not on disk (the same file_exists() test
 *      wp_get_active_and_valid_plugins() runs on every request);
 *   4. a file the plugin-header inventory does not list.
 *
 * Criterion 4 is core's own ('no_plugin_header'), NOT a wpt addition, and
 * it is worth being explicit about what it means: a plugin file that is
 * present and therefore LOADED by the front end, but whose header
 * get_plugins() cannot read (unreadable file, headerless stray .php,
 * truncated transfer), IS deactivated here — precisely as clicking
 * "Deactivate" in wp-admin would deactivate it. That is not a silent
 * wrong action: the action plans every entry by name, the operator
 * confirms, the pre-action snapshot captures the options table, and the
 * apply re-reads the option afterwards.
 *
 * The opposite choice — keeping such an entry because the runtime loads it
 * — would make this op disagree with the very screen it replaces, and
 * would leave the stale entry in place forever, re-imported by the next
 * migration.
 */
function wpt_classify_active_plugin( $plugin_file, array $installed ) {
	if ( '' === $plugin_file || false !== strpos( $plugin_file, "\0" ) ) {
		return 'drop';
	}
	if ( 0 !== validate_file( $plugin_file ) ) {
		return 'drop'; // core: `if ( validate_file( $plugin ) )`
	}
	if ( ! file_exists( WP_PLUGIN_DIR . '/' . $plugin_file ) ) {
		return 'drop'; // core: plugin_not_found
	}
	return isset( $installed[ $plugin_file ] ) ? 'keep' : 'drop'; // core: no_plugin_header
}

/**
 * reconcile_active_plugins: rewrite active_plugins against the plugin set
 * core itself would keep. Each entry is classified by wp-admin's own
 * validate_plugin() criteria (see wpt_classify_active_plugin above), so an
 * entry that fails it is "active but missing" — the state a migrated dump
 * is left in once clean-files removes the plugin directories: WordPress
 * only repairs this lazily, in wp-admin, where wp-admin/plugins.php calls
 * validate_active_plugins(); every other consumer — front-end, REST, cron,
 * and the next dump — keeps seeing the stale list).
 *
 * Params: apply (STRICT boolean, default FALSE — a report-only call is the
 * fail-closed default, so a caller that forgets the flag never rewrites an
 * option). With apply, the missing entries are dropped from the option via
 * the core-faithful 2-argument update_option() (same rule and comment
 * discipline as plugin_deactivate above: the autoload flag is left alone; a
 * third argument of false would set autoload=off on WP 6.6+, and core's own
 * deactivate_plugins() also uses the 2-arg form).
 *
 * Never deactivates what wp-admin's own repair would keep: each entry is
 * classified by validate_plugin()'s criteria (see
 * wpt_classify_active_plugin above), and the comparison is refused outright
 * when the plugin inventory is unavailable (a failed get_plugins() must
 * never look like "nothing is installed" and deactivate the entire site).
 * A non-list option is refused too, where core's own repair would silently
 * overwrite it with an empty list — that repair deactivates EVERY plugin of
 * a site whose option is merely corrupt, which a toolkit must report, not
 * perform.
 *
 * Payload: installed (get_plugins() size), active_before, missing (the
 * active-but-absent entries — the same list in both modes), applied (bool),
 * updated (null when nothing was written, else update_option's bool),
 * removed (the entries actually dropped — empty unless the write happened
 * AND succeeded), active_after (what the option still lists once this call
 * is over: the rewritten list on a successful write, the untouched one
 * otherwise) and active_now (the option re-read AFTER the write, so the
 * caller verifies the persisted state instead of trusting the write).
 */
function wpt_action_reconcile_active_plugins( array $params ) {
	$apply = isset( $params['apply'] ) && true === $params['apply'];
	if ( ! function_exists( 'get_plugins' ) ) {
		throw new RuntimeException( 'plugin inventory unavailable' );
	}
	// The live-plugins probe below is rooted at WP_PLUGIN_DIR. An undefined
	// or empty constant would make every entry resolve against "/" and
	// report the whole site as missing: refuse instead of guessing.
	if ( ! defined( 'WP_PLUGIN_DIR' ) || ! is_string( WP_PLUGIN_DIR ) || '' === WP_PLUGIN_DIR ) {
		throw new RuntimeException( 'plugin directory unavailable' );
	}
	$active = get_option( 'active_plugins' );
	$active = wpt_option_string_list( $active, 'active_plugins' );
	$before    = $active;
	$installed = get_plugins();
	if ( ! is_array( $installed ) ) {
		throw new RuntimeException( 'plugin inventory unavailable' );
	}

	$keep    = array();
	$missing = array();
	foreach ( $before as $plugin_file ) {
		if ( 'keep' === wpt_classify_active_plugin( $plugin_file, $installed ) ) {
			$keep[] = $plugin_file;
		} else {
			$missing[] = $plugin_file;
		}
	}

	$updated = null;
	if ( $apply && $missing ) {
		// Core-faithful 2-arg update_option (autoload untouched).
		$updated = update_option( 'active_plugins', array_values( $keep ) );
	}
	$removed    = ( $apply && $missing && $updated ) ? $missing : array();
	$active_now = get_option( 'active_plugins' );
	// The verification re-read must PROVE the persisted state.  The SAME
	// list owner refuses a non-list or a non-string entry instead of
	// smoothing it into "the option is clean" (or emitting a PHP warning
	// before the JSON).
	$active_now = wpt_option_string_list( $active_now, 'active_plugins' );
	return array(
		'installed'     => count( $installed ),
		'active_before' => count( $before ),
		'missing'       => $missing,
		'applied'       => $apply,
		'updated'       => $updated,
		'removed'       => $removed,
		'active_after'  => ( $updated ) ? count( $keep ) : count( $before ),
		'active_now'    => $active_now,
	);
}

/**
 * users_reset: reset WordPress user passwords to fresh random values, and
 * hand the new values back to the operator ("reset all users with random
 * password and provide them" was the original migration requirement; a
 * targeted subset is the default the command now drives).
 *
 * Params:
 *   - apply (STRICT boolean, default FALSE). Without it the op is
 *     READ-ONLY: it lists who WOULD be reset and never generates a
 *     password, so a dry run cannot leave a secret behind or invalidate a
 *     single session.
 *   - logins (optional list of non-empty strings). Its PRESENCE means
 *     TARGETED: only rows whose user_login matches an entry (compared
 *     case-insensitively — the collation WordPress logins live under) are
 *     processed, and EVERY requested login must match or the whole op
 *     throws, so a typo can never silently reset a subset while the caller
 *     believes it reset the named accounts. ABSENCE means every user.
 *     An empty list is refused (never read as "everyone").
 *
 * With apply, every selected row of {$wpdb->users} gets
 *   - a password from WordPress's OWN generator — wp_generate_password(
 *     20, true, false ): 20 chars, the documented special-character set, no
 *     extra specials, which is the shape wp-admin's own "Generate password"
 *     button produces;
 *   - set with wp_set_password() (core, pluggable.php): hashes it, clears
 *     the user's user_activation_key, calls clean_user_cache() and fires the
 *     `wp_set_password` action.
 *
 * Session invalidation: core's wp_set_password() does NOT destroy session
 * tokens (verified against the WP 6.8 source — it writes the hash, clears
 * the activation key, cleans the cache and fires the action; nothing
 * touches session_tokens). Left alone, the reset would be cosmetic: a
 * session cookie minted before the reset (a migrated dump carries the
 * source site's session_tokens usermeta straight across) would keep
 * authenticating, and the "reset" would not have revoked anything. So the
 * op also calls the per-user core API
 * WP_Session_Tokens::get_instance( $id )->destroy_all() — wp-settings.php
 * always loads that class — and reports per user whether it ran
 * (sessions_destroyed). class_exists() guards it so a stripped-down
 * install degrades to "passwords reset, sessions untouched" rather than
 * fatally.
 *
 * Secrets discipline: the plaintext passwords exist only in this response
 * body. Nothing is logged, nothing is written to a file, and no error
 * message carries one — the client hands them to the CLI presentation
 * layer, which prints them once. Roles are read through get_userdata()
 * (core) BEFORE the rewrite.
 *
 * Payload: results { users: [{login, email, roles, sessions_destroyed,
 * password}], count, skipped: [{id, reason}] }. Untargeted, count is the
 * number of VALID users in the table (an invalid-UTF-8 login is skipped
 * before any write and named by ID in `skipped`), so the caller can prove
 * the op covered everyone it could hand a credential to; targeted, every
 * requested login is proven matched above and count is the number of rows
 * returned.
 */
/**
 * Prove a just-set password is LIVE, in one contained probe.
 *
 * Core's wp_set_password() ignores wpdb->update()'s return, so a read-only
 * database, a lock, or a plugin that no-ops the write returns normally
 * while the old hash stays in place.  The setter returning is therefore
 * not proof: read the stored hash for THIS user and let WordPress's own
 * verifier decide.  Any failure (a throwing read, a missing hash, no
 * wp_check_password) answers false — the caller must never publish a
 * credential it could not prove.
 */
function wpt_user_password_live( $wpdb, $id, $password ) {
	if ( ! is_string( $password ) || '' === $password ) {
		return false;
	}
	if ( ! function_exists( 'wp_check_password' ) ) {
		return false;
	}
	try {
		$live_hash = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT user_pass FROM {$wpdb->users} WHERE ID = %d",
				$id
			)
		);
		if ( ! is_string( $live_hash ) || '' === $live_hash ) {
			return false;
		}
		return (bool) wp_check_password( $password, $live_hash, $id );
	} catch ( Throwable $verify_error ) {
		return false;
	}
}

function wpt_action_users_reset( array $params ) {
	global $wpdb;
	$apply    = isset( $params['apply'] ) && true === $params['apply'];
	$targeted = array_key_exists( 'logins', $params );
	$wanted   = array();
	if ( $targeted ) {
		if ( ! is_array( $params['logins'] ) || empty( $params['logins'] ) ) {
			throw new InvalidArgumentException( 'logins must be a non-empty list of strings' );
		}
		foreach ( $params['logins'] as $one ) {
			if ( ! is_string( $one ) || '' === trim( $one ) ) {
				throw new InvalidArgumentException( 'logins must be a non-empty list of strings' );
			}
			$wanted[ strtolower( $one ) ] = $one;
		}
	}
	if ( $apply && ( ! function_exists( 'wp_generate_password' ) || ! function_exists( 'wp_set_password' ) ) ) {
		throw new RuntimeException( 'user password API unavailable' );
	}

	// Table names come from $wpdb's own properties (never from the request),
	// and the bridge never interpolates a caller-supplied identifier.
	$rows = $wpdb->get_results(
		"SELECT ID, user_login, user_email FROM {$wpdb->users} ORDER BY ID", ARRAY_A
	);
	if ( ! is_array( $rows ) ) {
		// A failed query is UNKNOWN, never "no users": a false empty would
		// read as "nothing to reset" on a site that has users.
		throw new RuntimeException( 'could not read the users table' );
	}

	// A latin-1-migrated row can carry bytes that are not UTF-8 in
	// user_login.  The success envelope would SUBSTITUTE them ("admin?"),
	// publishing a login that does not exist while the row's old password
	// was revoked — an operator lockout with a false success.  Validate
	// BEFORE the first write: an invalid login is SKIPPED (never reset,
	// never returned as a credential) and named by ID only in `skipped`.
	$skipped = array();
	$valid_rows = array();
	foreach ( $rows as $row ) {
		$raw_login = isset( $row['user_login'] ) ? (string) $row['user_login'] : '';
		if ( ! preg_match( '//u', $raw_login ) ) {
			$skipped[] = array(
				'id'     => isset( $row['ID'] ) ? (int) $row['ID'] : 0,
				'reason' => 'user_login is not valid UTF-8',
			);
			continue;
		}
		$valid_rows[] = $row;
	}
	$rows = $valid_rows;

	// The coverage proof runs BEFORE the first write: an unknown login must
	// refuse the whole op with nothing reset, never reset the known
	// accounts and then report the typo (the operator would have revoked
	// credentials for accounts the refused run claimed not to touch).
	if ( $targeted ) {
		$present = array();
		foreach ( $rows as $row ) {
			if ( isset( $row['user_login'] ) ) {
				$present[ strtolower( (string) $row['user_login'] ) ] = true;
			}
		}
		$missing = array();
		foreach ( $wanted as $low => $original ) {
			if ( ! isset( $present[ $low ] ) ) {
				$missing[] = $original;
			}
		}
		if ( ! empty( $missing ) ) {
			throw new InvalidArgumentException( 'no such user: ' . implode( ', ', $missing ) );
		}
	}

	$users = array();
	$failures = array();
	foreach ( $rows as $row ) {
		$id = isset( $row['ID'] ) ? (int) $row['ID'] : 0;
		if ( $id < 1 ) {
			continue;
		}
		$login = isset( $row['user_login'] ) ? (string) $row['user_login'] : '';
		$email = isset( $row['user_email'] ) ? (string) $row['user_email'] : '';
		if ( $targeted && ! isset( $wanted[ strtolower( $login ) ] ) ) {
			continue;
		}

		$entry    = array(
			'login'  => $login,
			'email'  => $email,
			'roles'  => array(),
		);
		$password     = null;
		$password_set = false;
		// PER-USER containment (C12/R11): the WHOLE body is inside the
		// try, not only wp_set_password.  get_userdata(), the password
		// generator and the session-token manager can all throw too; a
		// throw after user 1 used to reach the global envelope with NO
		// rows, losing every live password already reset.  A row is
		// recorded the moment wp_set_password returns; a later per-user
		// failure marks the run failed but still returns every COMPLETE
		// row.
		try {
			if ( function_exists( 'get_userdata' ) ) {
				$user = get_userdata( $id );
				if ( is_object( $user ) && isset( $user->roles ) && is_array( $user->roles ) ) {
					// Roles are NAMES, and core builds that property two ways:
					// WP_User::init() leaves a plain list of names, while
					// WP_User::set_role() leaves a name => true map. Read the
					// name out of whichever shape arrived (a plain string cast
					// would answer "1" for every role of a mapped user).
					foreach ( $user->roles as $role_key => $role_value ) {
						$entry['roles'][] = is_string( $role_key ) ? $role_key : (string) $role_value;
					}
				}
			}

			if ( $apply ) {
				$password = wp_generate_password( 20, true, false );
				wp_set_password( $password, $id );
				// Core's setter ignores the database write's return: prove
				// the generated credential really is the live hash before
				// publishing it (a silent no-op must fail the row, never
				// hand the operator a dead password).
				if ( ! wpt_user_password_live( $wpdb, $id, $password ) ) {
					throw new RuntimeException(
						'the password setter did not store a verifiable hash'
					);
				}
				$password_set                = true;
				$entry['password']           = (string) $password;
				$entry['sessions_destroyed'] = false;
				if ( class_exists( 'WP_Session_Tokens' ) ) {
					$manager = WP_Session_Tokens::get_instance( $id );
					if ( is_object( $manager ) && method_exists( $manager, 'destroy_all' ) ) {
						$manager->destroy_all();
						$entry['sessions_destroyed'] = true;
					}
				}
			}
		} catch ( Throwable $e ) {
			// A setter can throw AFTER core's wp_set_password() wrote the
			// new hash (its do_action runs after the $wpdb->update).  The
			// old password is already revoked; withholding the new one
			// would lock the account out with no answer.  Re-read the live
			// hash in a CONTAINED probe and publish the credential only
			// when wp_check_password proves it is the one we generated.
			if ( ! $password_set && is_string( $password ) && '' !== $password ) {
				// The setter can throw after core wrote the hash (its
				// do_action runs after $wpdb->update), or return normally
				// without writing it.  The SAME contained probe decides:
				// publish the credential only when wp_check_password
				// proves the generated plaintext is the stored hash.
				$password_set = wpt_user_password_live( $wpdb, $id, $password );
			}
			if ( $password_set ) {
				$entry['password']           = (string) $password;
				$entry['sessions_destroyed'] = false;
			}
			$failed_login = '' !== $login ? $login : ( '#' . $id );
			// A hook receives the just-generated plaintext (core fires
			// do_action('wp_set_password', $password, ...)) and can embed it
			// in its exception text, raw or encoded.  The password exists
			// only here, so scrub at the owner on EVERY failure path before
			// the text reaches the envelope/log/report.
			$failures[ $failed_login ] = (
				$password_set
					? 'password was reset but a later step failed: '
					: 'password reset failed: '
			) . wpt_scrub_secret( $e->getMessage(), $password );
			// The password IS live only once the setter returned (or the
			// contained re-read proved it landed).  Keep the row then, so
			// the caller can publish it before failing.
			if ( $password_set ) {
				$users[] = $entry;
			}
			continue;
		}

		$users[] = $entry;
	}

	if ( ! empty( $failures ) ) {
		// ok:false carries the partial rows, so the client can publish every
		// password that IS live before failing closed.  The global Throwable
		// envelope cannot carry handler results.
		$results = array( 'users' => $users, 'count' => count( $users ) );
		if ( ! empty( $skipped ) ) {
			$results['skipped'] = $skipped;
		}
		return array(
			'ok'      => false,
			'error'   => 'users_reset failed for '
				. implode( ', ', array_keys( $failures ) ),
			'results' => $results,
			'failed'  => array_keys( $failures ),
			// Per-login SCRUBBED reasons: the message is the operator's
			// only diagnosis for a failed account, and this map has passed
			// the same fail-closed wpt_scrub_secret owner as every other
			// error path.  It is emitted here, so the scrubbing is not a
			// dead assignment.
			'failed_reasons' => $failures,
		);
	}

	$results = array( 'users' => $users, 'count' => count( $users ) );
	if ( ! empty( $skipped ) ) {
		$results['skipped'] = $skipped;
	}
	return array( 'results' => $results );
}

/**
 * user_create: create ONE WordPress user with WordPress's own insertion
 * API, and hand the generated password back to the operator.
 *
 * Params:
 *   - apply (STRICT boolean, default FALSE). Without it the op only
 *     VALIDATES — no password is generated, no row is written: the login
 *     after sanitize_user( strict ), its length (≤60, core's bound), the
 *     site's illegal_user_logins filter, the email and the role are
 *     checked against the live site and the account that WOULD be created
 *     is returned (with the sanitized login), so a dry run can neither
 *     print a secret nor mutate anything.
 *   - login, email, role (non-empty strings; role must be an EXISTING
 *     role — the op never writes a capability key for a role the site does
 *     not define).  email must satisfy is_email(); a login that sanitizes
 *     to empty, is too long, is blocked by the site, an existing login, an
 *     existing email and an unknown role each throw, so every refusal the
 *     site can give is a structured ok:false answer instead of a
 *     half-created row.
 *
 * With apply the op generates the password with WordPress's own
 * wp_generate_password( 20, true, false ), inserts through wp_insert_user()
 * — which hashes the password, enforces the duplicate checks AGAIN (the
 * plan/apply race), sets the role and fires user_register — then READS THE
 * ACCOUNT BACK with get_userdata() and answers the read-back.  The
 * verification is structural: an answer exists only for an account
 * WordPress really persisted, and the caller compares its planned login
 * against this read-back.
 *
 * No notification email is sent: the generated credential reaches the
 * operator once (the response body) and exists nowhere else — nothing is
 * logged, nothing is written to a file, and no error message carries it.
 *
 * Payload: results { user: {login, email, roles, password}, apply }.
 */
function wpt_action_user_create( array $params ) {
	$apply = isset( $params['apply'] ) && true === $params['apply'];

	$login = ( isset( $params['login'] ) && is_string( $params['login'] ) )
		? trim( $params['login'] ) : '';
	if ( '' === $login ) {
		throw new InvalidArgumentException( 'missing or non-string param: login' );
	}
	$email = ( isset( $params['email'] ) && is_string( $params['email'] ) )
		? trim( $params['email'] ) : '';
	if ( '' === $email ) {
		throw new InvalidArgumentException( 'missing or non-string param: email' );
	}
	if ( ! is_email( $email ) ) {
		throw new InvalidArgumentException( 'not a valid email address: ' . $email );
	}
	$role = ( isset( $params['role'] ) && is_string( $params['role'] ) )
		? $params['role'] : '';
	if ( '' === $role ) {
		throw new InvalidArgumentException( 'missing or non-string param: role' );
	}
	if ( ! function_exists( 'get_role' ) || null === get_role( $role ) ) {
		throw new InvalidArgumentException( 'unknown role: ' . $role );
	}
	if ( $apply && ( ! function_exists( 'wp_insert_user' ) || ! function_exists( 'wp_generate_password' ) ) ) {
		throw new RuntimeException( 'user creation API unavailable' );
	}

	// The login WordPress would actually create: sanitize_user( strict )
	// is the sanitization wp_insert_user() applies, so validating the RAW
	// request would accept a login the insert then rejects (or create a
	// different one than the caller planned).
	$sanitized = trim( (string) sanitize_user( $login, true ) );
	if ( '' === $sanitized ) {
		throw new InvalidArgumentException( 'login is empty after WordPress sanitization: ' . $login );
	}
	// The same two refusals wp_insert_user() applies beyond the duplicate
	// checks (mirrored from core's user.php): a login longer than 60
	// characters, and one the site's illegal_user_logins filter blocks.
	// Without them a read-only plan could pass and the apply then fail
	// AFTER generating a password.
	$login_length = function_exists( 'mb_strlen' ) ? mb_strlen( $sanitized ) : strlen( $sanitized );
	if ( $login_length > 60 ) {
		throw new InvalidArgumentException( 'login may not be longer than 60 characters: ' . $sanitized );
	}
	$illegal_logins = (array) apply_filters( 'illegal_user_logins', array() );
	if ( in_array( strtolower( $sanitized ), array_map( 'strtolower', $illegal_logins ), true ) ) {
		throw new InvalidArgumentException( 'this login is not allowed on this site: ' . $sanitized );
	}
	if ( username_exists( $sanitized ) ) {
		throw new InvalidArgumentException( 'a user with that login already exists: ' . $sanitized );
	}
	if ( email_exists( $email ) ) {
		throw new InvalidArgumentException( 'a user with that email already exists: ' . $email );
	}

	if ( ! $apply ) {
		return array(
			'results' => array(
				'user'  => array(
					'login' => (string) $sanitized,
					'email' => $email,
					'roles' => array( $role ),
				),
				'apply' => false,
			),
		);
	}

	$password    = wp_generate_password( 20, true, false );
	$write_error = null;
	// Capture the row's id BEFORE any user_register hook can throw.  Core
	// applies pre_user_login/pre_user_email and then fires user_register
	// from INSIDE wp_insert_user, AFTER the row exists; when a later hook
	// throws, wp_insert_user never returns the id and the generated
	// password (already live) would be lost.  The EARLIEST priority is
	// the one callback that runs before every other user_register hook.
	// Sanitized login/email are NOT recovery keys: both may be rewritten
	// by pre_* filters, so the id is the only stable identity.
	$created_id = 0;
	if ( function_exists( 'add_action' ) ) {
		add_action(
			'user_register',
			static function ( $user_id ) use ( &$created_id ) {
				$created_id = (int) $user_id;
			},
			-1000000,
			1
		);
	}
	try {
		$user_id = wp_insert_user(
			array(
				'user_login' => $sanitized,
				'user_email' => $email,
				'user_pass'  => $password,
				'role'       => $role,
			)
		);
	} catch ( Throwable $e ) {
		// A user_register hook (or another plugin) can throw AFTER core has
		// written the row: the account and password are live, but the id
		// never came back.  The earliest user_register callback captured
		// that id before any later hook ran, so the credential is not lost
		// to the global envelope (C12).  The old recovery searched the
		// request's sanitized login/email AFTER wp_insert_user, but core
		// applies pre_user_login/pre_user_email FIRST: a plugin that
		// rewrites either field made the written account unfindable.  A
		// fallback lookup remains for a WordPress double without
		// add_action; its reads are contained too (R11-P1-2).
		$recovered = (int) $created_id;
		$recovery_error = null;
		try {
			// The login/email lookup is a last resort for a WordPress double
			// WITHOUT add_action (where no user_register capture is
			// possible).  When add_action exists, a captured id of 0 means
			// the insert did not reach user_register: an account that merely
			// already exists must never be reported as this run's creation.
			if ( $recovered < 1 && ! function_exists( 'add_action' )
				&& function_exists( 'username_exists' ) ) {
				$recovered = (int) username_exists( $sanitized );
				// A pre-existing row is not proof this run created it: accept
				// the fallback only when the generated password is LIVE on
				// that row.  Otherwise the operator would receive a password
				// that was never set.
				if ( $recovered > 0 ) {
					global $wpdb;
					if ( ! is_object( $wpdb )
						|| ! function_exists( 'wpt_user_password_live' )
						|| ! wpt_user_password_live( $wpdb, $recovered, $password ) ) {
						$recovered = 0;
					}
				}
			}
			if ( $recovered > 0 && function_exists( 'get_userdata' ) ) {
				$candidate = get_userdata( $recovered );
				if ( ! is_object( $candidate ) ) {
					// The id came from user_register (or a password-proven
					// fallback): the row and the generated password are
					// live, only the read-back cannot see them.  Keep that
					// fact so the failure branch below returns the
					// credential with ok:false instead of rethrowing into
					// the global envelope, which cannot carry a password.
					if ( null === $recovery_error ) {
						$recovery_error = 'the created user could not be read back';
					}
					$recovered = 0;
				} elseif ( $created_id < 1
					&& ( ! isset( $candidate->user_email )
						|| (string) $candidate->user_email !== (string) $email ) ) {
					// Only the unverified fallback lookup needs the email
					// proof; a captured user_register id is the row core
					// just wrote, even when filters changed its email.
					$recovered = 0;
				}
			}
		} catch ( Throwable $read_error ) {
			$recovery_error = $read_error->getMessage();
			$recovered      = 0;
		}
		if ( $recovered < 1 ) {
			if ( null === $recovery_error ) {
				// The global envelope carries only the message, so the one
				// value only THIS frame knows must be scrubbed before any
				// rethrow (a user_register hook can quote the plaintext).
				throw new RuntimeException(
					wpt_scrub_secret( $e->getMessage(), $password )
				);
			}
			// The insert threw after its write and the recovery read also
			// threw: the password may be live, so return it with ok:false
			// rather than letting the global envelope lose it.
			return array(
				'ok'      => false,
				'error'   => 'user_create may have created the account but '
					. 'the recovery read failed: '
					. wpt_scrub_secret( $e->getMessage(), $password )
					. ' (' . wpt_scrub_secret( $recovery_error, $password ) . ')',
				'results' => array(
					'user'  => array(
						'login'    => (string) $sanitized,
						'email'    => $email,
						'roles'    => array( $role ),
						'password' => (string) $password,
					),
					'apply' => true,
				),
				'created' => true,
			);
		}
		$user_id     = $recovered;
		$write_error = 'wp_insert_user reported a failure after writing the account: '
			. wpt_scrub_secret( $e->getMessage(), $password );
	}
	if ( null === $write_error ) {
		if ( is_wp_error( $user_id ) ) {
			throw new RuntimeException(
				'wp_insert_user failed: '
				. wpt_scrub_secret( $user_id->get_error_message(), $password )
			);
		}
		$user_id = (int) $user_id;
		if ( $user_id < 1 ) {
			throw new RuntimeException( 'wp_insert_user returned no user id' );
		}
	}

	$user = null;
	$roles = array();
	$readback_error = null;
	try {
		$user = get_userdata( $user_id );
	} catch ( Throwable $e ) {
		// The insert SUCCEEDED and the password is live; a throwing read-back
		// (a plugin hook, a broken user cache) must not reach the global
		// Throwable envelope, which cannot carry the credential (C12).
		$readback_error = 'the created user could not be read back';
	}
	if ( ! is_object( $user ) ) {
		$readback_error = 'the created user could not be read back';
	} else {
		if ( isset( $user->roles ) && is_array( $user->roles ) ) {
			// The same normalization users_reset applies: WP_User::init()
			// leaves a plain list of names, WP_User::set_role() a name => true
			// map (wp_insert_user calls set_role), and the wire carries names.
			foreach ( $user->roles as $role_key => $role_value ) {
				$roles[] = is_string( $role_key ) ? $role_key : (string) $role_value;
			}
		}
	}

	// The account's WRITTEN identity may differ from the request's after
	// pre_user_login/pre_user_email; report the read-back row when it was
	// readable, and fall back to the request only when it was not.
	$result_login = ( is_object( $user ) && isset( $user->user_login ) )
		? (string) $user->user_login : (string) $sanitized;
	$result_email = ( is_object( $user ) && isset( $user->user_email ) )
		? (string) $user->user_email : $email;

	if ( null !== $write_error ) {
		// The insert wrote the account before the Throwable: return the live
		// credential with ok:false (the global envelope cannot carry it).
		return array(
			'ok'      => false,
			'error'   => 'user_create created the account but ' . $write_error,
			'results' => array(
				'user' => array(
					'login'    => $result_login,
					'email'    => $result_email,
					'roles'    => $roles,
					'password' => (string) $password,
				),
				'apply' => true,
			),
			'created' => true,
		);
	}

	if ( null !== $readback_error ) {
		// The account and its password ARE live: return them with ok:false
		// (the global Throwable envelope would lose the credential).  C12.
		return array(
			'ok'      => false,
			'error'   => 'user_create created the account but ' . $readback_error,
			'results' => array(
				'user' => array(
					'login'    => (string) $sanitized,
					'email'    => $email,
					'roles'    => array(),
					'password' => (string) $password,
				),
				'apply' => true,
			),
			'created' => true,
		);
	}

	return array(
		'results' => array(
			'user'  => array(
				'login'    => (string) $user->user_login,
				'email'    => (string) $user->user_email,
				'roles'    => $roles,
				'password' => (string) $password,
			),
			'apply' => true,
		),
	);
}

/**
 * db_dump (streaming; returns null so the dispatcher emits nothing extra).
 * Per table, NDJSON lines, in order:
 *   {"table":<name>,"create":<SHOW CREATE TABLE output>}
 *   {"table":<name>,"row":[<cell>,...]}   (batched by PK offset; PK-less
 *                                         tables fall back to one unbatched
 *                                         SELECT; flush() every batch)
 *   {"table":<name>,"done":<int row count>}
 * Table names are whitelisted against information_schema — no arbitrary
 * identifiers. Cells are JSON values; invalid-UTF-8 binaries are emitted as
 * ["__wpt_b64__", "<base64>"].
 */
function wpt_action_db_dump( array $params ) {
	$tables    = wpt_param_str_list( $params, 'tables' );
	$chunk     = isset( $params['chunk_rows'] ) ? (int) $params['chunk_rows'] : 100;
	if ( $chunk < 1 ) {
		$chunk = 1;
	}
	if ( $chunk > 10000 ) {
		$chunk = 10000;
	}
	$whitelist = wpt_table_whitelist();
	foreach ( $tables as $t ) {
		if ( ! in_array( $t, $whitelist, true ) ) {
			throw new InvalidArgumentException( 'table not allowed: ' . $t );
		}
	}
	if ( ! headers_sent() ) {
		header( 'Content-Type: application/x-ndjson' );
	}
	foreach ( $tables as $t ) {
		wpt_dump_table( $t, $chunk );
	}
	return null;
}

function wpt_dump_table( $table, $chunk ) {
	global $wpdb;
	$name = wpt_backtick( $table );
	$cr   = $wpdb->get_row( "SHOW CREATE TABLE `{$name}`", ARRAY_N );
	if ( ! is_array( $cr ) || ! isset( $cr[1] ) || ! is_string( $cr[1] ) ) {
		throw new RuntimeException( 'SHOW CREATE failed for ' . $table );
	}
	wpt_ndjson_out( array( 'table' => $table, 'create' => wpt_json_safe_cell( $cr[1] ) ) );

	$total = 0;
	$pks   = $wpdb->get_col( $wpdb->prepare(
		"SELECT COLUMN_NAME FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s AND CONSTRAINT_NAME = 'PRIMARY' ORDER BY ORDINAL_POSITION",
		$table
	) );
	if ( is_array( $pks ) && $pks ) {
		$order  = '`' . implode( '`, `', array_map( 'wpt_backtick', $pks ) ) . '`';
		$offset = 0;
		while ( true ) {
			$rows = $wpdb->get_results( "SELECT * FROM `{$name}` ORDER BY {$order} LIMIT {$chunk} OFFSET {$offset}", ARRAY_N );
			if ( null === $rows ) {
				throw new RuntimeException( 'dump select failed for ' . $table );
			}
			if ( ! $rows ) {
				break;
			}
			$buf = '';
			foreach ( $rows as $row ) {
				$buf .= wpt_json_line( array( 'table' => $table, 'row' => array_map( 'wpt_json_safe_cell', $row ) ) );
			}
			echo $buf;
			flush();
			$total += count( $rows );
			if ( count( $rows ) < $chunk ) {
				break;
			}
			$offset += $chunk;
		}
	} else {
		// PK-less table: no stable cursor — one unbatched scan.
		$rows = $wpdb->get_results( "SELECT * FROM `{$name}`", ARRAY_N );
		if ( null === $rows ) {
			throw new RuntimeException( 'dump select failed for ' . $table );
		}
		$buf = '';
		foreach ( $rows as $row ) {
			$buf .= wpt_json_line( array( 'table' => $table, 'row' => array_map( 'wpt_json_safe_cell', $row ) ) );
		}
		echo $buf;
		flush();
		$total = count( $rows );
	}
	wpt_ndjson_out( array( 'table' => $table, 'done' => $total ) );
}

/**
 * Bounded, OWNED scratch-table names for the atomic restore swap. The scratch
 * names embed the caller-supplied per-restore hex token (restore_id), so each
 * restore owns its staging/old tables: they cannot collide with a legitimate
 * user table, cannot collide with a concurrent restore, and a retry of THIS
 * restore recreates the same names. MySQL/MariaDB cap identifiers at 64 chars;
 * "__wpt_<id>__s" is 6 + id + 3, so the live name must be <= 64 - (6+id+3).
 * Identifiers are never silently truncated, so fail closed on a long name.
 */
function wpt_restore_table_names( $table, $restore_id ) {
	if ( ! is_string( $restore_id ) || ! preg_match( '/^[0-9a-f]{8,16}$/', $restore_id ) ) {
		throw new InvalidArgumentException( 'invalid restore_id' );
	}
	$suffix = '__wpt_' . $restore_id;
	if ( strlen( $table ) + strlen( $suffix ) + 3 > 64 ) {
		throw new RuntimeException( 'table name too long for atomic staging: ' . $table );
	}
	return array(
		'staging' => $table . $suffix . '__s',
		'old'     => $table . $suffix . '__o',
	);
}

/**
 * Fail closed when a RENAME-based swap would corrupt the schema. An incoming
 * foreign key follows the renamed old table (so the child would point at the
 * __o table and the final DROP fails), CREATE TABLE ... LIKE does not copy
 * foreign-key or trigger definitions, and triggers do not move with the swap.
 * WordPress core ships none, so this only ever refuses plugin-added FKs.
 */
function wpt_restore_swap_safe( $table ) {
	global $wpdb;
	// Fail CLOSED: an unreadable metadata query is UNKNOWN, never "safe".
	// (int) null would coerce a failed query to 0 and wave the swap through.
	$fk = wpt_audit_count( $wpdb->prepare(
		"SELECT COUNT(*) FROM information_schema.REFERENTIAL_CONSTRAINTS WHERE CONSTRAINT_SCHEMA = DATABASE() AND ( TABLE_NAME = %s OR REFERENCED_TABLE_NAME = %s )",
		$table,
		$table
	) );
	$trg = wpt_audit_count( $wpdb->prepare(
		"SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = DATABASE() AND EVENT_OBJECT_TABLE = %s",
		$table
	) );
	if ( null === $fk || null === $trg ) {
		throw new RuntimeException(
			'could not verify foreign keys/triggers for ' . $table . '; atomic swap refused'
		);
	}
	if ( $fk > 0 || $trg > 0 ) {
		throw new RuntimeException(
			'table has ' . $fk . ' foreign key(s) and ' . $trg . ' trigger(s); atomic swap is unsafe, restore refused'
		);
	}
}

/**
 * db_restore_table: staged, atomic whole-table restore of one whitelisted
 * table. Rows are loaded into an OWNED shadow table (created with CREATE
 * TABLE ... LIKE on the first call) whose name embeds the caller's per-restore
 * hex token (restore_id), so two concurrent restores never share staging and
 * a user table can never be mistaken for scratch. The LIVE table is replaced
 * only by a single atomic multi-table RENAME (live -> owned-old,
 * staging -> live) and ONLY after the staged row count is proven to equal the
 * caller's declared total_rows (so a partial or duplicated staging can never
 * be swapped in). TRUNCATE is NOT used: it implicitly commits and cannot be
 * rolled back, so the old truncate-then-insert left the live table
 * empty/partial on any mid-restore failure. Any failure before the swap
 * leaves the live table untouched.
 *
 * truncate_first marks the first call (creates staging); finalize marks the
 * last (completeness check + swap). Batched INSERTs (<=1000 rows per
 * statement) via $wpdb->prepare with %s placeholders (NULL cells become SQL
 * NULL literals, binary cells must be passed as
 * ["__wpt_b64__", "<base64>"]); refuses more than 5000 rows per call.
 */
function wpt_action_db_restore_table( array $params ) {
	global $wpdb;
	$table = ( isset( $params['table'] ) && is_string( $params['table'] ) ) ? $params['table'] : '';
	if ( '' === $table ) {
		throw new InvalidArgumentException( 'missing table' );
	}
	$restore_id = isset( $params['restore_id'] ) ? $params['restore_id'] : '';
	$rows = wpt_param_list( $params, 'rows' );
	foreach ( $rows as $r ) {
		if ( ! is_array( $r ) ) {
			throw new InvalidArgumentException( 'rows must be an array of arrays' );
		}
	}
	if ( count( $rows ) > 5000 ) {
		throw new InvalidArgumentException( 'too many rows (max 5000 per call)' );
	}
	if ( ! in_array( $table, wpt_table_whitelist(), true ) ) {
		throw new InvalidArgumentException( 'table not allowed: ' . $table );
	}
	$names = wpt_restore_table_names( $table, $restore_id );
	$cols  = wpt_table_columns( $table );
	if ( ! $cols ) {
		throw new RuntimeException( 'no columns found for ' . $table );
	}
	$width = count( $cols );
	foreach ( $rows as $r ) {
		if ( count( $r ) !== $width ) {
			throw new InvalidArgumentException( 'row width mismatch: expected ' . $width );
		}
	}

	// Strict booleans: !empty() would treat the string "false" as true.
	$begin = isset( $params['truncate_first'] ) && true === $params['truncate_first'];
	$final = isset( $params['finalize'] ) && true === $params['finalize'];
	// Validate total_rows BEFORE any mutation (a malformed value must never
	// reach the staging DROP/CREATE). finalize requires it; other calls may
	// carry it (restore.py sends it on every call for consistency).
	$declared = isset( $params['total_rows'] ) ? $params['total_rows'] : null;
	if ( null !== $declared
		&& ! is_int( $declared )
		&& ! ( is_string( $declared ) && ctype_digit( $declared ) ) ) {
		throw new InvalidArgumentException( 'invalid total_rows' );
	}
	if ( null !== $declared ) {
		$declared = (int) $declared;
	}
	if ( $final && null === $declared ) {
		throw new InvalidArgumentException( 'finalize requires an integer total_rows' );
	}
	$staging_exists = wpt_audit_count( $wpdb->prepare(
		"SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s",
		$names['staging']
	) );
	if ( null === $staging_exists ) {
		throw new RuntimeException( 'could not determine staging state for ' . $table );
	}
	// Serialize concurrent requests that carry the SAME restore_id. A client
	// network retry can leave the original request still executing server-side;
	// without a lock the retry could interleave an extra chunk into staging
	// between the finalize count and the RENAME. GET_LOCK is per-connection
	// and held for the whole body, so an overlapping request waits and then
	// fails closed (its staging is already consumed) instead of corrupting the
	// live table. The lock name is a bounded deterministic hash (<=64 chars,
	// MySQL's limit) of table+restore_id.
	$lock = 'wpt_restore_' . substr( md5( $table . '|' . $restore_id ), 0, 40 );
	$got  = $wpdb->get_var( $wpdb->prepare( 'SELECT GET_LOCK(%s, %d)', $lock, 30 ) );
	if ( '1' !== (string) $got ) {
		throw new RuntimeException( 'could not acquire restore lock for ' . $table );
	}
	try {
		if ( $begin ) {
			wpt_restore_swap_safe( $table );
			// Staging is owned by THIS restore_id: the DROP only ever removes our
			// own token-scoped scratch table (never a user table, never another
			// restore's), so a retried begin safely restarts.
			$wpdb->query( 'DROP TABLE IF EXISTS `' . wpt_backtick( $names['staging'] ) . '`' );
			if ( false === $wpdb->query( 'CREATE TABLE `' . wpt_backtick( $names['staging'] ) . '` LIKE `' . wpt_backtick( $table ) . '`' ) ) {
				throw new RuntimeException( 'staging create failed: ' . $wpdb->last_error );
			}
			$staging_exists = true;
		} elseif ( ! $staging_exists ) {
			// A middle/finalize call with no staging for THIS token means the
			// caller did not open the restore (or it was already swapped and the
			// staging is gone). Fail closed rather than swapping absent/partial.
			throw new RuntimeException(
				'no staging table for ' . $table . ' restore ' . $restore_id . '; restore must start with truncate_first'
			);
		}

		$col_sql  = '`' . implode( '`, `', array_map( 'wpt_backtick', $cols ) ) . '`';
		$inserted = 0;
		foreach ( array_chunk( $rows, 1000 ) as $batch ) {
			$values_sql = array();
			$flat       = array();
			foreach ( $batch as $row ) {
				$cells = array();
				for ( $i = 0; $i < $width; $i++ ) {
					$v = wpt_restore_cell( $row[ $i ] );
					if ( null === $v ) {
						$cells[] = 'NULL';
					} else {
						$cells[] = '%s';
						$flat[]  = $v;
					}
				}
				$values_sql[] = '( ' . implode( ', ', $cells ) . ' )';
			}
			$sql = 'INSERT INTO `' . wpt_backtick( $names['staging'] ) . '` ( ' . $col_sql . ' ) VALUES ' . implode( ', ', $values_sql );
			if ( $flat ) {
				$r = $wpdb->query( $wpdb->prepare( $sql, ...$flat ) );
			} else {
				$r = $wpdb->query( $sql );
			}
			if ( false === $r ) {
				throw new RuntimeException( 'insert failed: ' . $wpdb->last_error );
			}
			$inserted += count( $batch );
		}

		$swapped = false;
		if ( $final ) {
			// COMPLETENESS + ownership proof: the swap only proceeds when the
			// owned staging table holds exactly the declared total_rows. This is
			// what makes a partial staging (mid-restore failure), a duplicated
			// staging (an ambiguous network retry re-sending a chunk), and a
			// premature finalize (begin+finalize with a partial table) all fail
			// CLOSED instead of replacing the live table. ($declared was validated
			// as an integer before any mutation.)
			$staged = wpt_audit_count( "SELECT COUNT(*) FROM `" . wpt_backtick( $names['staging'] ) . "`" );
			if ( null === $staged ) {
				throw new RuntimeException( 'could not count staged rows for ' . $table );
			}
			if ( $staged !== $declared ) {
				throw new RuntimeException(
					'staged row count ' . $staged . ' != declared total_rows ' . $declared . '; swap refused (live table untouched)'
				);
			}
			// Re-verify the swap safety at finalize (a FK/trigger added mid-restore
			// would otherwise be swapped in unchecked). NOTE: this check and the
			// RENAME below are separate statements; a concurrent DDL on the live
			// table in that window is an accepted limitation (do not run schema
			// changes during a restore).
			wpt_restore_swap_safe( $table );
			// Single atomic multi-table RENAME: the live table is replaced at one
			// instant, so no reader observes it empty/partial.
			$rename = 'RENAME TABLE `' . wpt_backtick( $table ) . '` TO `' . wpt_backtick( $names['old'] )
				. '`, `' . wpt_backtick( $names['staging'] ) . '` TO `' . wpt_backtick( $table ) . '`';
			if ( false === $wpdb->query( $rename ) ) {
				throw new RuntimeException( 'atomic swap failed: ' . $wpdb->last_error );
			}
			$swapped = true;
			// Post-swap cleanup: the data IS restored at this point, so a failed
			// DROP must not fail the restore, but it is reported (old_left) so the
			// operator knows a leftover pre-restore copy table remains. It is inert
			// (token-scoped, hidden from audit) and does NOT block future restores
			// (each run uses a fresh token).
			$dropped = $wpdb->query( 'DROP TABLE IF EXISTS `' . wpt_backtick( $names['old'] ) . '`' );
			$old_left = ( false === $dropped );
		}
		return array(
			'table'      => $table,
			'inserted'   => $inserted,
			'swapped'    => $swapped,
			'old_left'   => isset( $old_left ) ? $old_left : false,
		);
	} finally {
		$wpdb->get_var( $wpdb->prepare( 'SELECT RELEASE_LOCK(%s)', $lock ) );
	}
}

/**
 * Decode one incoming restore cell: scalars pass through; the b64 marker
 * array decodes to the original binary; anything else is refused.
 */
function wpt_restore_cell( $cell ) {
	if ( is_array( $cell ) ) {
		if ( 2 === count( $cell ) && isset( $cell[0], $cell[1] ) && '__wpt_b64__' === $cell[0] && is_string( $cell[1] ) ) {
			$decoded = base64_decode( $cell[1], true );
			if ( false === $decoded ) {
				throw new InvalidArgumentException( 'bad base64 cell' );
			}
			return $decoded;
		}
		throw new InvalidArgumentException( 'unsupported cell type (array)' );
	}
	if ( null === $cell || is_string( $cell ) || is_int( $cell ) || is_float( $cell ) || is_bool( $cell ) ) {
		return $cell;
	}
	throw new InvalidArgumentException( 'unsupported cell type' );
}

/**
 * purge_cache: fire the LiteSpeed purge-all hook plus the W3 Total Cache and
 * WP Super Cache full-flush entry points, each function_exists-guarded (core
 * defines wp_cache_flush(), NOT wp_cache_clear_cache(), so an unguarded call
 * would fatal on stock WordPress). The action hook is safe unguarded (R2
 * verdict 3: a do_action with zero listeners is a no-op, and the LiteSpeed
 * hook is documented to work whether or not the plugin is active).
 */
function wpt_action_purge_cache( array $params ) {
	do_action( 'litespeed_purge_all' );
	if ( function_exists( 'w3tc_flush_all' ) ) {
		w3tc_flush_all();
	}
	if ( function_exists( 'wp_cache_clear_cache' ) ) {
		wp_cache_clear_cache();
	}
	return array( 'purged' => true );
}

/**
 * fileperms: "0644"-style permission strings for webroot-relative paths
 * (null when the path does not resolve inside ABSPATH), plus context perms
 * for ABSPATH and the uploads basedir.
 */
function wpt_action_fileperms( array $params ) {
	$paths     = wpt_param_str_list( $params, 'paths' );
	$root      = defined( 'ABSPATH' ) ? (string) ABSPATH : '';
	$root_real = ( '' !== $root ) ? realpath( $root ) : false;
	$out = array();
	foreach ( $paths as $rel ) {
		$rel   = ltrim( str_replace( "\0", '', (string) $rel ), '/' );
		$perms = null;
		if ( false !== $root_real ) {
			$real = realpath( $root . $rel );
			if ( false !== $real && 0 === strpos( $real, $root_real . DIRECTORY_SEPARATOR ) ) {
				$perms = wpt_perms_str( $real );
			}
		}
		$out[ $rel ] = $perms;
	}
	$context = array();
	if ( false !== $root_real ) {
		$context['abspath'] = wpt_perms_str( $root_real );
	}
	$ud = wp_upload_dir( null, false );
	if ( ! empty( $ud['basedir'] ) ) {
		$context['uploads_basedir'] = wpt_perms_str( (string) $ud['basedir'] );
	}
	return array( 'paths' => wpt_map( $out ), 'context' => wpt_map( $context ) );
}

/**
 * core_md5: bulk server-side md5 of webroot-relative core files in ONE call
 * (core.integrity reads ~3780 files; per-file FTP fetches stall for minutes
 * on a stale passive channel — the same reason db_dump/media_map are bridge
 * actions). Params: paths [webroot-relative POSIX paths, max 5000 per call].
 * Anti-traversal, media_delete's discipline applied BEFORE anything is
 * hashed (fail-closed): NUL bytes stripped, leading slashes dropped, no ".."
 * path segment, and the realpath must stay inside ABSPATH — any violation
 * refuses the whole request. Payload: files {rel: md5hex, null when the plain
 * file exists but cannot be read}, missing [rel — nothing there, or a
 * directory; directories are never hashed], unreadable [rel — exactly the
 * null-valued files entries]. All three deduplicate a repeated request path.
 */
function wpt_action_core_md5( array $params ) {
	$paths = wpt_param_str_list( $params, 'paths' );
	if ( count( $paths ) > 5000 ) {
		throw new InvalidArgumentException( 'too many paths (max 5000 per call)' );
	}
	$root      = defined( 'ABSPATH' ) ? (string) ABSPATH : '';
	$root_real = ( '' !== $root ) ? realpath( $root ) : false;
	if ( false === $root_real ) {
		throw new RuntimeException( 'webroot not on disk' );
	}

	$resolved = array();
	$missing  = array();
	foreach ( $paths as $rel ) {
		$rel = ltrim( str_replace( "\0", '', $rel ), '/' );
		if ( preg_match( '#(?:^|/)\.\.(?:/|$)#', $rel ) ) {
			throw new InvalidArgumentException( 'refused path (traversal): ' . $rel );
		}
		$real = realpath( $root . $rel );
		if ( false === $real ) {
			$missing[ $rel ] = true; // nothing there — tolerate
			continue;
		}
		if ( 0 !== strpos( $real, $root_real . DIRECTORY_SEPARATOR ) ) {
			throw new InvalidArgumentException( 'refused path (outside webroot): ' . $rel );
		}
		if ( ! is_file( $real ) ) {
			$missing[ $rel ] = true; // directories are never hashed
			continue;
		}
		$resolved[ $rel ] = $real;
	}

	$files     = array();
	$unreadable = array();
	foreach ( $resolved as $rel => $real ) {
		$md5 = @md5_file( $real );
		if ( false === $md5 ) {
			$files[ $rel ]      = null;
			$unreadable[ $rel ] = true;
		} else {
			$files[ $rel ] = $md5;
		}
	}
	return array(
		'files'      => wpt_map( $files ),
		'missing'    => array_keys( $missing ),
		'unreadable' => array_keys( $unreadable ),
	);
}

/**
 * core_upgrade: run WordPress's OWN database migration and report the
 * resulting schema version. Params: apply (bool, required — a migration is
 * irreversible on its own and every mutating op in this bridge is gated
 * the same way; a call without it refuses and runs nothing).
 *
 * The body is the smallest faithful thing that can exist: core's own
 * ``require_once wp-admin/includes/upgrade.php`` followed by
 * ``wp_upgrade()``.  There is no hand-written ALTER, no table allowlist
 * and no version arithmetic here — the schema target is
 * ``$wp_db_version`` from the ``wp-includes/version.php`` THIS request
 * loaded, which is why the op is only ever correct AFTER the file swap:
 * the migration target is then the release the operator asked for, and
 * ``wp_upgrade()`` itself is a no-op when the stored ``db_version``
 * already equals it.
 *
 * The op is deliberately the whole upgrade, not a diff: it also runs
 * ``upgrade_all()`` (every ``upgrade_XX()`` routine for the versions in
 * between), ``pre_schema_upgrade()``/``make_db_current_silent()`` and the
 * cache flushes core sequences around them.  Re-implementing any of that
 * in the bridge is how a "successful" update silently skips the migration
 * step that mattered.
 *
 * Payload: db_version (the stored schema version read back AFTER the
 * migration — the value the caller verifies against, never the value this
 * op hoped for), wp_version (get_bloginfo('version')), the db_version the
 * loaded core targets ($wp_db_version, null when the constant is absent),
 * output (whatever the migration PRINTED, captured, bounded and made
 * UTF-8-clean so the JSON envelope survives it — never discarded, because
 * a notice or a warning from core or a hook is the only evidence of WHY a
 * migration did not do what it was asked to) and output_truncated (the
 * output hit that bound).
 *
 * THE MARKER.  A FATAL inside wp_upgrade() — a modest memory_limit on a
 * big migration is the shape that actually happens on shared hosting — is
 * NOT catchable: it destroys the L4 envelope, so the caller receives
 * non-JSON and no diagnosis on a database the migration has already
 * half-moved.  So the op records what it is ABOUT to do, in the options
 * table, BEFORE it does it: the pre-migration db_version, the target, the
 * version and the wall time.  The marker is stamped finished on the way
 * out, and ``info`` reports it, so a vanished response still tells the
 * operator the state the migration began in — which is the difference
 * between "the update failed" and a diagnosis.  It is autoload=off: a
 * read-once diagnostic row must never be loaded on every page view.
 */
function wpt_action_core_upgrade( array $params ) {
	$apply = isset( $params['apply'] ) ? $params['apply'] : false;
	if ( true !== $apply ) {
		throw new InvalidArgumentException( 'core_upgrade requires apply=true (it migrates the database)' );
	}
	if ( function_exists( 'is_multisite' ) && is_multisite() ) {
		// wp_upgrade() takes a different path here (upgrade_network() plus
		// per-site db_version site meta). The update-core action refuses
		// multisite BEFORE it reaches this op; refusing here as well means
		// the refusal holds even if a future caller forgets.
		throw new RuntimeException( 'refusing to migrate a multisite installation' );
	}
	global $wp_db_version;
	$from    = wpt_option_scalar( get_option( 'db_version' ) );
	$marker  = array(
		'started'           => time(),
		'from_db_version'   => $from,
		'target_db_version' => isset( $wp_db_version ) ? (string) $wp_db_version : null,
		'wp_version'        => (string) get_bloginfo( 'version' ),
		'finished'          => null,
	);
	update_option( 'wpt_core_upgrade', $marker, 'no' );
	ob_start();
	try {
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		wp_upgrade();
	} finally {
		$noise = ob_get_clean();
	}
	$marker['finished'] = time();
	update_option( 'wpt_core_upgrade', $marker, 'no' );
	$stored = wpt_option_scalar( get_option( 'db_version' ) );
	list( $out, $truncated ) = wpt_upgrade_output( $noise );
	return array(
		'db_version'        => $stored,
		'wp_version'        => (string) get_bloginfo( 'version' ),
		'target_db_version' => isset( $wp_db_version ) ? (string) $wp_db_version : null,
		'output'            => $out,
		'output_truncated'  => $truncated,
	);
}

/**
 * The argument array core's Core_Upgrader::upgrade() parses — the ONE place
 * wpt states it, so the value is an argument of core's own upgrader and not
 * a flag of our own invention.  The keys and defaults are core's
 * (class-core-upgrader.php, ``upgrade()``).
 *
 * ``attempt_rollback => true`` is the argument the ADMIN UI NEVER passes: a
 * manually clicked "Update Now" gets no rollback, and only
 * ``WP_Automatic_Updater`` arms it.  wpt arms it because its run has the
 * pre-action snapshot an unattended update never has — and because the arming
 * makes core's own critical-failure rule observable (see
 * :func:`wpt_core_upgrade_rollback_critical`), so the operator is told
 * whether the failure that happened is the class core would have rolled back.
 *
 * ``pre_check_md5 => false`` because the CALLER proved the package bytes
 * against the target's own wp.org checksum map before uploading them, and
 * core's check_files() is about the INSTALLED tree deciding whether a PARTIAL
 * package is safe — a question the caller already answered (it uploads the
 * full release).
 */
function wpt_core_upgrade_args() {
	return array(
		'pre_check_md5'                => false,
		'attempt_rollback'             => true,
		'do_rollback'                  => false,
		'allow_relaxed_file_ownership' => false,
	);
}

/**
 * core's OWN critical-error rule for a rollback, transcribed (not
 * re-derived): ``class-core-upgrader.php`` ``upgrade()`` arms the rollback for
 * error codes containing ``do_rollback`` or ``__copy_dir``, and for
 * ``disk_full`` — and for nothing else (``insane_distro``, the PHP/MySQL
 * incompatibility gates and ``files_not_writable`` are not rollback-worthy).
 * Used to ANSWER "would core have rolled this back?", never to roll back.
 */
function wpt_core_upgrade_rollback_critical( $code ) {
	$code = (string) $code;
	if ( false !== strpos( $code, 'do_rollback' ) ) {
		return true;
	}
	if ( false !== strpos( $code, '__copy_dir' ) ) {
		return true;
	}
	return 'disk_full' === $code;
}

/**
 * Block core's FIRE-AND-FORGET database step.
 *
 * ``update_core()`` finishes by POSTing ``upgrade.php?step=upgrade_db`` to
 * itself with a 60 s timeout and NEVER inspects the response
 * (wp-admin/includes/update-core.php: ``wp_remote_post( $db_upgrade_url, array(
 * 'timeout' => 60 ) )``).  From a bridge endpoint that request is a second,
 * unauthenticated migration racing the one wpt runs on purpose, and its
 * outcome is unobservable — which is exactly why the update-core action
 * re-reads db_version itself after the migration.
 *
 * So the op suppresses it through core's OWN ``pre_http_request`` filter and
 * SAYS SO in the answer.  The database is migrated by the ``core_upgrade`` op
 * (core's own ``wp_upgrade()``, in-process, with its pre-migration marker) and
 * proved by a fresh ``info`` afterwards; a suppressed request is a reported
 * one, never a silent gap.
 */
function wpt_core_upgrade_block_db_step( $preempt, $args, $url ) {
	if ( is_string( $url ) && false !== strpos( $url, 'upgrade.php?step=upgrade_db' ) ) {
		return new WP_Error(
			'wpt_db_step_suppressed',
			'wpt runs wp_upgrade() itself through core_upgrade and re-reads db_version'
		);
	}
	return $preempt;
}

/**
 * core_upgrade_files: install a core release with WORDPRESS'S OWN updater.
 *
 * The file half of a core update, driven by core's own code, with the
 * arguments the admin UI does not pass.  Params: apply (bool, required — the
 * op overwrites the site's core files, so the gate is the same one every
 * mutating op in this bridge carries), package (the webroot-relative path of
 * the release zip the CALLER uploaded and proved against wp.org's checksum
 * map), target (the X.Y.Z that package must carry).
 *
 * WHY NOT re-implement the copy.  WordPress encodes two things in its own
 * updater that are catastrophic to get wrong, and re-implementing placement
 * forfeits both for nothing:
 *
 *  1. ``copy_dir()`` with the skip list ``array( 'wp-content',
 *     'wp-includes/version.php' )`` — wp-content is excluded wholesale and
 *     re-added item by item, and version.php is copied LAST so a failed
 *     update still reports its OLD version (update-core.php: the comment on
 *     the skip list says exactly that).
 *  2. The extraction into ``wp-content/upgrade/`` (core's own staging dir)
 *     through core's own ``unzip_file()``, which opens the archive with
 *     ``ZIPARCHIVE::CHECKCONS`` and falls through ZipArchive -> PclZip.
 *
 * So the op calls core and nothing else: ``WP_Upgrader::unpack_package()``
 * (unzip) then ``update_core()`` (the whole copy body: the ``insane_distro``
 * confidence check, the PHP/MySQL/extension gates, the writable pre-flight,
 * copy_dir, the post-copy md5 re-verification with a retry, the
 * ``wp-content/languages`` copy, the bundled theme/plugin re-add, the
 * ``$_old_files`` removal and the incompatible-plugin deactivation).
 *
 * WHAT THE OP DOES NOT DO, and why each is the caller's job:
 *
 * * ``.maintenance`` — core writes it and deletes it on ITS success route
 *   only, which is the reachable "stuck in maintenance" state.  wpt writes
 *   its own (with a body a human can read) before the op and removes it in a
 *   ``finally`` that no core path can skip.  The op REPORTS whether core
 *   left one behind.
 * * the database step — see :func:`wpt_core_upgrade_block_db_step`.
 * * the verification — the caller re-reads the version and re-hashes every
 *   replaced file.  Core's success return is a version STRING; it does not
 *   prove the site loads.
 *
 * THE STAGING DIRECTORY IS NOT SWEPT BLINDLY.  ``wp-content/upgrade/`` is
 * core's own staging area and, on a site whose earlier core update died
 * mid-copy, the operator's recovery path — so the op REFUSES to start when it
 * already holds anything (naming what), rather than letting core's
 * ``unpack_package()`` wipe it on its way in.  The path is reported in the
 * answer, and the caller owns clearing it.
 *
 * Payload: wp_version (read from ``ABSPATH/wp-includes/version.php`` AFTER
 * the copy — the fact the caller verifies against, never the one core
 * returned), from_wp_version (what the site ran before), db_version (the
 * stored schema version, unchanged: the DB step is suppressed), staging /
 * staging_exists (the directory this run used), upgrade_args (the array above,
 * ``attempt_rollback`` included), rollback {armed, taken, reason, and
 * critical_code when core's own rule says the failure is its rollback class},
 * phases {unzip, copy, bundled} MEASURED (see wpt_core_upgrade_phase), the
 * ordered list of core's own progress messages, bundled_added (the bundled
 * theme/plugin units that appeared), db_step, filesystem_method,
 * maintenance_left, error (null or {code, message} — a core failure is
 * REPORTED, not thrown, so the phases that got that far survive the answer),
 * and output / output_truncated.
 */
function wpt_action_core_upgrade_files( array $params ) {
	$apply = isset( $params['apply'] ) ? $params['apply'] : false;
	if ( true !== $apply ) {
		throw new InvalidArgumentException( 'core_upgrade_files requires apply=true (it overwrites the site\'s core files)' );
	}
	if ( function_exists( 'is_multisite' ) && is_multisite() ) {
		// The same refusal core_upgrade makes, for the same reason: a
		// network install's core update and schema migration are network
		// operations, and this action's snapshot is one site's.
		throw new RuntimeException( 'refusing to update core files on a multisite installation' );
	}
	$target = isset( $params['target'] ) && is_string( $params['target'] ) ? trim( $params['target'] ) : '';
	if ( '' === $target ) {
		throw new InvalidArgumentException( 'missing target: the X.Y.Z this package must carry' );
	}
	$package = wpt_core_upgrade_package( $params );

	// core's own file layer, loaded the way wp-admin/update-core.php loads it
	require_once ABSPATH . 'wp-admin/includes/file.php';
	require_once ABSPATH . 'wp-admin/includes/class-wp-filesystem-base.php';
	require_once ABSPATH . 'wp-admin/includes/class-wp-filesystem-direct.php';
	require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
	require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader-skin.php';
	if ( ! class_exists( 'Automatic_Upgrader_Skin' ) ) {
		require_once ABSPATH . 'wp-admin/includes/class-wp-automatic-upgrader.php';
	}

	// THE PRECONDITION, not a retry: core's updater authenticates its
	// filesystem through fs_connect() -> request_filesystem_credentials(),
	// which is an interactive PROMPT.  A bridge endpoint has nobody to answer
	// it, and every non-direct method (ftpext / ftpsockets / ssh2) would copy
	// core into a different tree than the one the site serves.  So the method
	// is resolved HERE, first, and a non-direct one refuses the run.
	// ``allow_relaxed_file_ownership => false`` for the same reason core's own
	// callers pass false: the relaxed probe answers 'direct' but cannot create
	// files, and a core update is mostly creating files.
	$method = get_filesystem_method( array(), ABSPATH, false );
	if ( ! is_string( $method ) || '' === $method ) {
		throw new RuntimeException( 'cannot read this site\'s filesystem method — WordPress\'s own updater cannot be driven blind, and the pre-action snapshot is the rollback' );
	}
	if ( 'direct' !== $method ) {
		throw new RuntimeException(
			'refusing to update core files: this site\'s filesystem method is ' . $method
			. ', and WordPress\'s own updater cannot extract or copy core without a filesystem it can authenticate to (it blocks on an interactive credential prompt a bridge endpoint cannot answer); use the swap driver instead (--set update.driver=swap)'
		);
	}
	$zip = wpt_core_upgrade_zip_library();
	if ( '' === $zip ) {
		throw new RuntimeException(
			'refusing to update core files: this PHP has neither ZipArchive nor core\'s bundled PclZip, so core\'s own unzip_file() cannot extract the release; use the swap driver instead (--set update.driver=swap)'
		);
	}
	if ( ! WP_Filesystem( array( 'context' => ABSPATH ), ABSPATH, false ) ) {
		throw new RuntimeException( 'WordPress could not connect to its own filesystem (WP_Filesystem failed) — the pre-action snapshot is the rollback' );
	}
	global $wp_filesystem;

	$content_dir = (string) $wp_filesystem->wp_content_dir();
	if ( '' === $content_dir ) {
		throw new RuntimeException( 'WordPress could not resolve WP_CONTENT_DIR on this install — there is no staging directory to extract into' );
	}
	$upgrade_folder = $content_dir . 'upgrade/';
	$existing       = wpt_core_upgrade_dirlist_names( $upgrade_folder );
	if ( $existing ) {
		// core's unpack_package() WIPES the upgrade folder on its way in, so
		// starting with content there would delete a recovery path silently.
		throw new RuntimeException(
			'refusing to update core files: ' . $upgrade_folder . ' already holds '
			. count( $existing ) . ' entr(ies) (' . implode( ', ', array_slice( $existing, 0, 3 ) )
			. ( count( $existing ) > 3 ? ', …' : '' )
			. ') — that is a site whose earlier core update did not finish, and that staging is the recovery path; re-run `wpt update-core` (its residue report names it) and move it aside, or restore the pre-action snapshot, before updating'
		);
	}

	$from_version = (string) get_bloginfo( 'version' );
	$progress     = array();
	$error        = null;
	$staging      = '';
	$staging_exists = false;
	$bundled_added  = array();
	$phases         = array(
		'unzip'   => array( 'ok' => false, 'detail' => 'not attempted' ),
		'copy'    => array( 'ok' => false, 'detail' => 'not attempted' ),
		'bundled' => array( 'ok' => false, 'detail' => 'not attempted' ),
	);

	ob_start();
	try {
		// The upgrader's own skin, non-interactive: Automatic_Upgrader_Skin is
		// the class WP_Automatic_Updater drives core's updater with, and it
		// records core's progress into $skin->messages instead of printing
		// it.  That is also the answer's per-phase evidence.
		$GLOBALS['wpt_core_upgrade_progress'] = array();
		$upgrader = new WP_Upgrader( new Automatic_Upgrader_Skin() );
		add_filter( 'update_feedback', 'wpt_core_upgrade_record_feedback', 10, 1 );
		add_filter( 'pre_http_request', 'wpt_core_upgrade_block_db_step', 10, 3 );

		$working = $upgrader->unpack_package( $package, false /* keep the package: the caller's sweep owns it */ );
		if ( is_wp_error( $working ) ) {
			$error = array( 'code' => $working->get_error_code(), 'message' => $working->get_error_message() );
		} else {
			$staging        = wpt_core_upgrade_staging( $working );
			$staging_exists = true;
			$distro         = wpt_core_upgrade_distro( $working );
			$phases['unzip'] = wpt_core_upgrade_phase( $distro, $staging );
			// What the release ships under wp-content/{plugins,themes}/, read
			// BEFORE the copy: core's bundled re-add only ever introduces an
			// item that was absent, so the before/after difference is exactly
			// the set it introduced.
			$bundled_before = wpt_core_upgrade_bundled( $working, $distro );
			$dest_before    = wpt_core_upgrade_installed_bundled( $wp_filesystem );

			// update_core() lives in update-core.php from WP 6.9 on and in
			// update.php before that; the file is the CURRENT core's, which is
			// what core's own upgrader copies in before requiring it (so a very
			// old install still gets the new body).  wpt does not copy that one
			// file first: it must not touch the live tree before the caller's
			// own proof, and an install shipping neither file refuses here
			// rather than half-copying.
			if ( ! function_exists( 'update_core' ) ) {
				foreach ( array( 'update-core.php', 'update.php' ) as $inc ) {
					$path = ABSPATH . 'wp-admin/includes/' . $inc;
					if ( is_readable( $path ) ) {
						require_once $path;
					}
					if ( function_exists( 'update_core' ) ) {
						break;
					}
				}
			}
			if ( ! function_exists( 'update_core' ) ) {
				$error = array(
					'code'    => 'no_update_core_body',
					'message' => 'this install ships neither wp-admin/includes/update-core.php nor wp-admin/includes/update.php, so WordPress\'s own core update body is not available on the site; use the swap driver instead (--set update.driver=swap)',
				);
			} else {
				$result = update_core( $working, trailingslashit( $wp_filesystem->abspath() ) );
				if ( is_wp_error( $result ) ) {
					$error = array( 'code' => $result->get_error_code(), 'message' => $result->get_error_message() );
				}
			}
			$landed = wpt_core_upgrade_version_php( ABSPATH . 'wp-includes/version.php' );
			$phases['copy'] = array(
				'ok'     => ( null !== $landed && $landed === $target ),
				'detail' => ( null === $landed
					? 'wp-includes/version.php could not be read after the copy'
					: 'wp-includes/version.php declares $wp_version = ' . $landed
						. ( $landed === $target ? '' : ' (the target was ' . $target . ')' ) ),
			);
			if ( null === $error && $landed !== $target ) {
				// core does NOT assert that the package carries the version
				// that was asked for (its insane_distro check is two sentinel
				// files), so the op refuses to call that a success.
				$error = array(
					'code'    => 'version_mismatch',
					'message' => 'the core on disk declares $wp_version = '
						. ( null === $landed ? '(unreadable)' : $landed )
						. ', not the requested ' . $target,
				);
			}
			$dest_after = wpt_core_upgrade_installed_bundled( $wp_filesystem );
			$added      = array();
			foreach ( $bundled_before as $unit ) {
				if ( ! in_array( $unit, $dest_before, true ) && in_array( $unit, $dest_after, true ) ) {
					$added[] = $unit;
				}
			}
			$bundled_added  = $added;
			$phases['bundled'] = array(
				// A bundled item the site ALREADY has is not an addition: core
				// refuses to overwrite a bundled unit on a stable build, so an
				// empty $added is a normal outcome.  The phase fails only on
				// core's own bundled-copy error code.
				'ok'     => ( null === $error || false === strpos( $error['code'], 'new_bundled' ) ),
				'detail' => empty( $bundled_before )
					? 'the release ships no bundled theme or plugin to re-add'
					: count( $added ) . ' of ' . count( $bundled_before )
						. ' bundled unit(s) the release ships were added (the rest were already installed, which core never overwrites on a stable build)',
			);
			// core deletes its own staging at the end of both routes; report
			// what is actually there rather than what was asked for.
			$staging_exists = is_dir( $staging );
		}
	} finally {
		remove_filter( 'update_feedback', 'wpt_core_upgrade_record_feedback', 10 );
		remove_filter( 'pre_http_request', 'wpt_core_upgrade_block_db_step', 10 );
		$noise    = ob_get_clean();
		$progress = wpt_core_upgrade_feedback();
	}

	list( $out, $truncated ) = wpt_upgrade_output( $noise );
	$args = wpt_core_upgrade_args();
	// The payload's version is read off the disk AFTER every phase, not
	// remembered from the copy: a value the answer reports must be a value
	// something can read.
	$landed = wpt_core_upgrade_version_php( ABSPATH . 'wp-includes/version.php' );
	$stored = wpt_option_scalar( get_option( 'db_version' ) );
	$rollback = array(
		'armed'  => (bool) $args['attempt_rollback'],
		'taken'  => false,
		'reason' => 'WordPress\'s own rollback is a SECOND full upgrade against a rollback package downloaded from wordpress.org, which this op never has; wpt\'s rollback is the pre-action snapshot (`wpt restore --undo-last`)',
	);
	if ( null !== $error && wpt_core_upgrade_rollback_critical( $error['code'] ) ) {
		$rollback['critical_code'] = $error['code'];
	}
	return array(
		'wp_version'        => $landed,
		'from_wp_version'   => $from_version,
		'db_version'        => $stored,
		'target'            => $target,
		'staging'           => $staging,
		'staging_exists'    => (bool) $staging_exists,
		'upgrade_args'      => wpt_map( $args ),
		'rollback'          => wpt_map( $rollback ),
		'phases'            => wpt_map( $phases ),
		'progress'          => $progress,
		'bundled_added'     => $bundled_added,
		'db_step'           => 'suppressed: WordPress fires it as a fire-and-forget wp_remote_post with a 60s timeout and never checks the response; wpt runs wp_upgrade() itself through core_upgrade and re-reads db_version',
		'filesystem_method' => $method,
		'zip_library'       => $zip,
		'maintenance_left'  => file_exists( ABSPATH . '.maintenance' ),
		'error'             => ( null === $error ? null : wpt_map( $error ) ),
		'output'            => $out,
		'output_truncated'  => $truncated,
	);
}

/**
 * The $wp_version a version.php declares, read WITHOUT executing it in this
 * scope: the file is ``include``d inside a function so its globals stay
 * local, exactly as core reads the release's copy
 * (update-core.php: ``require WP_CONTENT_DIR . '/upgrade/version-current.php'``).
 * Returns null when the file is absent or unreadable — UNKNOWN, never "".
 */
function wpt_core_upgrade_version_php( $path ) {
	if ( ! is_readable( $path ) ) {
		return null;
	}
	$wp_version = null;
	// The include runs INSIDE a discarded output buffer, and that is not
	// defensive decoration: this file runs with display_errors on, and a
	// version.php that is not parseable PHP (a truncated copy, a text file
	// where the version file belongs) PRINTS its own bytes on include —
	// which would land before this operation's JSON envelope and destroy
	// the whole answer (the [L4] rule, one level deeper).  The read is
	// still core's own file and core's own global.
	ob_start();
	try {
		include $path;
	} finally {
		ob_end_clean();
	}
	return is_string( $wp_version ) && '' !== $wp_version ? $wp_version : null;
}

/**
 * The release package, resolved INSIDE the webroot: the same anti-traversal
 * discipline core_md5 applies, re-proved here (NUL stripped, no leading
 * slash, no ".." segment, realpath contained in ABSPATH) because this op
 * hands the path to core's own extractor.  A .zip suffix is required: core's
 * unpack_package() derives the staging directory name from it.
 */
function wpt_core_upgrade_package( array $params ) {
	$rel = isset( $params['package'] ) && is_string( $params['package'] ) ? $params['package'] : '';
	$rel = ltrim( str_replace( "\0", '', $rel ), '/' );
	if ( '' === $rel ) {
		throw new InvalidArgumentException( 'missing package: the release zip the caller proved and uploaded' );
	}
	if ( preg_match( '#(?:^|/)\.\.(?:/|$)#', $rel ) ) {
		throw new InvalidArgumentException( 'refused package (traversal): ' . $rel );
	}
	$root = defined( 'ABSPATH' ) ? realpath( ABSPATH ) : false;
	if ( false === $root ) {
		throw new RuntimeException( 'webroot not on disk' );
	}
	$real = realpath( $root . '/' . $rel );
	if ( false === $real || 0 !== strpos( $real, $root . DIRECTORY_SEPARATOR ) ) {
		throw new RuntimeException( 'refused package (outside the webroot or missing): ' . $rel );
	}
	if ( ! is_file( $real ) ) {
		throw new RuntimeException( 'the release package is not a file: ' . $rel );
	}
	if ( 'zip' !== strtolower( (string) pathinfo( $real, PATHINFO_EXTENSION ) ) ) {
		throw new RuntimeException( 'the release package is not a .zip: ' . $rel );
	}
	return $real;
}

/**
 * The zip library core's own unzip_file() will use: ZipArchive when the
 * extension is loaded, else core's bundled PclZip, else "" (neither — the
 * extraction cannot run, and a run that cannot extract must not start).
 * Read AFTER wp-admin/includes/file.php is loaded, because PclZip is defined
 * at the bottom of that file.
 */
function wpt_core_upgrade_zip_library() {
	if ( class_exists( 'ZipArchive' ) ) {
		return 'ZipArchive';
	}
	if ( class_exists( 'PclZip' ) ) {
		return 'PclZip';
	}
	return '';
}

/**
 * core's own ``insane_distro`` confidence check, as a PREDICATE (it is two
 * sentinel files, update-core.php: the loop over /wordpress/ and
 * /wordpress-mu/): the distro root inside the extracted staging, or ''.
 * It is a structural check, not a version match — which is why the op reads
 * the landed version.php itself and compares it with the target.
 */
function wpt_core_upgrade_distro( $working ) {
	foreach ( array( '/wordpress/', '/wordpress-mu/' ) as $root ) {
		if ( is_file( $working . $root . 'readme.html' )
			&& is_file( $working . $root . 'wp-includes/version.php' ) ) {
			return $root;
		}
	}
	return '';
}

/**
 * One phase's MEASURED outcome, never its intent: a phase is "ok" only on
 * evidence read back off the disk after core ran.
 */
function wpt_core_upgrade_phase( $distro, $staging ) {
	if ( '' === $distro ) {
		return array(
			'ok'     => false,
			'detail' => 'the extracted release carries neither readme.html nor wp-includes/version.php under /wordpress/ — core calls this an insane_distro and refuses to copy it',
		);
	}
	return array(
		'ok'     => true,
		'detail' => 'extracted under ' . rtrim( $staging, '/' ) . $distro
			. ' (core\'s own staging directory, wp-content/upgrade/)',
	);
}

/**
 * The staging path, WEBROOT-relative, so the answer never carries a
 * server-absolute path the caller would have to relativize (the same rule
 * media_rewrite_refs' uploads fact follows).  The path is normalized here
 * rather than through wp_normalize_path() so the op's dependency on core's
 * admin surface stays exactly the updater's own.
 */
function wpt_core_upgrade_staging( $working ) {
	// Both sides are realpath'd before the prefix test, and the base is
	// ABSPATH (WP_CONTENT_DIR is built from it and ends in a separator, so
	// a string comparison on the raw constants can miss on a doubled
	// separator): the answer is WEBROOT-relative, which is the only shape
	// the caller can match against its own residue rule.
	$content = realpath( ABSPATH );
	$staging = realpath( $working );
	if ( ! is_string( $content ) || ! is_string( $staging ) ) {
		return basename( untrailingslashit( (string) $working ) );
	}
	$content = wpt_core_upgrade_slash( $content );
	$staging = wpt_core_upgrade_slash( $staging );
	if ( 0 === strpos( $staging, $content ) ) {
		return rtrim( substr( $staging, strlen( $content ) ), '/' );
	}
	return basename( untrailingslashit( $staging ) );
}

/**
 * Backslashes to forward slashes (the zip-release path shape), with a
 * trailing separator added when one is missing.
 */
function wpt_core_upgrade_slash( $path ) {
	$path = str_replace( '\\', '/', (string) $path );
	return ( '' === $path || '/' === substr( $path, -1 ) ) ? $path : $path . '/';
}

/**
 * Entry names directly inside a directory, or an empty list (absent,
 * unreadable and empty are all "nothing there": the only consumer is the
 * refusal above, which is about what is IN there).
 */
function wpt_core_upgrade_dirlist_names( $dir ) {
	if ( ! is_dir( $dir ) ) {
		return array();
	}
	$entries = @scandir( $dir );
	if ( ! is_array( $entries ) ) {
		return array();
	}
	$out = array();
	foreach ( $entries as $name ) {
		if ( '.' !== $name && '..' !== $name ) {
			$out[] = $name;
		}
	}
	return $out;
}

/**
 * The bundled theme/plugin units the extracted release ships, as
 * ``type/filename/`` (core's own $_new_bundled_files shape), read from the
 * staging under the DISTRO root core detected.
 */
function wpt_core_upgrade_bundled( $working, $distro ) {
	$out = array();
	if ( '' === $distro ) {
		return $out;
	}
	foreach ( array( 'plugins', 'themes' ) as $type ) {
		foreach ( wpt_core_upgrade_dirlist_names( $working . $distro . 'wp-content/' . $type ) as $name ) {
			$out[] = $type . '/' . $name . '/';
		}
	}
	return $out;
}

/**
 * The bundled units this site currently HAS, same shape — the "before" side
 * of the re-add measurement.
 */
function wpt_core_upgrade_installed_bundled( $wp_filesystem ) {
	$out = array();
	$dirs = array(
		'plugins' => $wp_filesystem->wp_plugins_dir(),
		'themes'  => trailingslashit( $wp_filesystem->wp_themes_dir() ),
	);
	foreach ( $dirs as $type => $dir ) {
		foreach ( wpt_core_upgrade_dirlist_names( $dir ) as $name ) {
			$out[] = $type . '/' . $name . '/';
		}
	}
	return $out;
}

/**
 * core's own progress messages, in order: ``update_core()`` announces every
 * phase through the ``update_feedback`` filter, so the ordered list is the
 * phase list core itself published — the answer's per-phase evidence for the
 * phases between the sentinels.
 */
function wpt_core_upgrade_record_feedback( $feedback ) {
	$GLOBALS['wpt_core_upgrade_progress'][] = (string) $feedback;
	return $feedback;
}

function wpt_core_upgrade_feedback() {
	return isset( $GLOBALS['wpt_core_upgrade_progress'] ) && is_array( $GLOBALS['wpt_core_upgrade_progress'] )
		? $GLOBALS['wpt_core_upgrade_progress']
		: array();
}


/**
 * A scalar option value as a string, or null when it is absent, empty or
 * not a scalar.  The same UNKNOWN-never-zero rule the info op applies to
 * db_version, in one place: a corrupt options row (an array where a
 * string belongs) is "unknown", and a string cast of it would raise
 * "Array to string conversion" — which, with this file's display_errors
 * on, would be PRINTED before the JSON and destroy the envelope.
 */
function wpt_option_scalar( $value ) {
	if ( ! is_scalar( $value ) || '' === (string) $value ) {
		return null;
	}
	return (string) $value;
}

/**
 * ONE scalar/list owner for option values that must be a LIST OF STRINGS.
 *
 * WordPress returns `active_plugins` as a list of plugin-file strings.  A
 * corrupt serialized row can hold an array/object entry; `array_map(
 * 'strval', ... )` then emits "Array to string conversion" BEFORE the JSON
 * (display_errors is on, SPEC R12) and every audit fact is lost, while the
 * mutating ops wrote the literal string "Array" into the option.  This
 * owner refuses the whole list instead: a corrupt active set is UNKNOWN,
 * never a fabricated empty/one-entry set.  `$absent_is_empty` covers
 * get_option()'s `false` for an option that was never created.
 */
function wpt_option_string_list( $value, $what, $absent_is_empty = true ) {
	if ( false === $value && $absent_is_empty ) {
		return array();
	}
	if ( ! is_array( $value ) ) {
		throw new RuntimeException( $what . ' option is not a list' );
	}
	$out = array();
	foreach ( array_values( $value ) as $index => $entry ) {
		if ( ! is_string( $entry ) ) {
			throw new RuntimeException(
				$what . ' option entry ' . $index . ' is not a string'
			);
		}
		$out[] = $entry;
	}
	return $out;
}

/**
 * ONE scalar owner for an OPTIONAL integer option fact.
 *
 * A non-scalar (array/object), an empty string or a non-numeric value is
 * UNKNOWN (null), never a PHP `(int)` cast that would emit a warning before
 * the JSON or fabricate a 0/1 from a corrupt row.
 */
function wpt_option_int( $value ) {
	if ( ! is_scalar( $value ) || is_bool( $value ) ) {
		return null;
	}
	if ( is_string( $value ) && '' === trim( $value ) ) {
		return null;
	}
	if ( ! is_numeric( $value ) ) {
		return null;
	}
	return (int) $value;
}

/**
 * The migration's captured output, made safe to put in a JSON envelope.
 *
 * Two bounds, both structural: a LENGTH cap (what a migration prints is
 * unbounded — a plugin's debug loop can print megabytes, and the answer
 * must not become the payload) and a UTF-8 guarantee (the success
 * envelope is encoded with JSON_THROW_ON_ERROR, so ONE invalid byte from
 * a host whose notices are not UTF-8 would throw inside the op and turn a
 * successful migration into an error answer).  Invalid sequences are
 * dropped rather than substituted, and the returned flag says whether
 * anything was cut so the caller can say so in its log.
 */
function wpt_upgrade_output( $noise, $max = 2000 ) {
	$noise = is_string( $noise ) ? $noise : '';
	if ( '' === trim( $noise ) ) {
		return array( '', false );
	}
	$truncated = false;
	if ( strlen( $noise ) > $max ) {
		$noise     = substr( $noise, 0, $max );
		$truncated = true;
	}
	if ( ! preg_match( '//u', $noise ) ) {
		$clean = function_exists( 'iconv' )
			? @iconv( 'UTF-8', 'UTF-8//IGNORE', $noise )
			: false;
		if ( false === $clean || null === $clean ) {
			return array( '', true );   // unencodable: keep the answer, drop the noise
		}
		$noise = $clean;
	}
	return array( $noise, $truncated );
}

/**
 * Action registry — the bridge's ONLY extension surface. Adding an op =
 * one entry + one small handler above (+ one client method). Handler names
 * are resolved at dispatch; unknown names never reach PHP code.
 */
$wpt_actions = array(
	'info'              => 'wpt_action_info',
	'db_audit'          => 'wpt_action_db_audit',
	'media_map'         => 'wpt_action_media_map',
	'media_delete'      => 'wpt_action_media_delete',
	'media_rewrite_refs' => 'wpt_action_media_rewrite_refs',
	'db_clean'          => 'wpt_action_db_clean',
	'plugin_deactivate' => 'wpt_action_plugin_deactivate',
	'reconcile_active_plugins' => 'wpt_action_reconcile_active_plugins',
	'users_reset'       => 'wpt_action_users_reset',
	'user_create'       => 'wpt_action_user_create',
	'db_dump'           => 'wpt_action_db_dump',
	'db_restore_table'  => 'wpt_action_db_restore_table',
	'purge_cache'       => 'wpt_action_purge_cache',
	'fileperms'         => 'wpt_action_fileperms',
	'core_md5'          => 'wpt_action_core_md5',
	'core_upgrade'      => 'wpt_action_core_upgrade',
	'core_upgrade_files' => 'wpt_action_core_upgrade_files',
);

// ---------------------------------------------------------------------------
// Token gate + dispatch.
// ---------------------------------------------------------------------------

// Placeholders — the client substitutes both at upload time. Unsubstituted
// values fail closed: the token can never match, the expiry casts to 0.
$wpt_token   = '__WPT_TOKEN__';
$wpt_expires = '__WPT_EXPIRES__';

if ( ! isset( $_GET['t'] ) || ! hash_equals( $wpt_token, (string) $_GET['t'] ) || time() > (int) $wpt_expires ) {
	wpt_bridge_not_found();
}

// Valid token only: remove the bridge from disk and confirm.
if ( isset( $_GET['selfdestruct'] ) && '1' === (string) $_GET['selfdestruct'] ) {
	@unlink( __FILE__ );
	header( 'Content-Type: text/plain' );
	echo 'gone';
	exit;
}

try {
	$req = json_decode( (string) file_get_contents( 'php://input' ), true, 512, JSON_THROW_ON_ERROR );
	if ( ! is_array( $req ) ) {
		wpt_bridge_send( array( 'ok' => false, 'error' => 'request body must be a JSON object' ) );
	}
	// json_decode(assoc) turns JSON lists into int-keyed arrays — refuse them.
	$first_key = array_key_first( $req );
	if ( null !== $first_key && is_int( $first_key ) ) {
		wpt_bridge_send( array( 'ok' => false, 'error' => 'request body must be a JSON object' ) );
	}
	$action = ( isset( $req['action'] ) && is_string( $req['action'] ) ) ? $req['action'] : '';
	if ( '' === $action ) {
		wpt_bridge_send( array( 'ok' => false, 'error' => 'missing action' ) );
	}
	if ( ! isset( $wpt_actions[ $action ] ) ) {
		wpt_bridge_send( array( 'ok' => false, 'error' => 'unknown action' ) );
	}
	$params = ( isset( $req['params'] ) && is_array( $req['params'] ) ) ? $req['params'] : array();
	$handler = $wpt_actions[ $action ];
	$result  = $handler( $params );
	if ( null === $result ) {
		exit; // streaming handler (db_dump) already emitted its output
	}
	// Success envelopes are LENIENT about invalid UTF-8: the op may have
	// ALREADY mutated the site (users_reset sets and proves a live random
	// password before returning DB-provided login/email fields), and a
	// single latin-1 byte in a row must never replace the credential-bearing
	// rows with the error-only catch below.  JSON_INVALID_UTF8_SUBSTITUTE
	// keeps the results and marks the offending byte "?".
	wpt_bridge_send( array_merge( array( 'ok' => true ), $result ), true );
} catch ( Throwable $e ) {
	// L4: opaque 500s become structured JSON with HTTP 200.
	wpt_bridge_send(
		array(
			'ok'    => false,
			'error' => $e->getMessage(),
			'type'  => get_class( $e ),
			'line'  => $e->getLine(),
		),
		true
	);
}
