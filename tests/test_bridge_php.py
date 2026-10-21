"""Behavioral harness for wpt/wpbridge/bridge.php.

No WordPress installation is required: a stub wp-load.php doubles the
WordPress surface the bridge touches (a wpdb recording double with canned
SQL-pattern answers, an options store, plugin list, uploads dir), the bridge
is deployed with test token/expiry substitutions, and served by the PHP CLI
built-in server. Every wpdb/update_option/do_action call is appended to
wpt-stub-calls.log (one line per call) for assertions.
"""

import base64
import hashlib
import inspect
import json
import logging
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

import pytest
import requests

from wpt.settings import BridgeSettings
from wpt.sources.base import WalkMixin
from wpt.types import BridgeError, Entry, SourceError
from wpt.wpbridge import client as client_module
from wpt.wpbridge.client import Bridge

REPO = Path(__file__).resolve().parents[1]
BRIDGE_SOURCE = REPO / "wpt" / "wpbridge" / "bridge.php"
TOKEN = "0123456789abcdef0123456789abcdef"
EXPIRY_FUTURE = int(time.time()) + 3600
EXPIRY_PAST = 1_000_000_000  # 2001-09-09 — always in the past

# Doubles the WP APIs bridge.php calls after wp-load. The wpdb answers the
# exact SQL patterns the bridge emits; attachment 101 deliberately has NO
# _wp_attachment_metadata row (the L5 migrated-site case), 102 has a full
# size map. DELETEs touching the sentinel ID 424242 throw — the L4 probe.
WP_LOAD_STUB = r"""<?php
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}
if ( ! defined( 'WPMU_PLUGIN_DIR' ) ) {
	define( 'WPMU_PLUGIN_DIR', __DIR__ . '/wp-content/mu-plugins' );
}
if ( ! defined( 'WP_PLUGIN_DIR' ) ) {
	define( 'WP_PLUGIN_DIR', __DIR__ . '/wp-content/plugins' );
}
if ( ! defined( 'ARRAY_A' ) ) {
	define( 'ARRAY_A', 'ARRAY_A' );
}
if ( ! defined( 'ARRAY_N' ) ) {
	define( 'ARRAY_N', 'ARRAY_N' );
}
if ( ! defined( 'WP_DEBUG' ) ) {
	define( 'WP_DEBUG', true );
}

$GLOBALS['wpt_stub_options'] = array(
	'siteurl'        => 'https://example.test',
	'home'           => 'https://example.test',
	'template'       => 'twentytwentyfour',
	'stylesheet'     => 'twentytwentyfour',
	'blog_public'    => '1',
	'permalink_structure' => '/%year%/%monthnum%/%day%/%postname%/',
	'active_plugins' => array( 'akismet/akismet.php', 'litespeed-cache/litespeed-cache.php', 'hello.php' ),
	'WPLANG'         => 'fr_CA',
	// The WordPress DATABASE SCHEMA version (the stored db_version
	// option), distinct from the ENGINE version the wpdb double reports.
	// core_upgrade's migration moves THIS one; info reports it.
	'db_version'     => '56657',
);

// The $wp_db_version of the core THIS REQUEST LOADED.  On a real site
// wp-includes/version.php declares it at global scope during wp-load, so
// the op can read the migration TARGET before it starts — which is what
// its pre-migration marker records.  wpt-stub-upgrade-target names the
// version the "just-swapped" tree declares.
$GLOBALS['wp_db_version'] = trim( (string) @file_get_contents( __DIR__ . '/wpt-stub-upgrade-target' ) );
if ( '' === $GLOBALS['wp_db_version'] ) {
	$GLOBALS['wp_db_version'] = '60356';
}

// A CORRUPT options row: a non-string WPLANG / permalink_structure is
// what a tampered or badly-unserialized options value looks like, and
// core hands both to the op verbatim (see get_locale() below, and
// get_option()'s unserialization). String-casting one raises PHP's
// "Array to string conversion", which — with the bridge's display_errors
// on — is printed BEFORE the JSON and corrupts the whole answer
// (SPEC R12), taking every audit fact down with one bad row.
if ( file_exists( __DIR__ . '/wpt-stub-corrupt-options' ) ) {
	$GLOBALS['wpt_stub_options']['WPLANG'] = array( 'fr_CA' );
	$GLOBALS['wpt_stub_options']['permalink_structure'] = array( '/%postname%/' );
	$GLOBALS['wpt_stub_options']['siteurl'] = array( 'https://example.test' );
	$GLOBALS['wpt_stub_options']['home'] = array( 'https://example.test' );
	$GLOBALS['wpt_stub_options']['template'] = array( 'twentytwentyfour' );
	$GLOBALS['wpt_stub_options']['stylesheet'] = array( 'twentytwentyfour' );
	// An OBJECT-valued scalar option (a serialized option row): casting it
	// to int emits a PHP warning before the JSON under display_errors.
	$GLOBALS['wpt_stub_options']['blog_public'] = new stdClass();
}

$GLOBALS['wpt_stub_attached'] = array(
	array( 'post_id' => '101', 'meta_value' => '2023/10/pic.jpg' ),
	array( 'post_id' => '102', 'meta_value' => '2023/11/alt.png' ),
);

$GLOBALS['wpt_stub_attachment_meta'] = array(
	'102' => serialize( array(
		'file'  => '2023/11/alt.png',
		'sizes' => array(
			'thumbnail' => array( 'file' => 'alt-150x150.png', 'width' => 150, 'height' => 150 ),
			'custom'    => array( 'file' => '2023/11/alt-odd.png', 'width' => 320, 'height' => 240 ),
		),
	) ),
);

// The DATABASE half of the media keep-set (media_map mode=db).  A page
// renders only a fraction of its attachment images: on a real site
// (an observed run) most files / most of the media bytes were
// database-referenced and invisible to the live walk.  The stub answers
// the six read-only queries wpt_media_db_map() emits, one fixture per
// reference class: the attached-file rows (101, 102 and 106), the
// attachment metadata in BOTH stored size forms, the legacy
// _wp_attachment_backup_sizes key, a metadata row for post 107 whose
// ANCHOR does not exist (the deferral path), and the text scan classes.
$GLOBALS['wpt_stub_db_attached_extra'] = array(
	array( 'post_id' => '106', 'meta_value' => '2023/12/legacy.png' ),
	// An extension the SHIPPED family does not carry — the D1 scenario:
	// the shipped gate cannot name this file, so a profile the operator
	// widened to include "psd" (SPEC [L20]) would enumerate it and plan it
	// for deletion while the database references it.  The read carries the
	// caller's family, so asking with it keeps the row.
	array( 'post_id' => '108', 'meta_value' => '2023/01/design.psd' ),
);

$GLOBALS['wpt_stub_db_metadata'] = array(
	// 102: sizes stored BOTH ways - a bare basename and a full path
	array(
		'post_id'     => '102',
		'meta_value'  => serialize( array(
			'file'  => '2023/11/alt.png',
			'sizes' => array(
				'thumbnail' => array( 'file' => 'alt-150x150.png' ),
				'custom'    => array( 'file' => '2023/11/alt-odd.png' ),
			),
		) ),
	),
	// 106: the legacy backup-sizes key, a bare basename anchored to 106
	array(
		'post_id'     => '106',
		'meta_value'  => serialize( array(
			'file'  => '2023/12/legacy.png',
			'sizes' => array( 'full' => array( 'file' => 'legacy-1024x768.png' ) ),
		) ),
	),
	// 107: NO _wp_attached_file row -> the bare basename cannot be
	// anchored to a directory and must NOT be resolved into a wrong one
	array(
		'post_id'     => '107',
		'meta_value'  => serialize( array(
			'sizes' => array( 'orphan' => array( 'file' => 'orphan-150x150.png' ) ),
		) ),
	),
);

$GLOBALS['wpt_stub_db_postmeta_text'] = array(
	array( 'meta_value' => '{"bg":"https://example.test/wp-content/uploads/2024/01/bg.png"}' ),
	array( 'meta_value' => 'no uploads path in this row' ),
	// a plugin meta pointing at a DIRECTORY whose name carries a media
	// extension — a real shape (thumb caches), and the reason the ref gate
	// is not "has a dot in the name" alone.
	array( 'meta_value' => 'thumb cache: /wp-content/uploads/2024/05/thumbs.jpg' ),
);

// The media_rewrite_refs fixtures: the database SURFACES that hold a media
// reference, keyed by the surface's own primary key (so the same rows serve
// the read-only scan and the keyed read/write the apply does).  One row per
// load-bearing shape:
//   wp_posts[7]     a PLAIN post body (uploads URL) plus a GATED excerpt
//   wp_posts[8]     no reference at all -> the prefilter must not return it
//   wp_postmeta[11] a PHP-SERIALIZED value (the only thing that can rewrite
//                   an "s:NN:" length prefix server-side)
//   wp_postmeta[12] a plain postmeta value
//   wp_comments[5]  a GATED-only surface (comment content)
//   wp_usermeta[3]  a GATED-only surface (user meta)
//   wp_options[4]   a rewritable OPTION value
//   wp_termmeta[6]  a GATED-only surface (term meta)
$GLOBALS['wpt_stub_ref_rewrite'] = array(
	'wp_posts' => array(
		'7' => array(
			'ID'           => '7',
			'post_content' => '<p><img src="https://example.test/wp-content/uploads/2023/10/pic.jpg" /></p>',
			'post_excerpt' => 'cover: wp-content/uploads/2023/10/pic-300x233.jpg',
		),
		'8' => array(
			'ID'           => '8',
			'post_content' => 'a plain paragraph with no image in it',
			'post_excerpt' => '',
		),
	),
	'wp_postmeta' => array(
		'11' => array(
			'meta_id'    => '11',
			'post_id'    => '7',
			'meta_value' => serialize( array(
				'sizes' => array(
					'thumbnail' => array( 'file' => '2023/10/pic-150x150.jpg' ),
				),
				'note' => 'see wp-content/uploads/2023/10/pic.jpg',
			) ),
		),
		'12' => array(
			'meta_id'    => '12',
			'post_id'    => '7',
			'meta_value' => 'https://example.test/wp-content/uploads/2023/10/pic.jpg',
		),
	),
	'wp_options' => array(
		// a SERIALIZED autoloaded theme option: the shape that makes the
		// server-side rewrite the only possible one (its "s:33:" byte
		// length has to be recomputed when the reference moves)
		'4' => array(
			'option_id'    => '4',
			'option_name'  => 'theme_mods_avada',
			'autoload'     => 'yes',
			'option_value' => serialize( array(
				'background_image' => '/wp-content/uploads/2023/10/pic.jpg',
			) ),
		),
	),
	'wp_comments' => array(
		'5' => array(
			'comment_ID'         => '5',
			'comment_content'    => 'look at wp-content/uploads/2023/11/alt.png',
			'comment_author_url' => 'https://example.test/wp-content/uploads/2023/11/alt.png',
		),
	),
	'wp_usermeta' => array(
		'3' => array(
			'umeta_id'   => '3',
			'user_id'    => '1',
			'meta_value' => 'https://example.test/wp-content/uploads/2024/03/category.jpg',
		),
	),
	'wp_termmeta' => array(
		'6' => array(
			'meta_id'    => '6',
			'term_id'    => '4',
			'meta_value' => 'wp-content/uploads/2024/04/term.jpg',
		),
	),
);

// The WordPress schema the surfaces are resolved against: table name =>
// its real columns.  The bridge derives every identifier it interpolates
// from information_schema (wpt_table_columns), so a surface can only be
// used when these columns exist.
$GLOBALS['wpt_stub_wp_columns'] = array(
	'wp_posts'    => array( 'ID', 'post_author', 'post_date', 'post_content', 'post_title', 'post_excerpt', 'post_status', 'post_name', 'post_modified', 'post_parent', 'guid', 'menu_order', 'post_type', 'post_mime_type', 'comment_count' ),
	'wp_postmeta' => array( 'meta_id', 'post_id', 'meta_key', 'meta_value' ),
	'wp_options'  => array( 'option_id', 'option_name', 'option_value', 'autoload' ),
	'wp_comments' => array( 'comment_ID', 'comment_post_ID', 'comment_author', 'comment_author_url', 'comment_content', 'comment_date' ),
	'wp_users'    => array( 'ID', 'user_login', 'user_email', 'user_pass', 'user_url', 'user_registered' ),
	'wp_usermeta' => array( 'umeta_id', 'user_id', 'meta_key', 'meta_value' ),
	'wp_termmeta' => array( 'meta_id', 'term_id', 'meta_key', 'meta_value' ),
);

// The media_map(mode=db) fixture grown with the observed defect: a
// stale _transient_dirsize_cache option holding absolute paths to the
// site's PREVIOUS host, several of them bare YEAR DIRECTORIES.  One such row
// used to make the client reject the whole answer and disable the union
// keep-set for the site.  The rows also cover the other refusal classes:
// an old-host path with a valid tail (kept, as its uploads-relative form),
// an old-host path with a junk tail, a non-media extension, and a media
// path carrying a query string.
$GLOBALS['wpt_stub_db_dirsize'] = array(
	'/home/hostaccount/public_html/wp-content/uploads/2018',
	'/home/hostaccount/public_html/wp-content/uploads/2019',
	'/home/hostaccount/public_html/wp-content/uploads/2020',
	'/home/hostaccount/public_html/wp-content/uploads/2021',
	'/home/hostaccount/public_html/wp-content/uploads/2022',
	'/home/hostaccount/public_html/wp-content/uploads/2023',
	// a real file on the previous host: the tail IS this site's path
	'/home/hostaccount/public_html/wp-content/uploads/2023/10/pic.jpg',
	// no uploads anchor at all
	'/home/hostaccount/public_html/wp-images/logo.png',
	// a traversing tail
	'/home/hostaccount/public_html/wp-content/uploads/../../evil.jpg',
	// a non-media extension
	'/home/hostaccount/public_html/wp-content/uploads/2023/10/notes.txt.php',
	// a cache-busting query on a real media path
	'/home/hostaccount/public_html/wp-content/uploads/2023/10/pic.jpg?ver=3',
);

$GLOBALS['wpt_stub_db_posts'] = array(
	array(
		'post_content' => '<p><a href="/wp-content/uploads/2023/11/brochure.pdf">PDF</a></p>',
		'post_excerpt' => 'see wp-content/uploads/2023/11/gallery-1.jpg, more',
		'post_guid'    => 'https://example.test/wp-content/uploads/2023/11/guid-only.jpg',
	),
);

$GLOBALS['wpt_stub_db_options'] = array(
	array( 'option_value' => serialize( array( 'logo' => 'https://example.test/wp-content/uploads/2024/02/logo.png' ) ) ),
	// The stale _transient_dirsize_cache of a site migrated off another
	// host (measured live on a real site): several absolute paths to the PREVIOUS
	// host, several of them bare YEAR DIRECTORIES.  Serialized, so the extractor
	// reads them out of the string leaves like any other option value.
	array( 'option_value' => serialize( $GLOBALS['wpt_stub_db_dirsize'] ) ),
);

$GLOBALS['wpt_stub_db_termmeta'] = array(
	array( 'meta_value' => '/wp-content/uploads/2024/03/category.jpg' ),
);

$GLOBALS['wpt_stub_rows'] = array(
	array( '1', 'hello' ),
	array( '2', 'wörld' ),
);

// wp_users rows + per-user roles, for the users_reset op. Deterministic and
// ordered by ID, exactly as the op's ORDER BY ID query returns them.
$GLOBALS['wpt_stub_users'] = array(
	array( 'ID' => '1', 'user_login' => 'admin', 'user_email' => 'admin@example.test' ),
	array( 'ID' => '2', 'user_login' => 'editor', 'user_email' => 'editor@example.test' ),
	array( 'ID' => '7', 'user_login' => 'author', 'user_email' => 'author@legacy.test' ),
);
// A latin-1-migrated database row: ONE login with an invalid UTF-8 byte
// (the other rows stay valid).  users_reset must skip that row before any
// write (never publish a substituted login while revoking its password)
// and continue the valid users.  user_create still returns its live
// credential because only the EMAIL read-back is invalid there.
if ( @is_file( __DIR__ . '/wpt-stub-user-invalid-utf8' ) ) {
	$GLOBALS['wpt_stub_users'][0]['user_login'] =
		$GLOBALS['wpt_stub_users'][0]['user_login'] . "\xff";
	$GLOBALS['wpt_stub_users'][0]['user_email'] =
		'invalid-1' . "\xff" . '@example.test';
}
$GLOBALS['wpt_stub_roles'] = array(
	'1' => array( 'administrator' ),
	'2' => array( 'editor' ),
	// WP_User::set_role() leaves $roles as a name => true MAP (not the
	// plain list WP_User::init() builds), so one fixture carries the shape
	// core itself produces and the op must still report role NAMES.
	'7' => array( 'author' => true, 'subscriber' => true ),
);

// A same-suffix LOOK-ALIKE table, modelled by the wpt-stub-decoy-options
// marker: "wp_myoptions" ends with "options" exactly like the real options
// table, so a suffix-first resolution would scan and rewrite the WRONG
// table.  It is registered FIRST so a suffix-first implementation picks it.
if ( @is_file( __DIR__ . '/wpt-stub-decoy-options' ) ) {
	$GLOBALS['wpt_stub_wp_columns'] = array_merge(
		array( 'wp_myoptions' => array( 'option_id', 'option_name', 'option_value', 'autoload' ) ),
		$GLOBALS['wpt_stub_wp_columns']
	);
	$GLOBALS['wpt_stub_ref_rewrite']['wp_myoptions'] = array(
		'99' => array(
			'option_id'    => '99',
			'option_name'  => 'decoy',
			'autoload'     => 'no',
			'option_value' => 'url("/wp-content/uploads/2023/10/decoy.jpg")',
		),
	);
}

// File-backed store for the media_rewrite_refs surface rows.  The op
// READS a row, WRITES it and then RE-READS it, and every bridge call is a
// separate HTTP request (fresh PHP state), so a write has to be visible to
// the re-read AND to the test: the file is the honest model of a table.
// Seeded from $GLOBALS['wpt_stub_ref_rewrite'] on first use.
function wpt_stub_ref_rows_file() {
	return __DIR__ . '/wpt-stub-ref-rows.json';
}
function wpt_stub_load_ref_rows() {
	$f = wpt_stub_ref_rows_file();
	if ( @is_file( $f ) ) {
		$j = json_decode( (string) @file_get_contents( $f ), true );
		if ( is_array( $j ) ) {
			return $j;
		}
	}
	$seed = array();
	foreach ( $GLOBALS['wpt_stub_ref_rewrite'] as $table => $rows ) {
		$seed[ $table ] = $rows;
	}
	@file_put_contents( $f, json_encode( $seed ) );
	return $seed;
}
function wpt_stub_save_ref_rows( $rows ) {
	@file_put_contents( wpt_stub_ref_rows_file(), json_encode( $rows ) );
}

// The table whose reference-scan SELECT FAILS ('' when no marker): a
// mid-stream failure, which is the only way a streaming op can find out
// something is wrong AFTER its first rows are on the wire.
function wpt_stub_ref_scan_failure() {
	$f = __DIR__ . '/wpt-stub-ref-scan-fails';
	return @is_file( $f ) ? trim( (string) @file_get_contents( $f ) ) : '';
}

function wpt_stub_rec( $line ) {
	$GLOBALS['wpt_stub_calls'][] = $line;
	@file_put_contents( __DIR__ . '/wpt-stub-calls.log', $line . "\n", FILE_APPEND );
	return $line;
}

if ( ! isset( $GLOBALS['wpt_stub_calls'] ) ) {
	$GLOBALS['wpt_stub_calls'] = array();
}

// File-backed live table registry. Each bridge call is a separate HTTP
// request (fresh PHP state), so the atomic-restore staging guard needs its
// table state to persist ACROSS calls to be honestly exercised. Mirrors the
// real server: CREATE adds, DROP removes, RENAME moves.
function wpt_stub_tables_file() {
	return __DIR__ . '/wpt-stub-tables.json';
}
function wpt_stub_load_tables() {
	$f = wpt_stub_tables_file();
	if ( @is_file( $f ) ) {
		$j = json_decode( (string) @file_get_contents( $f ), true );
		if ( is_array( $j ) ) {
			return $j;
		}
	}
	$base = array( 'wpt_rows', 'wpt_flat', 'wp_posts' );
	// A legitimate user table whose name happens to look scratch-shaped but
	// carries a DIFFERENT token than this restore. It lives in the REGISTRY,
	// so if a restore ever DROPped it, the file would lose it (proving
	// ownership is by the exact restore_id token, not a name pattern).
	if ( @is_file( __DIR__ . '/wpt-stub-user-scratch-table' ) ) {
		$base[] = 'wpt_rows__wpt_deadbeefdeadbeef__s';
	}
	@file_put_contents( $f, json_encode( $base ) );
	return $base;
}
function wpt_stub_save_tables( $tables ) {
	@file_put_contents( wpt_stub_tables_file(), json_encode( array_values( $tables ) ) );
}

// Per-table staged row counter so the atomic-restore completeness check
// (COUNT(staging) == declared total_rows) is a REAL assertion, not a canned 0.
function wpt_stub_counts_file() {
	return __DIR__ . '/wpt-stub-counts.json';
}
function wpt_stub_load_counts() {
	$f = wpt_stub_counts_file();
	if ( @is_file( $f ) ) {
		$j = json_decode( (string) @file_get_contents( $f ), true );
		if ( is_array( $j ) ) {
			return $j;
		}
	}
	return array();
}
function wpt_stub_set_count( $table, $n ) {
	$c = wpt_stub_load_counts();
	$c[ $table ] = (int) $n;
	@file_put_contents( wpt_stub_counts_file(), json_encode( $c ) );
}
function wpt_stub_bump_count( $table, $by ) {
	$c = wpt_stub_load_counts();
	$c[ $table ] = ( isset( $c[ $table ] ) ? (int) $c[ $table ] : 0 ) + (int) $by;
	@file_put_contents( wpt_stub_counts_file(), json_encode( $c ) );
}

class WPT_Stub_wpdb {
	public $posts              = 'wp_posts';
	public $postmeta           = 'wp_postmeta';
	public $termmeta           = 'wp_termmeta';
	public $commentmeta        = 'wp_commentmeta';
	public $term_relationships = 'wp_term_relationships';
	public $comments           = 'wp_comments';
	public $terms              = 'wp_terms';
	public $options            = 'wp_options';
	public $users              = 'wp_users';
	public $usermeta           = 'wp_usermeta';
	public $prefix             = 'wp_';
	public $last_error         = '';

	public function db_version() {
		return '8.0.36';
	}

	public function prepare( $query, ...$args ) {
		if ( 1 === count( $args ) && is_array( $args[0] ) ) {
			$args = $args[0];
		}
		$i = 0;
		$prepared = preg_replace_callback(
			'/%[sdf]/',
			function ( $m ) use ( &$i, $args ) {
				if ( $i >= count( $args ) ) {
					return $m[0];
				}
				$v = $args[ $i++ ];
				if ( '%d' === $m[0] ) {
					return (string) (int) $v;
				}
				if ( '%f' === $m[0] ) {
					return (string) (float) $v;
				}
				return "'" . str_replace( array( '\\', "'" ), array( '\\\\', "\\'" ), (string) $v ) . "'";
			},
			$query
		);
		// The substituted arguments, so query() can act on an UPDATE's
		// bound value (and its row id) without re-parsing SQL string
		// literals — the stub never has to un-escape a quote correctly.
		$GLOBALS['wpt_stub_prepared'] = array( 'sql' => $prepared, 'args' => $args );
		return $prepared;
	}

	public function get_var( $sql ) {
		wpt_stub_rec( $sql );
		// Simulated COUNT-query failure: the wpt-stub-count-fails marker makes
		// the revisions count return null, so db_audit must report UNKNOWN
		// (null) for that field rather than a false measured 0.
		if ( @is_file( __DIR__ . '/wpt-stub-count-fails' ) && false !== strpos( $sql, 'auto-draft' ) ) {
			return null;
		}
		// FK / trigger presence for the atomic-restore swap guard. 0 (safe)
		// by default; the marker files let a test make db_restore_table
		// refuse the swap the way a real plugin-added FK would.
		if ( false !== strpos( $sql, 'REFERENTIAL_CONSTRAINTS' ) ) {
			if ( @is_file( __DIR__ . '/wpt-stub-fk-unreadable' ) ) {
				return null;  // models an unreadable metadata query
			}
			return @is_file( __DIR__ . '/wpt-stub-has-fk' ) ? '1' : '0';
		}
		// media_rewrite_refs' cache invalidation: the owner id of a
		// meta row (post_id / term_id), read the way core would.
		if ( preg_match( '/^SELECT `(post_id|term_id)` FROM `([^`]+)` WHERE `(meta_id|umeta_id)` = (\\d+)$/', trim( $sql ), $own ) ) {
			$rows = wpt_stub_load_ref_rows();
			$id   = $own[4];
			if ( ! isset( $rows[ $own[2] ][ $id ] ) ) {
				return null;
			}
			return isset( $rows[ $own[2] ][ $id ][ $own[1] ] ) ? $rows[ $own[2] ][ $id ][ $own[1] ] : null;
		}
		if ( false !== strpos( $sql, 'information_schema.TRIGGERS' ) ) {
			return @is_file( __DIR__ . '/wpt-stub-has-trigger' ) ? '1' : '0';
		}
		// users_reset's post-write recovery: re-read the live hash the same
		// way core's wp_set_password() stored it (the cached WP_User carries
		// the hash in this harness).
		if ( false !== strpos( $sql, 'user_pass' )
			&& preg_match( '/WHERE ID = (\d+)/', $sql, $user_match ) ) {
			$user = get_userdata( (int) $user_match[1] );
			return $user ? $user->user_pass : null;
		}
		// Table-existence count (the atomic-restore staging guard): reads the
		// file-backed registry so the guard sees REAL cross-request state.
		// MySQL advisory lock (serializes concurrent same-restore requests).
		if ( false !== strpos( $sql, 'GET_LOCK' ) || false !== strpos( $sql, 'RELEASE_LOCK' ) ) {
			return '1';
		}
		if ( false !== strpos( $sql, 'information_schema.TABLES' ) && preg_match( "/TABLE_NAME = '([^']+)'/", $sql, $tm ) ) {
			return in_array( $tm[1], wpt_stub_load_tables(), true ) ? '1' : '0';
		}
		// Staged-row count for the atomic-restore completeness check:
		// SELECT COUNT(*) FROM `<staging>` -> the real tracked count.
		if ( preg_match( "/SELECT COUNT\(\*\) FROM `([^`]+)`/", $sql, $cm ) ) {
			$counts = wpt_stub_load_counts();
			return (string) ( isset( $counts[ $cm[1] ] ) ? (int) $counts[ $cm[1] ] : 0 );
		}
		if ( false !== strpos( $sql, '_wp_attachment_metadata' ) ) {
			preg_match( "/post_id = '?(\d+)'?/", $sql, $m );
			$pid = isset( $m[1] ) ? $m[1] : '';
			return isset( $GLOBALS['wpt_stub_attachment_meta'][ $pid ] ) ? $GLOBALS['wpt_stub_attachment_meta'][ $pid ] : null;
		}
		if ( false !== strpos( $sql, 'LEFT JOIN' ) ) {
			if ( false !== strpos( $sql, 'wp_postmeta' ) ) {
				return '4';
			}
			if ( false !== strpos( $sql, 'wp_termmeta' ) ) {
				return '1';
			}
			if ( false !== strpos( $sql, 'wp_commentmeta' ) ) {
				return '2';
			}
			return '0';
		}
		if ( false !== strpos( $sql, '_transient_' ) ) {
			return '2';
		}
		if ( false !== strpos( $sql, 'auto-draft' ) ) {
			return '5';
		}
		if ( false !== strpos( $sql, 'autoload' ) ) {
			return '123456';
		}
		return '0';
	}

	// The canned answers below are column-keyed; get_results() shapes them
	// per $output the way core does, so a caller that forgets ARRAY_A gets
	// row OBJECTS (and a fatal on array access) exactly as it would on a
	// live site. A stub that always answered ARRAY_A would let that class
	// of bug pass here and break in production.
	public function get_results( $sql, $output = 'OBJECT' ) {
		wpt_stub_rec( $sql );
		return $this->wpt_shape( $this->wpt_rows( $sql ), $output );
	}

	private function wpt_shape( $rows, $output ) {
		if ( ! is_array( $rows ) ) {
			return $rows;
		}
		if ( 'ARRAY_A' === $output ) {
			return $rows;
		}
		$out = array();
		foreach ( $rows as $row ) {
			$out[] = ( 'ARRAY_N' === $output )
				? array_values( (array) $row )
				: (object) $row;
		}
		return $out;
	}

	private function wpt_rows( $sql ) {
		// media_rewrite_refs: the reference scan.  The stub models the
		// collation-insensitive prefilter (LOWER(col) LIKE '%.jpg%' OR ...)
		// rather than ignoring it, so the harness's rows are the rows a
		// real site's WHERE clause returns.
		if ( false !== strpos( $sql, "LIKE '%.jpg%'" ) ) {
			preg_match( '/SELECT (.+?) FROM `([^`]+)`/s', $sql, $scan );
			// A FAILED statement part way through the scan: the marker names
			// the table whose SELECT answers null (a lock wait, a dead
			// connection, a killed statement).  Every surface BEFORE it has
			// already streamed its rows, which is the whole point — the op
			// has to answer this failure with the rows already on the wire.
			$broken = wpt_stub_ref_scan_failure();
			if ( '' !== $broken && $broken === $scan[2] ) {
				// A driver failure whose MESSAGE is the site's own bytes: the
				// wpt-stub-ref-scan-error marker holds it RAW, which is how a
				// real one reaches PHP (a latin1 table or column name echoed
				// back in the error).  The op's own failure line has to
				// survive that; the ASCII-only message this stub invents
				// otherwise would prove nothing about the encoder.
				$hostile = __DIR__ . '/wpt-stub-ref-scan-error';
				if ( @is_file( $hostile ) ) {
					throw new RuntimeException( (string) @file_get_contents( $hostile ) );
				}
				return null;
			}
			$columns = array();
			foreach ( explode( ',', $scan[1] ) as $column ) {
				$columns[] = trim( str_replace( '`', '', $column ) );
			}
			$rows = wpt_stub_load_ref_rows();
			$out  = array();
			foreach ( ( isset( $rows[ $scan[2] ] ) ? $rows[ $scan[2] ] : array() ) as $row ) {
				foreach ( $columns as $column ) {
					if ( isset( $row[ $column ] )
						&& preg_match( '/\.(?:jpg|jpeg|png)/i', (string) $row[ $column ] ) ) {
						$out[] = $row;
						continue 2;
					}
				}
			}
			return $out;
		}
		if ( false !== strpos( $sql, 'information_schema' ) && false !== strpos( $sql, 'TABLE_TYPE' ) ) {
			// The table list comes from the live registry so any restore
			// scratch table the stub created is actually visible here — the
			// bridge's own filter is what must hide it.
			$rows = array(
				array( 'name' => 'wp_options', 'row_count' => '42', 'size_mb' => '0.5', 'data_free_kb' => '8.0', 'collation' => 'utf8mb4_general_ci' ),
				array( 'name' => 'wp_posts', 'row_count' => '7', 'size_mb' => '1.25', 'data_free_kb' => '32.0', 'collation' => 'latin1_swedish_ci' ),
				array( 'name' => 'wp_comments', 'row_count' => '0', 'size_mb' => '0.03', 'data_free_kb' => '0.0', 'collation' => null ),
			);
			foreach ( wpt_stub_load_tables() as $t ) {
				$rows[] = array( 'name' => $t, 'row_count' => '1', 'size_mb' => '0.1', 'data_free_kb' => '0.0', 'collation' => 'utf8mb4_general_ci' );
			}
			return $rows;
		}
		if ( false !== strpos( $sql, 'user_level' ) ) {
			// db_audit admin-user query: admins only (user_level = 10),
			// login-ordered, one row with a NULL registration date.
			return array(
				array( 'login' => 'admin', 'registered' => '2019-05-14 09:30:00' ),
				array( 'login' => 'legacy', 'registered' => null ),
				array( 'login' => 'site_owner', 'registered' => '2020-01-02 03:04:05' ),
			);
		}
		if ( false !== strpos( $sql, 'GROUP BY post_type, post_status' ) ) {
			return array(
				array( 'post_type' => 'post', 'post_status' => 'publish', 'n' => '3' ),
				array( 'post_type' => 'attachment', 'post_status' => 'inherit', 'n' => '7' ),
				array( 'post_type' => 'revision', 'post_status' => 'inherit', 'n' => '5' ),
			);
		}
		if ( false !== strpos( $sql, "'attachment', 'nav_menu_item'" ) ) {
			return array(
				array( 'post_type' => 'attachment', 'n' => '7' ),
				array( 'post_type' => 'nav_menu_item', 'n' => '2' ),
			);
		}
		if ( false !== strpos( $sql, '_wp_attached_file' ) ) {
			return array_merge( $GLOBALS['wpt_stub_attached'], $GLOBALS['wpt_stub_db_attached_extra'] );
		}
		// media_map(mode=db): the attachment size maps, both keys at once
		if ( false !== strpos( $sql, '_wp_attachment_metadata' ) ) {
			return $GLOBALS['wpt_stub_db_metadata'];
		}
		if ( false !== strpos( $sql, 'wp_termmeta' ) ) {
			return $GLOBALS['wpt_stub_db_termmeta'];
		}
		if ( false !== strpos( $sql, 'wp_options' ) && false !== strpos( $sql, 'option_value' ) ) {
			return $GLOBALS['wpt_stub_db_options'];
		}
		if ( false !== strpos( $sql, 'post_content' ) ) {
			return $GLOBALS['wpt_stub_db_posts'];
		}
		if ( false !== strpos( $sql, 'wp-content/uploads' ) ) {
			return $GLOBALS['wpt_stub_db_postmeta_text'];
		}
		if ( false !== strpos( $sql, 'SELECT ID, user_login, user_email' ) ) {
			// users_reset's user inventory. The marker models a FAILED
			// query (null), which the op must refuse rather than read as
			// "this site has no users".
			if ( @is_file( __DIR__ . '/wpt-stub-users-query-fails' ) ) {
				return null;
			}
			return $GLOBALS['wpt_stub_users'];
		}
		if ( false !== strpos( $sql, 'FROM `wpt_rows`' ) ) {
			$limit  = 1000000;
			$offset = 0;
			if ( preg_match( '/LIMIT (\d+)(?: OFFSET (\d+))?/', $sql, $m ) ) {
				$limit  = (int) $m[1];
				$offset = isset( $m[2] ) ? (int) $m[2] : 0;
			}
			return array_slice( $GLOBALS['wpt_stub_rows'], $offset, $limit );
		}
		if ( false !== strpos( $sql, 'FROM `wpt_flat`' ) ) {
			return array( array( 'x', 'y' ) );
		}
		return array();
	}

	public function get_col( $sql ) {
		wpt_stub_rec( $sql );
		if ( false !== strpos( $sql, 'information_schema.COLUMNS' ) ) {
			preg_match( "/TABLE_NAME = '([^']+)'/", $sql, $m );
			$table = isset( $m[1] ) ? $m[1] : '';
			// The WordPress schema the media_rewrite_refs surfaces are
			// resolved against: a surface is only used when every column
			// it reads really exists.
			if ( isset( $GLOBALS['wpt_stub_wp_columns'][ $table ] ) ) {
				return $GLOBALS['wpt_stub_wp_columns'][ $table ];
			}
			return ( 'wpt_rows' === $table ) ? array( 'id', 'name' ) : array( 'a', 'b' );
		}
		if ( false !== strpos( $sql, 'KEY_COLUMN_USAGE' ) ) {
			preg_match( "/TABLE_NAME = '([^']+)'/", $sql, $m );
			$table = isset( $m[1] ) ? $m[1] : '';
			return ( 'wpt_rows' === $table ) ? array( 'id' ) : array();
		}
		if ( false !== strpos( $sql, 'information_schema.TABLES' ) ) {
			// The whitelist every interpolated identifier is checked
			// against: the WordPress tables the rewrite op resolves its
			// surfaces from, plus the live scratch-table registry.
			$tables = array_values( array_unique( array_merge(
				array_keys( $GLOBALS['wpt_stub_wp_columns'] ),
				wpt_stub_load_tables()
			) ) );
			// The wpt-stub-long-name marker adds a >51-char table so a test can
			// exercise the atomic-restore identifier bound without changing
			// the table count other tests assert on.
			if ( @is_file( __DIR__ . '/wpt-stub-long-name' ) ) {
				$tables[] = 'wpt_' . str_repeat( 'x', 48 );
			}
			return $tables;
		}
		return array();
	}

	public function get_row( $sql, $output = 'OBJECT' ) {
		wpt_stub_rec( $sql );
		// A keyed single-row read (media_rewrite_refs' read/re-read, and
		// the option_name/autoload lookup its cache invalidation needs):
		// core answers a row that is not there with null, which the op
		// must report as "row not found" rather than read as an empty
		// value.
		if ( preg_match( '/^SELECT (.+?) FROM `([^`]+)` WHERE `([^`]+)` = (\\d+)$/', trim( $sql ), $read ) ) {
			$columns = array();
			foreach ( explode( ',', $read[1] ) as $column ) {
				$columns[] = trim( str_replace( '`', '', $column ) );
			}
			$rows = wpt_stub_load_ref_rows();
			$id   = $read[4];
			if ( ! isset( $rows[ $read[2] ][ $id ] ) ) {
				return null;
			}
			$out = array();
			foreach ( $columns as $column ) {
				$out[ $column ] = isset( $rows[ $read[2] ][ $id ][ $column ] )
					? $rows[ $read[2] ][ $id ][ $column ] : null;
			}
			// get_row answers with THE ROW, shaped per $output (not with a
			// list of rows the way get_results does).
			if ( 'ARRAY_N' === $output ) {
				return array_values( $out );
			}
			return ( 'ARRAY_A' === $output ) ? $out : (object) $out;
		}
		if ( 0 === strpos( $sql, 'SHOW CREATE TABLE `wpt_rows`' ) ) {
			return array( 'wpt_rows', "CREATE TABLE `wpt_rows` (\n  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,\n  `name` varchar(200) NOT NULL DEFAULT '',\n  PRIMARY KEY (`id`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4" );
		}
		// A DDL read that fails part way through a db_dump stream: the
		// wpt-stub-dump-table-fails marker names the table whose SHOW CREATE
		// answers nothing, so the op has to fail with rows already out.
		if ( preg_match( '/^SHOW CREATE TABLE `([^`]+)`$/', trim( $sql ), $ddl ) ) {
			$broken = __DIR__ . '/wpt-stub-dump-table-fails';
			if ( @is_file( $broken )
				&& trim( (string) @file_get_contents( $broken ) ) === $ddl[1] ) {
				return null;
			}
		}
		if ( 0 === strpos( $sql, 'SHOW CREATE TABLE `wpt_flat`' ) ) {
			return array( 'wpt_flat', "CREATE TABLE `wpt_flat` (\n  `a` varchar(10) DEFAULT NULL,\n  `b` varchar(10) DEFAULT NULL\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4" );
		}
		return null;
	}

	public function query( $sql ) {
		wpt_stub_rec( $sql );
		// The TOCTOU seam for media_delete: the op validates every path,
		// THEN runs its DB transaction, THEN unlinks — so a real attacker
		// with write access inside uploads gets a window as wide as the
		// whole transaction. The wpt-stub-swap-on-commit marker fires the
		// swap exactly there (a rename of the validated parent directory
		// aside plus a symlink in its place, both scripted in the swap
		// file), which makes the race deterministic instead of timed.
		if ( 'COMMIT' === $sql && @is_file( __DIR__ . '/wpt-stub-swap-on-commit' ) ) {
			$swap = json_decode( (string) @file_get_contents( __DIR__ . '/wpt-stub-swap-on-commit' ), true );
			if ( is_array( $swap ) ) {
				if ( ! empty( $swap['dir'] ) && ! empty( $swap['link_to'] ) ) {
					@rename( $swap['dir'], $swap['dir'] . '.moved' );
					@symlink( $swap['link_to'], $swap['dir'] );
				}
				if ( ! empty( $swap['replace'] ) ) {
					// Same path, different file (the device/inode half of
					// the re-check).
					//
					// A TEMP FILE RENAMED ONTO THE PATH, not
					// unlink-then-create: an unlink frees the inode, and
					// the next create at the same path very often gets the
					// SAME inode back — which is exactly the identity the
					// re-check compares, so the seam modelled "a different
					// file" as "the same inode" and the test it feeds
					// became a coin flip (measured: 6 of 8 runs failed on
					// the pristine tree, before any change of ours).  A
					// rename gives the path the SOURCE file's inode, which
					// is a different inode by construction.
					$staged = $swap['replace'] . '.wpt-swap-staged';
					@file_put_contents( $staged, "wpt-swap-replacement\n" );
					@rename( $staged, $swap['replace'] );
				}
				if ( ! empty( $swap['unlink'] ) ) {
					// The same path, simply gone: the re-check's 'gone'
					// verdict, which must be tolerated, not refused.
					@unlink( $swap['unlink'] );
				}
			}
			wpt_stub_rec( 'swap-on-commit' );
		}
		if ( false !== strpos( $sql, 'DELETE' ) && false !== strpos( $sql, '424242' ) ) {
			throw new RuntimeException( 'stub: sentinel attachment 424242 refuses deletion (L4 probe)' );
		}
		// media_rewrite_refs(apply): the reference rewrite's own UPDATE,
		// applied to the file-backed store so the op's RE-READ is a real
		// read.  The bound value and row id come from the prepare() that
		// produced this statement.
		if ( 0 === strpos( $sql, 'UPDATE ' )
			&& preg_match( '/^UPDATE `([^`]+)` SET `([^`]+)`/', $sql, $up )
			&& isset( $GLOBALS['wpt_stub_prepared'] )
			&& $GLOBALS['wpt_stub_prepared']['sql'] === $sql ) {
			$args = $GLOBALS['wpt_stub_prepared']['args'];
			$rows = wpt_stub_load_ref_rows();
			$id   = (string) (int) $args[1];
			if ( ! isset( $rows[ $up[1] ][ $id ] ) ) {
				return false;   // a row that does not exist
			}
			if ( @is_file( __DIR__ . '/wpt-stub-rewrite-write-fails' ) ) {
				return false;   // a refused statement (deadlock, lock wait)
			}
			if ( ! @is_file( __DIR__ . '/wpt-stub-rewrite-write-lies' ) ) {
				// The silent no-op WRITE the re-read exists to catch: the
				// statement succeeds and the row keeps its old value (a
				// stale replica, a swallowed error, a rolled-back
				// transaction).  wpt-stub-rewrite-write-lies models it.
				$rows[ $up[1] ][ $id ][ $up[2] ] = (string) $args[0];
				wpt_stub_save_ref_rows( $rows );
			}
			return 1;
		}
		// DDL bookkeeping so the atomic-restore staging guard sees real table
		// state: CREATE adds, DROP removes, RENAME moves.
		if ( 0 === strpos( $sql, 'CREATE TABLE' )
			&& preg_match( '/CREATE TABLE `([^`]+)`/', $sql, $m ) ) {
			$t = wpt_stub_load_tables();
			$t[] = $m[1];
			wpt_stub_save_tables( $t );
			wpt_stub_set_count( $m[1], 0 );
			return 0;
		}
		if ( 0 === strpos( $sql, 'DROP TABLE' )
			&& preg_match( '/DROP TABLE (?:IF EXISTS )?`([^`]+)`/', $sql, $m ) ) {
			if ( @is_file( __DIR__ . '/wpt-stub-drop-fails' ) ) {
				return false;  // models a cleanup DROP the server refuses
			}
			$t = array_values( array_diff( wpt_stub_load_tables(), array( $m[1] ) ) );
			wpt_stub_save_tables( $t );
			return 0;
		}
		if ( 0 === strpos( $sql, 'RENAME TABLE' ) ) {
			// A multi-table RENAME is atomic: every source must exist, else
			// the whole statement fails. Each source MOVES to its destination.
			preg_match_all( '/`([^`]+)` TO `([^`]+)`/', $sql, $ren, PREG_SET_ORDER );
			$tables = wpt_stub_load_tables();
			foreach ( $ren as $pair ) {
				if ( ! in_array( $pair[1], $tables, true ) ) {
					return false;
				}
			}
			foreach ( $ren as $pair ) {
				$tables   = array_values( array_diff( $tables, array( $pair[1] ) ) );
				$tables[] = $pair[2];
			}
			wpt_stub_save_tables( $tables );
			return 0;
		}
		if ( 0 === strpos( $sql, 'INSERT' )
			&& preg_match( '/INSERT INTO `([^`]+)`/', $sql, $m ) ) {
			// one row per VALUES tuple
			wpt_stub_bump_count( $m[1], substr_count( $sql, '), (' ) + 1 );
			return 2;
		}
		if ( 0 === strpos( $sql, 'DELETE' ) ) {
			return 1;
		}
		return 0;
	}
}

// File-backed active_plugins store: each bridge call is a separate HTTP
// request (fresh PHP state), so a WRITE (update_option) would otherwise be
// invisible to the verification READ that follows it. Only the
// wpt-stub-active-plugins.json marker activates the persistence — every
// other test keeps the in-memory option store.
function wpt_stub_active_plugins_file() {
	return __DIR__ . '/wpt-stub-active-plugins.json';
}

// The pre-migration marker core_upgrade writes BEFORE it migrates.  It is
// the one option whose whole purpose is to SURVIVE the request that wrote
// it — a non-catchable PHP fatal inside wp_upgrade() destroys that
// request, and the marker is then the only account of the state the
// migration began in.  So it gets the same file-backed store as
// db_version: each bridge call is a separate HTTP request with fresh PHP
// state, exactly like a real options table.
function wpt_stub_marker_file() {
	return __DIR__ . '/wpt-stub-marker.json';
}

function get_option( $name, $default = false ) {
	if ( 'wpt_core_upgrade' === $name ) {
		$file = wpt_stub_marker_file();
		if ( @is_file( $file ) ) {
			$j = json_decode( (string) @file_get_contents( $file ), true );
			return is_array( $j ) ? $j : $default;
		}
		return $default;
	}
	if ( 'db_version' === $name ) {
		if ( @is_file( __DIR__ . '/wpt-stub-no-db-version' ) ) {
			// An option that cannot be read at all: core's own default.
			// info must report UNKNOWN (null) for it, never a fabricated 0.
			return $default;
		}
		// The PERSISTED value first: every bridge call is a separate HTTP
		// request (fresh PHP state), so a migration's write has to be
		// visible to the next read exactly as a real db_version is. The
		// file-backed-store idiom the rest of this stub uses.
		$stored = __DIR__ . '/wpt-stub-db-version.json';
		if ( @is_file( $stored ) ) {
			$j = json_decode( (string) @file_get_contents( $stored ), true );
			if ( is_string( $j ) && '' !== $j ) {
				return $j;
			}
		}
	}
	if ( 'active_plugins' === $name ) {
		// A raw PHP literal, so a test can model a CORRUPT option (a string,
		// a scalar, an empty value) — the state the op must report rather
		// than read as "no active plugins".
		$raw = __DIR__ . '/wpt-stub-active-plugins-raw';
		if ( @is_file( $raw ) ) {
			return require $raw;
		}
		if ( @is_file( wpt_stub_active_plugins_file() ) ) {
			$j = json_decode( (string) @file_get_contents( wpt_stub_active_plugins_file() ), true );
			if ( is_array( $j ) ) {
				return $j;
			}
		}
	}
	return array_key_exists( $name, $GLOBALS['wpt_stub_options'] ) ? $GLOBALS['wpt_stub_options'][ $name ] : $default;
}

function update_option( $name, $value, $autoload = null ) {
	$GLOBALS['wpt_stub_options'][ $name ] = $value;
	wpt_stub_rec( 'update_option:' . $name );
	// Core-faithfulness probe: a 2-arg update_option() leaves the row's
	// autoload flag alone. Record the call's ARGUMENT COUNT only when it
	// deviates from 2, so a 3-arg write (autoload=off on WP 6.6+) is
	// assertable without disturbing the plain update_option:<name> line
	// every existing test matches on.
	if ( 2 !== func_num_args() ) {
		wpt_stub_rec( 'update_option:argcount=' . func_num_args() );
	}
	if ( 'active_plugins' === $name ) {
		@file_put_contents( wpt_stub_active_plugins_file(), json_encode( array_values( (array) $value ) ) );
	}
	if ( 'db_version' === $name ) {
		@file_put_contents( __DIR__ . '/wpt-stub-db-version.json', json_encode( (string) $value ) );
	}
	if ( 'wpt_core_upgrade' === $name ) {
		@file_put_contents( wpt_stub_marker_file(), json_encode( (array) $value ) );
	}
	return true;
}

// ---------------------------------------------------------------------------
// User API stubs (users_reset).  wp_set_password's OUTCOME is modelled (the
// user_pass write), not core's internals; the session invalidation is a
// SEPARATE core call (WP_Session_Tokens::destroy_all) the op makes itself —
// core's wp_set_password does not touch session_tokens, which is exactly the
// gap these stubs let a test pin.
// ---------------------------------------------------------------------------

class WP_User {
	public $ID;
	public $user_login;
	public $user_email;
	public $user_pass;
	public $roles = array();

	public function __construct( $id, $login, $email ) {
		$this->ID         = (int) $id;
		$this->user_login = (string) $login;
		$this->user_email = (string) $email;
	}
}

function wpt_stub_user_row( $user_id ) {
	foreach ( $GLOBALS['wpt_stub_users'] as $row ) {
		if ( (int) $row['ID'] === (int) $user_id ) {
			return $row;
		}
	}
	return null;
}

function get_userdata( $user_id ) {
	$id = (int) $user_id;
	if ( $id < 1 ) {
		return false;
	}
	// A throwing read (plugin hook, broken cache): users_reset must contain
	// the role read inside its per-user try and still return every password
	// already set; user_create must contain its recovery read (R11-P1-2).
	$throw_file = __DIR__ . '/wpt-stub-userdata-throws';
	if ( @is_file( $throw_file ) ) {
		$targets = array_filter( array_map( 'trim', explode( ',', (string) @file_get_contents( $throw_file ) ) ) );
		if ( empty( $targets ) || in_array( (string) $id, $targets, true ) ) {
			throw new RuntimeException( 'simulated get_userdata failure for ' . $id );
		}
	}
	// Simulated throwing/failing read-back after wp_insert_user(): the
	// account IS persisted, so the op must return its password with
	// ok:false instead of losing it to the global envelope (C12).
	if ( isset( $GLOBALS['wpt_stub_unreadable_users'] )
		&& in_array( $id, $GLOBALS['wpt_stub_unreadable_users'], true ) ) {
		return false;
	}
	// One cached instance per ID (core caches WP_User objects too), so a
	// wp_set_password write is visible on the next read.
	if ( ! isset( $GLOBALS['wpt_stub_user_objects'][ $id ] ) ) {
		$row = wpt_stub_user_row( $id );
		if ( ! $row ) {
			return false;
		}
		$user                  = new WP_User( $id, $row['user_login'], $row['user_email'] );
		$user->user_pass       = 'hashed:initial';
		$user->roles           = isset( $GLOBALS['wpt_stub_roles'][ $id ] )
			? $GLOBALS['wpt_stub_roles'][ $id ]
			: array();
		$GLOBALS['wpt_stub_user_objects'][ $id ] = $user;
	}
	return $GLOBALS['wpt_stub_user_objects'][ $id ];
}

// Deterministic stand-in for core's generator: per-request counter, so the
// passwords a single op call returns are distinct and reproducible.
function wp_generate_password( $length = 12, $special_chars = true, $extra_special_chars = false ) {
	$GLOBALS['wpt_stub_pw_n'] = isset( $GLOBALS['wpt_stub_pw_n'] ) ? (int) $GLOBALS['wpt_stub_pw_n'] + 1 : 1;
	$fail_file = __DIR__ . '/wpt-stub-password-generate-fails';
	if ( @is_file( $fail_file ) ) {
		$target = (int) trim( (string) @file_get_contents( $fail_file ) );
		if ( $target < 1 || $target === (int) $GLOBALS['wpt_stub_pw_n'] ) {
			throw new RuntimeException( 'simulated password generator failure' );
		}
	}
	if ( @is_file( __DIR__ . '/wpt-stub-password-quotes' ) ) {
		// R19: a filter may return quotes; ENT_NOQUOTES/ENT_COMPAT output
		// differs from every ENT_QUOTES form the old scrubber knew.
		return "Abc'Def<9";
	}
	if ( @is_file( __DIR__ . '/wpt-stub-password-special' ) ) {
		// A password carrying characters every encoder changes.
		return 'Abc&Def!9';
	}
	return sprintf( 'wpt-stub-pw-%d-%s', $GLOBALS['wpt_stub_pw_n'], str_repeat( 'x', max( 1, (int) $length - 12 ) ) );
}

function wp_set_password( $password, $user_id ) {
	wpt_stub_rec( 'wp_set_password:' . (int) $user_id );
	// A core update can return without storing anything (read-only DB, a
	// lock, a plugin no-op).  The op must PROVE the hash before publishing
	// the generated credential.
	if ( @is_file( __DIR__ . '/wpt-stub-password-silent-noop' ) ) {
		return true;
	}
	// Simulated per-user failure: the marker names the user id whose setter
	// throws AFTER earlier accounts were already reset (C12).
	$fail_file = __DIR__ . '/wpt-stub-password-fails';
	if ( @is_file( $fail_file ) ) {
		$target = trim( (string) @file_get_contents( $fail_file ) );
		if ( '' === $target || (int) $target === (int) $user_id ) {
			throw new RuntimeException( 'simulated password store failure' );
		}
	}
	// A hook can put the just-generated plaintext into its exception text,
	// raw or encoded.  users_reset must scrub every form at the owner.
	if ( @is_file( __DIR__ . '/wpt-stub-password-echoes-encoded' ) ) {
		throw new RuntimeException(
			'store failed for ' . htmlspecialchars( (string) $password )
			. ' / ' . urlencode( (string) $password )
			. ' / ' . json_encode( (string) $password )
			. ' / ' . str_replace( '&', '&#038;', (string) $password ) );
	}
	$user = get_userdata( $user_id );
	if ( ! $user ) {
		return false;
	}
	$user->user_pass = 'hashed:' . (string) $password;  // core hashes, stores the hash
	// Digest, never the plaintext: lets a test prove the password the op
	// RETURNED is the one that was set, without the call log ever holding
	// a credential.
	wpt_stub_rec( 'user_pass_set:' . (int) $user_id . ':' . md5( (string) $password ) );
	// Core's wp_set_password() writes the hash and THEN fires
	// do_action('wp_set_password', ...) — a throwing hook reaches the op's
	// catch with the new password already live.  This marker models exactly
	// that after-write failure.
	$late_file = __DIR__ . '/wpt-stub-password-fails-after-write';
	if ( @is_file( $late_file ) ) {
		$target = trim( (string) @file_get_contents( $late_file ) );
		if ( '' === $target || (int) $target === (int) $user_id ) {
			throw new RuntimeException( 'simulated hook after password write' );
		}
	}
	return true;
}

// Core's verifier.  The op's after-write recovery re-reads the hash and
// proves the generated plaintext is the one now stored.
function wp_check_password( $password, $hash, $user_id = '' ) {
	$ok = hash_equals( (string) $hash, 'hashed:' . (string) $password );
	wpt_stub_rec( 'user_pass_check:' . (int) $user_id . ':' . ( $ok ? 'match' : 'miss' ) );
	return $ok;
}

// Core loads this class in wp-settings.php; the op guards on class_exists
// so a stripped-down install degrades instead of fataling. The
// wpt-stub-no-sessions marker removes it to exercise that guard.
if ( ! @is_file( __DIR__ . '/wpt-stub-no-sessions' ) ) {
	class WP_Session_Tokens {
		private $user_id;

		public function __construct( $user_id ) {
			$this->user_id = (int) $user_id;
		}

		public static function get_instance( $user_id ) {
			$fail_file = __DIR__ . '/wpt-stub-session-instance-throws';
			if ( @is_file( $fail_file ) ) {
				$targets = array_filter( array_map( 'trim', explode( ',', (string) @file_get_contents( $fail_file ) ) ) );
				if ( empty( $targets ) || in_array( (string) (int) $user_id, $targets, true ) ) {
					throw new RuntimeException( 'simulated session manager failure for ' . (int) $user_id );
				}
			}
			return new self( $user_id );
		}

		public function destroy_all() {
			wpt_stub_rec( 'session_tokens_destroy_all:' . $this->user_id );
			return true;
		}
	}
}

// ---------------------------------------------------------------------------
// User API stubs (user_create).  sanitize_user() follows the core pipeline
// (strip tags, drop percent-encodings and HTML entities, strict character
// class, trim, collapse whitespace) closely enough that a login the harness
// accepts is a login core accepts; username_exists()/email_exists() read the
// same $GLOBALS['wpt_stub_users'] the users_reset tests use, so a duplicate
// is the SAME duplicate both ops see; wp_insert_user() models core's
// duplicate/role validation and the outcome (a new row with its role as a
// name => true map, the shape WP_User::set_role() leaves), and records the
// password's DIGEST like wp_set_password — never the plaintext.
// ---------------------------------------------------------------------------

function wp_strip_all_tags( $text, $remove_breaks = false ) {
	$text = preg_replace( '@<(script|style)[^>]*?>.*?</\\1>@si', '', (string) $text );
	$text = strip_tags( $text );
	if ( $remove_breaks ) {
		$text = preg_replace( '/[\r\n\t ]+/', ' ', $text );
	}
	return trim( $text );
}

function remove_accents( $string ) {
	// The harness runs UTF-8 fixtures; keeping the graphemes is enough for
	// the strict char-class step below to drop them exactly as core would.
	return (string) $string;
}

function sanitize_user( $username, $strict = false ) {
	$raw_username = $username;
	$username     = wp_strip_all_tags( $username );
	$username     = remove_accents( $username );
	// Remove percent-encoded characters.
	$username = preg_replace( '|%([a-fA-F0-9][a-fA-F0-9])|', '', $username );
	// Remove HTML entities.
	$username = preg_replace( '/&.+?;/', '', $username );
	// If strict, reduce to ASCII for max portability.
	if ( $strict ) {
		$username = preg_replace( '|[^a-z0-9 _.\-@]|i', '', $username );
	}
	$username = trim( $username );
	// Consolidate contiguous whitespace.
	$username = preg_replace( '|\s+|', ' ', $username );
	return apply_filters( 'sanitize_user', $username, $raw_username, $strict );
}

function username_exists( $username ) {
	foreach ( $GLOBALS['wpt_stub_users'] as $row ) {
		if ( strtolower( (string) $row['user_login'] ) === strtolower( (string) $username ) ) {
			return (int) $row['ID'];
		}
	}
	return false;
}

function email_exists( $email ) {
	foreach ( $GLOBALS['wpt_stub_users'] as $row ) {
		if ( strtolower( (string) $row['user_email'] ) === strtolower( (string) $email ) ) {
			return (int) $row['ID'];
		}
	}
	return false;
}

function is_email( $email ) {
	return false !== filter_var( (string) $email, FILTER_VALIDATE_EMAIL );
}

function get_role( $role ) {
	$known = array( 'administrator', 'editor', 'author', 'contributor', 'subscriber' );
	if ( in_array( (string) $role, $known, true ) ) {
		$obj       = new stdClass();
		$obj->name = (string) $role;
		return $obj;
	}
	return null;
}

function wp_insert_user( $userdata ) {
	$userdata = (array) $userdata;
	if ( @is_file( __DIR__ . '/wpt-stub-insert-fails' ) ) {
		wpt_stub_rec( 'wp_insert_user:fail' );
		return new WP_Error( 'db_insert_error', 'Could not insert user into the database.' );
	}
	$login = isset( $userdata['user_login'] )
		? sanitize_user( (string) $userdata['user_login'], true ) : '';
	if ( '' === trim( $login ) ) {
		return new WP_Error( 'empty_user_login', 'Cannot create a user with an empty login name.' );
	}
	if ( username_exists( $login ) ) {
		return new WP_Error( 'existing_user_login', 'Sorry, that username already exists!' );
	}
	$email = isset( $userdata['user_email'] ) ? (string) $userdata['user_email'] : '';
	if ( '' !== $email && email_exists( $email ) ) {
		return new WP_Error( 'existing_user_email', 'Sorry, that email address is already used!' );
	}
	// Core applies pre_user_login/pre_user_email BEFORE the insert.  A
	// plugin that rewrites either field makes the written row unfindable
	// by the request's own login/email; only the user_register id is
	// stable.  The bridge's recovery must use that id.
	if ( @is_file( __DIR__ . '/wpt-stub-user-filters' ) ) {
		$login = 'filtered-' . $login;
		$email = 'filtered-' . $email;
	}
	if ( @is_file( __DIR__ . '/wpt-stub-user-invalid-utf8' ) ) {
		// The row WordPress wrote carries a byte that is not valid UTF-8;
		// the created account (and password) are still live and must be
		// returned by the success envelope.
		$email .= "\xff";
	}
	$role = isset( $userdata['role'] ) ? (string) $userdata['role'] : '';
	if ( '' !== $role && null === get_role( $role ) ) {
		return new WP_Error( 'invalid_role', 'Invalid role.' );
	}
	// A CONCURRENT duplicate: the row appears AFTER the duplicate checks
	// above (the real plan/apply race), and the insert throws before
	// user_register can capture its id.  The pre-existing row's password is
	// NOT the generated one, so the bridge must never report it as this
	// run's creation.
	if ( @is_file( __DIR__ . '/wpt-stub-insert-concurrent' ) ) {
		$GLOBALS['wpt_stub_users'][] = array(
			'ID'         => '999',
			'user_login' => $login,
			'user_email' => $email,
		);
		throw new RuntimeException( 'simulated concurrent duplicate insert' );
	}
	$pass = isset( $userdata['user_pass'] ) ? (string) $userdata['user_pass'] : '';
	$id   = 0;
	foreach ( $GLOBALS['wpt_stub_users'] as $row ) {
		$id = max( $id, (int) $row['ID'] );
	}
	$id++;
	$GLOBALS['wpt_stub_users'][] = array(
		'ID'         => (string) $id,
		'user_login' => $login,
		'user_email' => $email,
	);
	// WP_User::set_role() leaves a name => true MAP, not a plain list.
	$GLOBALS['wpt_stub_roles'][ $id ] = ( '' !== $role )
		? array( $role => true ) : array();
	unset( $GLOBALS['wpt_stub_user_objects'][ $id ] );
	// Simulated read-back failure for the account just created: the row
	// (and the password) are live, but get_userdata() cannot answer (C12).
	if ( @is_file( __DIR__ . '/wpt-stub-user-readback-fails' ) ) {
		$GLOBALS['wpt_stub_unreadable_users'][] = $id;
	}
	wpt_stub_rec( 'wp_insert_user:' . $id . ':' . $login );
	wpt_stub_rec( 'user_pass_set:' . $id . ':' . md5( $pass ) );
	// Core's own user_register action fires AFTER the row exists and BEFORE
	// wp_insert_user returns.  The bridge's earliest-priority callback must
	// capture the id here even when a later hook throws.
	do_action( 'user_register', $id );
	// Simulated user_register hook failure AFTER core wrote the row: the
	// account and password are live even though the call throws (C12).
	if ( @is_file( __DIR__ . '/wpt-stub-insert-throws-after' ) ) {
		throw new RuntimeException( 'simulated user_register hook failure' );
	}
	// The R12-P1-4 shape: a hook throws the PLAINTEXT password into its own
	// message after the row is written.  The bridge must scrub it before the
	// answer reaches the client/log/report.
	if ( @is_file( __DIR__ . '/wpt-stub-insert-throws-password' ) ) {
		throw new RuntimeException( 'simulated hook saw password ' . $pass );
	}
	// R15-P1-4: the same hook but it ENCODES the plaintext before throwing.
	// Every reversible form must be scrubbed from the envelope.
	if ( @is_file( __DIR__ . '/wpt-stub-insert-throws-encoded-password' ) ) {
		throw new RuntimeException(
			'simulated hook saw '
			. htmlspecialchars( $pass, ENT_QUOTES, 'UTF-8' ) . ' / '
			. htmlentities( $pass, ENT_QUOTES, 'UTF-8' ) . ' / '
			. urlencode( $pass ) . ' / '
			. rawurlencode( $pass ) . ' / '
			. json_encode( $pass )
		);
	}
	// R18-P1: WordPress's esc_url() writes `&` as `&#038;`, a reversible
	// numeric entity the html/url/json variants above never anticipated.
	if ( @is_file( __DIR__ . '/wpt-stub-insert-throws-esc-url-password' ) ) {
		throw new RuntimeException(
			'simulated hook saw '
			. str_replace( '&', '&#038;', $pass )
		);
	}
	// R19-P1: esc_html() uses ENT_NOQUOTES and esc_js() ENT_COMPAT — the
	// two quote policies the ENT_QUOTES-only variant list missed.
	if ( @is_file( __DIR__ . '/wpt-stub-insert-throws-noquotes-password' ) ) {
		throw new RuntimeException(
			'simulated hook saw '
			. htmlspecialchars( $pass, ENT_NOQUOTES, 'UTF-8' ) . ' / '
			. htmlspecialchars( $pass, ENT_COMPAT, 'UTF-8' )
		);
	}
	// R19-P1: whitespace/backslash escape spellings (addslashes, a literal
	// \xNN escape, and a shell-ish backslash-space form).  No finite
	// variant list proves these clean; the owner withholds the diagnostic.
	if ( @is_file( __DIR__ . '/wpt-stub-insert-throws-escaped-password' ) ) {
		throw new RuntimeException(
			'simulated hook saw '
			. addslashes( $pass ) . ' / '
			. str_replace( "'", '\\x27', $pass ) . ' / '
			. str_replace( ' ', '\\x20', $pass )
		);
	}
	return $id;
}

// ---------------------------------------------------------------------------
// Serialization stubs (media_rewrite_refs).
//
// The op rewrites a serialized value through WordPress's OWN
// maybe_unserialize/maybe_serialize, so the harness must provide them: the
// "s:NN:" byte lengths a serialized string carries are re-computed by
// PHP's serialize(), and that rewrite is the one thing only the server can
// do.
//
// The three function bodies below are COPIED VERBATIM from WordPress
// core — src/wp-includes/functions.php, the `maybe_serialize` /
// `maybe_unserialize` / `is_serialized` definitions, identical in the 6.8
// tag and in trunk — because a MODEL of them proves nothing: the op's
// whole refusal contract turns on where core's real predicate says
// "serialized" and where it says "no", and a plausible-looking
// approximation silently invents verdicts production never reaches.  A
// hand-written `preg_match('/^[aOsbdiC]:/')` said a plain-text value that
// happens to start "s:" WAS serialized, so every "value is serialized but
// unreadable" fixture proved a refusal core never issues; and dropping
// maybe_serialize's `is_serialized( $data, false )` branch hid core's
// double-serialization of an already-serialized-looking scalar.
//
// They need nothing from core around them: `serialize`/`unserialize` are
// PHP's, and `str_contains` (the one PHP 8 function the non-strict branch
// uses; core loads a polyfill from compat.php on older PHP, and the harness
// runs on the local PHP) is native from 8.0.
// ---------------------------------------------------------------------------

function is_serialized( $data, $strict = true ) {
	// If it isn't a string, it isn't serialized.
	if ( ! is_string( $data ) ) {
		return false;
	}
	$data = trim( $data );
	if ( 'N;' === $data ) {
		return true;
	}
	if ( strlen( $data ) < 4 ) {
		return false;
	}
	if ( ':' !== $data[1] ) {
		return false;
	}
	if ( $strict ) {
		$lastc = substr( $data, -1 );
		if ( ';' !== $lastc && '}' !== $lastc ) {
			return false;
		}
	} else {
		$semicolon = strpos( $data, ';' );
		$brace     = strpos( $data, '}' );
		// Either ; or } must exist.
		if ( false === $semicolon && false === $brace ) {
			return false;
		}
		// But neither must be in the first X characters.
		if ( false !== $semicolon && $semicolon < 3 ) {
			return false;
		}
		if ( false !== $brace && $brace < 4 ) {
			return false;
		}
	}
	$token = $data[0];
	switch ( $token ) {
		case 's':
			if ( $strict ) {
				if ( '"' !== substr( $data, -2, 1 ) ) {
					return false;
				}
			} elseif ( ! str_contains( $data, '"' ) ) {
				return false;
			}
			// Or else fall through.
		case 'a':
		case 'O':
		case 'E':
			return (bool) preg_match( "/^{$token}:[0-9]+:/s", $data );
		case 'b':
		case 'i':
		case 'd':
			$end = $strict ? '$' : '';
			return (bool) preg_match( "/^{$token}:[0-9.E+-]+;$end/", $data );
	}
	return false;
}

function maybe_unserialize( $data ) {
	if ( is_serialized( $data ) ) { // Don't attempt to unserialize data that wasn't serialized going in.
		return @unserialize( trim( $data ) );
	}

	return $data;
}

function maybe_serialize( $data ) {
	if ( is_array( $data ) || is_object( $data ) ) {
		return serialize( $data );
	}

	/*
	 * Double serialization is required for backward compatibility.
	 * See https://core.trac.wordpress.org/ticket/12930
	 * Also the world will end. See WP 3.6.1.
	 */
	if ( is_serialized( $data, false ) ) {
		return serialize( $data );
	}

	return $data;
}

// The object-cache invalidation a raw SQL write must perform, recorded so
// a test can prove the op does it (a stale cached value would keep serving
// the pre-rewrite reference to a page rendered after the purge).
function clean_post_cache( $post ) {
	wpt_stub_rec( 'clean_post_cache:' . (int) $post );
	return true;
}

function wp_cache_delete( $key, $group = '' ) {
	wpt_stub_rec( 'wp_cache_delete:' . $group . ':' . $key );
	return true;
}

function get_bloginfo( $show = '' ) {
	return '6.4.2';
}

// WordPress's own multisite test.  The wpt-stub-multisite marker models a
// network install, which is the only way core_upgrade's refusal is
// reachable (a single-site site never enters that branch).
function is_multisite() {
	return @is_file( ABSPATH . 'wpt-stub-multisite' );
}

// Mirrors WordPress's own site-locale resolution (wp-includes/l10n.php,
// get_locale(), 7.1) closely enough for the harness: the WPLANG option
// is returned VERBATIM (core does `return apply_filters( 'locale',
// $locale )` over the raw option value — only an EMPTY value falls back
// to en_US; the real function would first consult $wp_local_package,
// which the stub's no-marker version.php shape never sets).  The live
// localized migration sites answer 'fr_CA'.
function get_locale() {
	if ( isset( $GLOBALS['wpt_stub_options']['WPLANG'] ) ) {
		$wplang = $GLOBALS['wpt_stub_options']['WPLANG'];
		if ( is_string( $wplang ) && '' === $wplang ) {
			return 'en_US';
		}
		return $wplang;
	}
	return 'en_US';
}

/**
 * Core's validate_file() — wp-includes/functions.php (6.8), transcribed,
 * not approximated: reconcile_active_plugins defers to it for the
 * "can this be a plugin path at all" question, so a harness that answered
 * it differently would let the op pass a test and fail on a real site.
 */
function validate_file( $file, $allowed_files = array() ) {
	if ( ! is_scalar( $file ) || '' === $file ) {
		return 0;
	}
	$file = str_replace( '\\', '/', (string) $file );
	$allowed_files = array_map( function ( $f ) { return str_replace( '\\', '/', (string) $f ); }, $allowed_files );
	if ( '../' === $file ) {
		return 1;
	}
	if ( preg_match_all( '#\.\./#', $file, $matches ) && count( $matches[0] ) > 1 ) {
		return 1;
	}
	if ( false !== strpos( $file, '../' ) && '../' !== substr( $file, -3 ) ) {
		return 1;
	}
	if ( ! empty( $allowed_files ) && ! in_array( $file, $allowed_files, true ) ) {
		return 3;
	}
	if ( ':' === substr( $file, 1, 1 ) ) {
		return 2;
	}
	return 0;
}

// The wpt-stub-no-plugins marker models an admin include that loads but
// does not deliver the function (a trimmed/renamed plugin.php on a real
// host): bridge.php's own bootstrap require then succeeds, get_plugins()
// stays undefined, and the op's fail-closed guard is reachable.
if ( ! @is_file( __DIR__ . '/wpt-stub-no-plugins' ) ) {

/**
 * get_plugins() the way core BUILDS it (wp-admin/includes/plugin.php): scan
 * WP_PLUGIN_DIR for a root-level *.php and for <dir>/<dir>.php, and SKIP
 * every file whose plugin header cannot be read/parsed — core's
 * `if ( empty( $plugin_data['Name'] ) ) continue;`.
 *
 * A canned list (as an earlier harness revision returned) models a plugin
 * inventory no real install has, and hides exactly the class of production
 * bug this double exists to catch: a plugin file that is PRESENT and
 * therefore loaded by WordPress, yet absent from the inventory. The
 * wpt-stub-unreadable-plugin marker makes one file unreadable (chmod 000)
 * to model the other real-world cause of the same gap.
 */
function wpt_stub_plugin_data( $file ) {
	if ( ! is_readable( $file ) ) {
		return null;
	}
	$head = (string) @file_get_contents( $file, false, null, 0, 8192 );
	$name = '';
	if ( preg_match( '/^[ \t\/*#@]*Plugin Name:(.*)$/mi', $head, $m ) ) {
		$name = trim( $m[1] );
	}
	if ( '' === $name ) {
		return null;
	}
	$version = preg_match( '/^[ \t\/*#@]*Version:(.*)$/mi', $head, $v ) ? trim( $v[1] ) : '';
	return array( 'Name' => $name, 'Version' => $version );
}

function get_plugins( $plugin_folder = '' ) {
	$dir = WP_PLUGIN_DIR . ( '' !== $plugin_folder ? '/' . $plugin_folder : '' );
	if ( ! is_dir( $dir ) ) {
		return array();
	}
	$out = array();
	foreach ( (array) scandir( $dir ) as $entry ) {
		if ( '.' === $entry || '..' === $entry ) {
			continue;
		}
		$path = $dir . '/' . $entry;
		if ( is_dir( $path ) ) {
			$main = $path . '/' . $entry . '.php';
			if ( ! is_file( $main ) ) {
				continue;
			}
			$data = wpt_stub_plugin_data( $main );
			if ( null === $data ) {
				continue;
			}
			$out[ $entry . '/' . $entry . '.php' ] = $data;
		} elseif ( '.php' === substr( $entry, -4 ) ) {
			$data = wpt_stub_plugin_data( $path );
			if ( null === $data ) {
				continue;
			}
			$out[ $entry ] = $data;
		}
	}
	return $out;
}

} // end of the wpt-stub-no-plugins guard

function wp_upload_dir( $time = null, $create_dir = true, $legacy_filename = null ) {
	return array(
		'path'    => '__WPT_UPLOADS_DIR__',
		'url'     => 'https://example.test/wp-content/uploads',
		'subdir'  => '',
		'basedir' => '__WPT_UPLOADS_DIR__',
		'baseurl' => 'https://example.test/wp-content/uploads',
		'error'   => '',
	);
}

$GLOBALS['wpt_stub_actions'] = array();

function do_action( $tag, ...$args ) {
	wpt_stub_rec( 'do_action:' . $tag );
	if ( empty( $GLOBALS['wpt_stub_actions'][ $tag ] ) ) {
		return;
	}
	$by_priority = $GLOBALS['wpt_stub_actions'][ $tag ];
	ksort( $by_priority );
	foreach ( $by_priority as $callbacks ) {
		foreach ( $callbacks as $callback ) {
			call_user_func_array( $callback, $args );
		}
	}
}

function add_action( $tag, $callback, $priority = 10, $accepted_args = 1 ) {
	$GLOBALS['wpt_stub_actions'][ $tag ][ (int) $priority ][] = $callback;
	return true;
}

// The hook API, for real: core_upgrade_files hooks core's OWN
// ``update_feedback`` (to read the phases core publishes) and
// ``pre_http_request`` (to suppress core's fire-and-forget database
// step).  A stub whose apply_filters() always returned $value would make
// the op's own suppression a fiction, so this is a working
// priority-ordered implementation and wp_remote_post() honours
// pre_http_request exactly as core's WP_Http does.
$GLOBALS['wpt_stub_filters'] = array();

// A site whose security stack blocks logins: user_create mirrors core's
// illegal_user_logins refusal in its READ-ONLY validation too, so a plan
// that passes cannot fail at insert time.  Registered HERE, after the
// filter registry above is initialized (top-level code runs in file
// order; an earlier call would be wiped by that initialization).
if ( @is_file( __DIR__ . '/wpt-stub-illegal-logins' ) ) {
	add_filter( 'illegal_user_logins', 'wpt_stub_illegal_logins' );
}
function wpt_stub_illegal_logins( $logins ) {
	$logins   = is_array( $logins ) ? $logins : array();
	$logins[] = 'forbidden';
	return $logins;
}

function add_filter( $tag, $callback, $priority = 10, $accepted_args = 1 ) {
	$GLOBALS['wpt_stub_filters'][ $tag ][ (int) $priority ][] = $callback;
	return true;
}

function remove_filter( $tag, $callback, $priority = 10 ) {
	$bucket = isset( $GLOBALS['wpt_stub_filters'][ $tag ][ (int) $priority ] )
		? $GLOBALS['wpt_stub_filters'][ $tag ][ (int) $priority ]
		: array();
	foreach ( $bucket as $index => $registered ) {
		if ( $registered === $callback ) {
			unset( $GLOBALS['wpt_stub_filters'][ $tag ][ (int) $priority ][ $index ] );
		}
	}
	return true;
}

function apply_filters( $tag, $value, ...$args ) {
	if ( empty( $GLOBALS['wpt_stub_filters'][ $tag ] ) ) {
		return $value;
	}
	$by_priority = $GLOBALS['wpt_stub_filters'][ $tag ];
	ksort( $by_priority );
	foreach ( $by_priority as $callbacks ) {
		foreach ( $callbacks as $callback ) {
			$value = call_user_func_array( $callback, array_merge( array( $value ), $args ) );
		}
	}
	return $value;
}

class WP_Error {
	protected $errors = array();

	public function __construct( $code = '', $message = '', $data = '' ) {
		if ( '' !== $code ) {
			$this->errors[ $code ][] = array( $message, $data );
		}
	}

	public function get_error_code() {
		$codes = array_keys( $this->errors );
		return empty( $codes ) ? '' : $codes[0];
	}

	public function get_error_message( $code = '' ) {
		if ( '' === $code ) {
			$code = $this->get_error_code();
		}
		return isset( $this->errors[ $code ][0][0] ) ? $this->errors[ $code ][0][0] : '';
	}

	public function get_error_data( $code = '' ) {
		if ( '' === $code ) {
			$code = $this->get_error_code();
		}
		return isset( $this->errors[ $code ][0][1] ) ? $this->errors[ $code ][0][1] : null;
	}
}

function is_wp_error( $thing ) {
	return $thing instanceof WP_Error;
}

function untrailingslashit( $string ) {
	return rtrim( (string) $string, '/\\' );
}

function trailingslashit( $string ) {
	return untrailingslashit( $string ) . '/';
}

function admin_url( $path = '' ) {
	return 'https://example.test/wp-admin/' . ltrim( (string) $path, '/' );
}

function wp_cache_flush() {
	wpt_stub_rec( 'wp_cache_flush' );
	return true;
}

function delete_site_transient( $key ) {
	wpt_stub_rec( 'delete_site_transient:' . $key );
	return true;
}

function delete_site_option( $key ) {
	wpt_stub_rec( 'delete_site_option:' . $key );
	return true;
}

function wp_opcache_invalidate( $path ) {
	wpt_stub_rec( 'wp_opcache_invalidate' );
	return true;
}

function wp_remote_post( $url, $args = array() ) {
	$preempt = apply_filters( 'pre_http_request', false, $args, $url );
	if ( false !== $preempt ) {
		wpt_stub_rec( 'wp_remote_post:preempted' );
		return $preempt;
	}
	wpt_stub_rec( 'wp_remote_post:' . $url );
	return new WP_Error( 'http_request_failed', 'the harness makes no HTTP request' );
}

// The W3TC / WP Super Cache flush entry points only exist when those caching
// plugins are active. wpt-stub-no-cache-fns removes them to model a stock
// WordPress site with no caching plugin, so the function_exists guards in
// purge_cache are exercised on BOTH the present and absent paths.
if ( ! @is_file( __DIR__ . '/wpt-stub-no-cache-fns' ) ) {
	function w3tc_flush_all( $extras = null ) {
		wpt_stub_rec( 'w3tc_flush_all' );
	}

	function wp_cache_clear_cache( $blog_id = 0 ) {
		wpt_stub_rec( 'wp_cache_clear_cache' );
	}
}

$GLOBALS['wpdb'] = new WPT_Stub_wpdb();
// The "usermeta table not discoverable" case for the db_audit users guard:
// an unset wpdb property makes the bridge's isset() discovery fail, so the
// users payload degrades to null (unknown — never a measured []).
if ( @is_file( __DIR__ . '/wpt-stub-no-usermeta' ) ) {
	unset( $GLOBALS['wpdb']->usermeta );
}
"""


# ---------------------------------------------------------------------------
# The core upgrader's own file layer, as the docroot carries it.
#
# See the _build comment that writes these: the op's require_once calls are
# the real ones, and two of these bodies do real work (the extraction and
# the copy) so the phases a test measures are measured on a real tree.
# ---------------------------------------------------------------------------

FILE_PHP_STUB = r"""<?php
if ( ! defined( 'WP_CONTENT_DIR' ) ) {
	define( 'WP_CONTENT_DIR', ABSPATH . 'wp-content' );
}
if ( ! defined( 'WPINC' ) ) {
	define( 'WPINC', 'wp-includes' );
}
if ( ! defined( 'FS_CHMOD_DIR' ) ) {
	define( 'FS_CHMOD_DIR', 0755 );
}
if ( ! defined( 'FS_CHMOD_FILE' ) ) {
	define( 'FS_CHMOD_FILE', 0644 );
}

/**
 * core's own method resolution. The wpt-stub-fs-method marker answers
 * something else — a host whose files are owned by the FTP user, where
 * core's updater falls through to ftpext and blocks on a credential
 * prompt nobody can answer.
 */
/**
 * core's BUNDLED PclZip, which is why the op's zip answer needs this file
 * loaded at all: real file.php defines PclZip at its bottom, and
 * unzip_file() falls through ZipArchive to it. Modelled as the class core
 * defines; the wpt-stub-no-zip marker removes it, so "neither ZipArchive
 * nor PclZip" (a trimmed install, where core cannot extract a release at
 * all) is reachable.
 */
if ( ! @is_file( ABSPATH . 'wpt-stub-no-zip' ) ) {
	class PclZip {
	}
}

function get_filesystem_method( $args = array(), $context = '', $allow_relaxed_file_ownership = false ) {
	wpt_stub_rec( 'get_filesystem_method' );
	$marker = ABSPATH . 'wpt-stub-fs-method';
	if ( @is_file( $marker ) ) {
		return trim( (string) @file_get_contents( $marker ) );
	}
	return 'direct';
}

function WP_Filesystem( $args = false, $context = false, $allow_relaxed_file_ownership = false ) {
	global $wp_filesystem;
	$method = get_filesystem_method( $args, $context, $allow_relaxed_file_ownership );
	if ( ! $method || 'direct' !== $method ) {
		return false;
	}
	if ( ! class_exists( 'WP_Filesystem_Direct' ) ) {
		require_once ABSPATH . 'wp-admin/includes/class-wp-filesystem-direct.php';
	}
	$wp_filesystem = new WP_Filesystem_Direct( is_array( $args ) ? $args : array() );
	return true;
}

/**
 * core's own extraction, with the REAL work done through the unzip binary
 * (this PHP has no ZipArchive, and core's own ZipArchive path would be a
 * second thing to model). The zip's single top-level wordpress/ directory
 * is what makes the staged tree; the failure return is core's own
 * incompatible_archive.
 */
function unzip_file( $file, $to ) {
	wpt_stub_rec( 'unzip_file:' . str_replace( ABSPATH, '', (string) $file )
		. ' -> ' . str_replace( ABSPATH, '', (string) $to ) );
	if ( ! @is_file( $file ) ) {
		return new WP_Error( 'incompatible_archive', 'Incompatible Archive.' );
	}
	if ( ! @is_dir( $to ) && ! @mkdir( $to, 0777, true ) ) {
		return new WP_Error( 'incompatible_archive', 'Incompatible Archive.' );
	}
	$output = array();
	$status = 0;
	exec( 'unzip -qo ' . escapeshellarg( $file ) . ' -d ' . escapeshellarg( $to ) . ' 2>&1', $output, $status );
	if ( 0 !== $status ) {
		return new WP_Error( 'incompatible_archive', 'Incompatible Archive.', implode( "\n", $output ) );
	}
	return true;
}

/**
 * core's own copy, with the REAL work: the skip list is applied per
 * directory entry, exactly where core applies it (file.php's copy_dir
 * checks in_array( $filename, $skip_list, true ) inside its own loop), so
 * wp-content is skipped at the root AND version.php is skipped wherever it
 * sits — the two properties wpt's swap driver exists beside.
 */
function copy_dir( $from, $to, $skip = array() ) {
	wpt_stub_rec( 'copy_dir:' . str_replace( ABSPATH, '', (string) $from )
		. ' -> ' . str_replace( ABSPATH, '', (string) $to )
		. ' skip=' . implode( ',', (array) $skip ) );
	$handle = @opendir( $from );
	if ( ! $handle ) {
		return new WP_Error( 'copy_failed__copy_dir_opendir', 'Could not open the source directory.', $from );
	}
	$names = array();
	while ( false !== ( $entry = readdir( $handle ) ) ) {
		if ( '.' !== $entry && '..' !== $entry ) {
			$names[] = $entry;
		}
	}
	closedir( $handle );
	if ( ! @is_dir( $to ) && ! @mkdir( $to, 0777, true ) ) {
		return new WP_Error( 'mkdir_failed__copy_dir', 'Could not create the destination directory.', $to );
	}
	// core builds a SUB skip list per subdirectory, stripping the
	// ``<dir>/`` prefix off each entry (file.php's copy_dir) — which is the
	// only reason the root-level 'wp-includes/version.php' entry means
	// anything inside wp-includes at all.  Modelled as core does it, or the
	// version-last ordering this op relies on would be untested.
	foreach ( $names as $name ) {
		if ( in_array( $name, (array) $skip, true ) ) {
			wpt_stub_rec( 'copy_dir:skipped:' . $name );
			continue;
		}
		$source = $from . '/' . $name;
		$dest   = $to . '/' . $name;
		if ( is_dir( $source ) ) {
			$sub_skip = array();
			foreach ( (array) $skip as $item ) {
				if ( 0 === strpos( $item, $name . '/' ) ) {
					$sub_skip[] = substr( $item, strlen( $name ) + 1 );
				}
			}
			$result = copy_dir( $source, $dest, $sub_skip );
			if ( is_wp_error( $result ) ) {
				return $result;
			}
		} elseif ( ! @copy( $source, $dest ) ) {
			return new WP_Error( 'copy_failed__copy_dir', 'Could not copy file.', $dest );
		}
	}
	return true;
}
"""

#: The direct filesystem: only the methods the op and the stubs above call.
FILESYSTEM_CLASS_STUB = r"""<?php
class WP_Filesystem_Base {
	public $method = 'direct';

	public function abspath() {
		return ABSPATH;
	}

	public function wp_content_dir() {
		return trailingslashit( WP_CONTENT_DIR );
	}

	public function wp_plugins_dir() {
		return trailingslashit( WP_PLUGIN_DIR );
	}

	public function wp_themes_dir() {
		// core's own answer (WP_Filesystem_Direct::wp_themes_dir()), with
		// no existence test: a themes directory that does not exist yet is
		// still where themes belong.
		return trailingslashit( WP_CONTENT_DIR . '/themes' );
	}

	public function exists( $file ) {
		return @file_exists( $file );
	}

	public function is_file( $file ) {
		return @is_file( $file );
	}

	public function is_dir( $file ) {
		return @is_dir( $file );
	}

	public function is_writable( $file ) {
		return @is_writable( $file );
	}

	public function mkdir( $path, $chown = false, $chmod = false ) {
		return @mkdir( $path, 0777, true );
	}

	public function copy( $source, $destination, $overwrite = false, $mode = false ) {
		if ( ! $overwrite && @file_exists( $destination ) ) {
			return false;
		}
		return @copy( $source, $destination );
	}

	public function chmod( $file, $mode = false ) {
		return @chmod( $file, $mode ? $mode : 0644 );
	}

	public function put_contents( $file, $contents, $mode = false ) {
		return (bool) @file_put_contents( $file, $contents );
	}

	public function get_contents( $file ) {
		return @file_get_contents( $file );
	}

	public function delete( $file, $recursive = false, $type = false ) {
		if ( $recursive && is_dir( $file ) ) {
			foreach ( array_diff( (array) @scandir( $file ), array( '.', '..' ) ) as $name ) {
				$this->delete( $file . '/' . $name, true );
			}
			return @rmdir( $file );
		}
		return @unlink( $file );
	}

	public function dirlist( $path ) {
		return array();
	}

	public function find_folder( $folder ) {
		return @is_dir( $folder ) ? trailingslashit( $folder ) : false;
	}

	public function connect() {
		return true;
	}
}

"""
#: The direct filesystem class core's WP_Filesystem() instantiates for the
#: 'direct' method — the same stub body, its own file, so the op's
#: require_once of the base and of the direct class are both real.
FILESYSTEM_DIRECT_CLASS_STUB = r"""<?php
class WP_Filesystem_Direct extends WP_Filesystem_Base {
	public function __construct( $args ) {
	}
}
"""

#: WP_Upgrader: the one method the op drives, unpack_package(), with core's
#: own working-directory naming and its own pre-clean of the upgrade folder.
UPGRADER_CLASS_STUB = r"""<?php
class WP_Upgrader {
	public $skin;
	public $strings = array();

	public function __construct( $skin = null ) {
		$this->skin = $skin;
	}

	public function init() {
		$this->skin->set_upgrader( $this );
	}

	public function generic_strings() {
	}

	public function upgrade_strings() {
	}

	public function unpack_package( $package, $delete_package = true ) {
		global $wp_filesystem;
		if ( ! $wp_filesystem || ! $wp_filesystem->wp_content_dir() ) {
			return new WP_Error( 'fs_unavailable', 'Could not access filesystem.' );
		}
		$this->skin->feedback( 'unpack_package' );
		$upgrade_folder = $wp_filesystem->wp_content_dir() . 'upgrade/';
		// core wipes the upgrade folder before staging: the reason wpt
		// uploads its package OUTSIDE it, and the reason the op refuses a
		// non-empty one.
		$leftovers = @scandir( $upgrade_folder );
		foreach ( is_array( $leftovers ) ? $leftovers : array() as $name ) {
			if ( '.' !== $name && '..' !== $name ) {
				$wp_filesystem->delete( $upgrade_folder . $name, true );
				wpt_stub_rec( 'unpack_package:wiped:' . $name );
			}
		}
		$working_dir = $upgrade_folder . basename( basename( $package, '.tmp' ), '.zip' );
		wpt_stub_rec( 'unpack_package:working=' . str_replace( ABSPATH, '', $working_dir ) );
		if ( $wp_filesystem->is_dir( $working_dir ) ) {
			$wp_filesystem->delete( $working_dir, true );
		}
		$result = unzip_file( $package, $working_dir );
		if ( $delete_package ) {
			@unlink( $package );
		}
		if ( is_wp_error( $result ) ) {
			$wp_filesystem->delete( $working_dir, true );
			return $result;
		}
		return trailingslashit( $working_dir );
	}

	public static function create_lock( $lock, $expiration ) {
		return true;
	}

	public static function release_lock( $lock ) {
		return true;
	}
}
"""

#: The interactive skin and the NON-interactive one core's own
#: WP_Automatic_Updater drives the upgrader with — the op's choice, and the
#: reason core's progress ends up in the answer instead of on the page.
UPGRADER_SKIN_STUB = r"""<?php
class WP_Upgrader_Skin {
	public $upgrader;
	public $messages = array();

	public function __construct( $args = array() ) {
	}

	public function set_upgrader( &$upgrader ) {
		$this->upgrader = $upgrader;
	}

	public function header() {
	}

	public function footer() {
	}

	public function feedback( $feedback, ...$details ) {
		$this->messages[] = $feedback;
	}

	public function error( $errors ) {
		$this->messages[] = is_string( $errors ) ? $errors : 'error';
	}
}
"""

AUTOMATIC_SKIN_STUB = r"""<?php
class Automatic_Upgrader_Skin extends WP_Upgrader_Skin {
	public function __construct( $args = array() ) {
		parent::__construct( $args );
		$this->header();
	}

	public function header() {
		$this->messages[] = '';
	}

	public function footer() {
	}

	public function feedback( $feedback, ...$details ) {
		$this->messages[] = $feedback;
	}

	public function error( $errors ) {
		$this->messages[] = is_string( $errors ) ? $errors : 'error';
	}
}
"""

#: update_core(): core's own body, in the order core runs it — the
#: insane_distro confidence check, the maintenance file, copy_dir with the
#: skip list, version.php copied LAST, the maintenance file removed only on
#: the success route, the bundled re-add, and the fire-and-forget database
#: step. The phases are announced through update_feedback exactly as core
#: announces them, so the op's progress list is core's own.
UPDATE_CORE_STUB = r"""<?php
global $_new_bundled_files;
$_new_bundled_files = array(
	'themes/twentytwentyfive/' => '6.7',
);

function update_core( $from, $to ) {
	global $wp_filesystem, $_new_bundled_files;
	wpt_stub_rec( 'update_core' );
	set_time_limit( 300 );
	apply_filters( 'update_feedback', 'Verifying the unpacked files…' );

	$distro = '';
	foreach ( array( '/wordpress/', '/wordpress-mu/' ) as $root ) {
		if ( $wp_filesystem->exists( $from . $root . 'readme.html' )
			&& $wp_filesystem->exists( $from . $root . 'wp-includes/version.php' ) ) {
			$distro = $root;
			break;
		}
	}
	if ( ! $distro ) {
		return new WP_Error( 'insane_distro', 'The update could not be unpacked' );
	}

	apply_filters( 'update_feedback', 'Preparing to install the latest version…' );
	$maintenance_file = $to . '.maintenance';
	$wp_filesystem->put_contents( $maintenance_file, '<?php $upgrading = ' . time() . '; ?>' );
	wpt_stub_rec( 'maintenance:write' );
	apply_filters( 'update_feedback', 'Enabling Maintenance mode…' );

	$skip = array( 'wp-content', 'wp-includes/version.php' );
	$result = copy_dir( $from . $distro, $to, $skip );
	if ( @is_file( ABSPATH . 'wpt-stub-core-copy-fails' ) && ! is_wp_error( $result ) ) {
		// A mid-tree copy failure: ABSPATH is left half old, half new, and
		// core does NOT remove the maintenance file on this path.
		return new WP_Error( 'copy_failed__copy_dir', 'Could not copy files.', $to );
	}
	if ( is_wp_error( $result ) ) {
		return $result;
	}
	// version.php LAST, so a failed update still reports the old version.
	if ( ! $wp_filesystem->copy( $from . $distro . 'wp-includes/version.php', $to . 'wp-includes/version.php', true ) ) {
		return new WP_Error( 'copy_failed_for_version_file', 'Could not copy the version file.', 'wp-includes/version.php' );
	}
	wpt_stub_rec( 'copy:version.php:last' );

	apply_filters( 'update_feedback', 'Disabling Maintenance mode…' );
	$wp_filesystem->delete( $maintenance_file );
	wpt_stub_rec( 'maintenance:delete' );

	// The bundled re-add: only items introduced after the installed version.
	foreach ( (array) $_new_bundled_files as $file => $introduced_version ) {
		if ( ! version_compare( $introduced_version, '6.0', '>' ) ) {
			continue;
		}
		list( $type, $filename ) = explode( '/', $file, 2 );
		$dest = ( 'themes' === $type )
			? trailingslashit( $wp_filesystem->wp_themes_dir() )
			: trailingslashit( $wp_filesystem->wp_plugins_dir() );
		if ( $wp_filesystem->is_dir( $dest . $filename ) ) {
			wpt_stub_rec( 'bundled:already:' . $file );
			continue;
		}
		$wp_filesystem->mkdir( $dest . $filename, FS_CHMOD_DIR );
		$_result = copy_dir( $from . $distro . 'wp-content/' . $file, $dest . $filename );
		if ( is_wp_error( $_result ) ) {
			$result = $_result;
		} else {
			wpt_stub_rec( 'bundled:added:' . $file );
		}
	}
	if ( is_wp_error( $result ) ) {
		$wp_filesystem->delete( $from, true );
		return $result;
	}

	apply_filters( 'update_feedback', 'Upgrading database…' );
	wp_remote_post( admin_url( 'upgrade.php?step=upgrade_db' ), array( 'timeout' => 60 ) );

	// core removes its own staging at the end of the success route.
	$wp_filesystem->delete( $from, true );
	return 'landed';
}
"""


class BridgeEnv:
    """A running php -S instance with the stub docroot and deployed bridges."""

    def __init__(self, docroot: Path, uploads: Path, port: int, proc, log_path: Path, log_fh):
        self.docroot = docroot
        self.uploads = uploads
        self.port = port
        self.proc = proc
        self.log_path = log_path
        self.log_fh = log_fh
        self.base = f"http://127.0.0.1:{port}"
        self.calls_path = docroot / "wpt-stub-calls.log"

    def close(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)
        self.log_fh.close()

    def url(self, bridge: str = "bridge-test.php", *, token: str | None = TOKEN, **params) -> str:
        query = {}
        if token is not None:
            query["t"] = token
        query.update({k: v for k, v in params.items() if v is not None})
        qs = "&".join(f"{k}={v}" for k, v in query.items())
        return f"{self.base}/{bridge}" + ("?" + qs if qs else "")

    def call(self, action: str | None = None, params: dict | None = None, *, body=None,
             bridge: str = "bridge-test.php", token: str | None = TOKEN, **query) -> requests.Response:
        if body is None:
            body = json.dumps({"action": action, "params": params if params is not None else {}})
        data = body.encode("utf-8") if isinstance(body, str) else body
        return requests.post(
            self.url(bridge, token=token, **query),
            data=data,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )

    def calls(self) -> list[str]:
        if not self.calls_path.exists():
            return []
        return self.calls_path.read_text(encoding="utf-8").splitlines()


#: The line ``php -S`` prints once it is LISTENING, with the address it
#: actually bound.  Read out of the server's own output rather than
#: predicted: asking the kernel for a free port, recording it and CLOSING
#: the socket (what this harness used to do) is a TOCTOU — the port is
#: unowned between the close and php's bind, and anything that takes it in
#: that window makes the whole run talk to a FOREIGN server, which answers
#: 200 and passes a readiness check that only asks "did something answer".
#: :func:`_server_port` therefore reads the port php itself chose, which
#: closes the window instead of narrowing it.
_SERVER_STARTED_RE = re.compile(
    r"Development Server \(http://(?P<host>[^:]+):(?P<port>\d+)\) started")

#: The identity every readiness probe must see.  The fixture deploys a
#: token-guarded bridge of its own (wpt/wpbridge/bridge.php with the test
#: token substituted) and asks IT, over a GET with no body — which the
#: bridge answers with its L4 structured error (``{"ok": false, "error":
#: "Syntax error", "type": "JsonException", ...}``, the shape
#: test_l4_invalid_json_returns_structured_error pins).  A reply only the
#: fixture's own ``php -S``, serving this docroot, with this bridge
#: deployed, can produce; a stray server on a recycled port 404s the file
#: or answers something else entirely.
_BRIDGE_IDENTITY = '"type":"JsonException"'

#: The harness must not let PHP CACHE anything between the docroot this
#: test writes and the server that reads it.  PHP's realpath cache is
#: per-process and lives for the life of the ``php -S`` worker, so a file
#: this suite writes AFTER the server started (every ``wpt-stub-ref-rows``
#: fixture, every deployed bridge) can be resolved to a path from BEFORE
#: the write — the classic cause of a suite that is green four times and
#: red the fifth, with a different victim each time.  The verification
#: round measured the cache as the cause: 2 flakes in 40 runs as shipped,
#: 0 in 40 with this off.
#: It is a HARNESS property, not a product one: the deployed bridge runs
#: under whatever the site's own php.ini sets, and a production request
#: pays a fresh cache per process.
_HARNESS_PHP_INI = ["-d", "realpath_cache_size=0"]


def _server_port(proc, log_path: Path) -> int | None:
    """The port php bound, out of its own startup line, or None.

    ``None`` means it has not said yet (or never will — the caller
    re-checks ``proc.poll()``), so the caller can retry instead of talking
    to whatever else may own the port it guessed.
    """
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return None
        try:
            text = log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        found = _SERVER_STARTED_RE.search(text)
        if found is not None:
            return int(found.group("port"))
        time.sleep(0.02)
    return None


def _wait_ready(proc, port: int) -> bool:
    """Is OUR ``php -S`` answering on ``port`` — not merely something?

    The check is the fixture's own bridge, so the answer names the docroot
    and the deployment, not just a port.  Anything else on that port (a
    recycled one, a developer's own server) fails here instead of silently
    routing the run's requests somewhere else — which is what made this
    file the suite's only flaky one, with a different victim each time.
    """
    deadline = time.monotonic() + 5
    url = f"http://127.0.0.1:{port}/bridge-test.php?t={TOKEN}"
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        try:
            response = requests.get(url, timeout=0.5)
        except requests.RequestException:
            time.sleep(0.05)
            continue
        if response.status_code == 200 and _BRIDGE_IDENTITY in response.text:
            return True
        time.sleep(0.05)
    return False


def _start_server(docroot: Path, tmp_path: Path, ini: list | None = None):
    """A php -S on the stub docroot, plus ``ini`` before the SAPI flags.

    ``ini`` exists for the tests that must make a runaway PHP DIE rather
    than take the host with it: the built-in server runs with
    ``memory_limit=-1`` by default, so a payload the deployed code cannot
    bound would exhaust the machine instead of failing the test.

    The port is CHOSEN BY PHP (``-S 127.0.0.1:0``) and read back out of its
    startup line, and readiness is the fixture's own bridge answering:
    neither step can be satisfied by something other than this server.  A
    failed attempt is retried with a fresh one, and a server that never
    becomes ready is terminated by this function (never by hand) so a
    failed start leaves no listener behind.
    """
    for attempt in range(3):
        log_path = tmp_path / f"php-server-{attempt}.log"
        fh = open(log_path, "w")
        proc = subprocess.Popen(
            ["php", *(ini or []), *_HARNESS_PHP_INI,
             "-S", "127.0.0.1:0", "-t", str(docroot)],
            stdout=fh,
            stderr=subprocess.STDOUT,
            cwd=str(docroot),
        )
        port = _server_port(proc, log_path)
        if port is not None and _wait_ready(proc, port):
            return proc, port, log_path, fh
        # this attempt is not the run's server: end it HERE, where its
        # process handle is, rather than leaving a listener nothing owns
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        fh.close()
    pytest.fail(f"could not start php -S; last log: {log_path.read_text()[-2000:]}")


def _build(tmp_path: Path, ini: list | None = None) -> BridgeEnv:
    """The harness docroot, the deployed bridges and a live ``php -S``.

    ``ini`` reaches ``php -d`` BEFORE the SAPI flags, for the tests that
    must make a runaway PHP DIE rather than take the host with it (see
    :func:`_start_server`).
    """
    if shutil.which("php") is None:
        pytest.fail("php CLI not found on PATH")
    docroot = tmp_path / "docroot"
    uploads = docroot / "wp-content" / "uploads"
    for rel in (
        "2023/10/pic.jpg",
        "2023/10/pic-300x233.jpg",
        "2023/10/unrelated.jpg",
        "2023/11/alt.png",
        "2023/11/alt-scaled.png",
        # NOT a YYYY/ path: the real migration's plugin-owned uploads
        # subtree (media_delete's former "must be under YYYY/" rule
        # refused every one of these and failed the whole trim).
        "bb-plugin/cache/sample-1-square.jpg",
        "bb-plugin/cache/thumb.png",
        "flat-root-level.jpg",
    ):
        p = uploads / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"wpt-fixture:" + rel.encode())
    # A DIRECTORY whose name carries a media extension: the media_map(db)
    # gate must refuse it (a directory in a keep-set protects nothing and
    # makes the answer unreadable), which is why the rule is not "has a
    # dot in the name" alone.
    (uploads / "2024" / "05" / "thumbs.jpg").mkdir(parents=True, exist_ok=True)
    (uploads / "2024" / "05" / "thumbs.jpg" / "index.html").write_bytes(b"dir")
    # A symlink INSIDE uploads whose target is outside it: the containment
    # layer media_delete must still refuse.
    outside_media = docroot / "wp-content" / "outside-secret.jpg"
    outside_media.write_bytes(b"wpt-fixture:outside-secret.jpg")
    os.symlink(outside_media, uploads / "bb-plugin" / "escape.jpg")

    # A real plugin tree, because get_plugins() is now built from the disk
    # the way core builds it: four header-bearing plugins (the inventory the
    # reconcile tests assert on) plus two files that are PRESENT on disk yet
    # deliberately absent from that inventory — a headerless stray and an
    # unreadable file, the two real ways core's own 'no_plugin_header'
    # verdict arises.
    for rel, body in (
        ("akismet/akismet.php", "Plugin Name: Akismet\nVersion: 5.3.1\n"),
        ("litespeed-cache/litespeed-cache.php",
         "Plugin Name: LiteSpeed Cache\nVersion: 6.5.0.2\n"),
        ("wp-super-cache/wp-super-cache.php",
         "Plugin Name: WP Super Cache\nVersion: 1.9.4\n"),
        ("hello.php", "Plugin Name: Hello Dolly\nVersion: 1.7.2\n"),
        ("headerless/headerless.php", "<?php\n// no plugin header at all\n"),
    ):
        p = docroot / "wp-content" / "plugins" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("<?php\n/*\n" + body + "*/\n", encoding="utf-8")
    unreadable = docroot / "wp-content" / "plugins" / "locked" / "locked.php"
    unreadable.parent.mkdir(parents=True, exist_ok=True)
    unreadable.write_text("<?php\n/*\nPlugin Name: Locked\nVersion: 1.0\n*/\n",
                          encoding="utf-8")
    if os.geteuid() != 0:
        # root ignores the mode bits, so the unreadable case is modelled
        # only where it can actually be modelled.
        unreadable.chmod(0o000)
    (docroot / "wp-config.php").write_text("<?php\n")
    (docroot / "wp-load.php").write_text(
        WP_LOAD_STUB.replace("__WPT_UPLOADS_DIR__", str(uploads)), encoding="utf-8"
    )
    # wp-admin/includes/plugin.php exists on every real install and is what
    # bridge.php's bootstrap requires when get_plugins() is missing. Here it
    # re-exposes the stub's plugin API; the wpt-stub-no-plugins marker models
    # a trimmed copy that loads but delivers nothing, which is the only way
    # the op's fail-closed inventory guard becomes reachable.
    admin_inc = docroot / "wp-admin" / "includes" / "plugin.php"
    admin_inc.parent.mkdir(parents=True, exist_ok=True)
    admin_inc.write_text(
        "<?php\n"
        "$wpt_root = dirname( __DIR__, 2 );\n"
        "if ( ! @is_file( $wpt_root . '/wpt-stub-no-plugins' ) ) {\n"
        "\trequire_once $wpt_root . '/wp-load.php';\n"
        "}\n",
        encoding="utf-8",
    )

    # wp-admin/includes/upgrade.php — what the core_upgrade op requires.
    # The stub models the OUTCOME core's own wp_upgrade() has (the stored
    # db_version moving to the version the just-swapped core targets) and
    # records the call, so the op's "the migration ran, and the answer is
    # the value read back from the database" contract is testable without
    # a WordPress install.  wpt-stub-upgrade-target names the target
    # schema version (wp-load publishes it as $wp_db_version, exactly as
    # the just-swapped wp-includes/version.php does on a real site);
    # wpt-stub-upgrade-noise makes the migration PRINT, the case the op
    # must absorb so the JSON envelope stays the wire contract; and
    # wpt-stub-upgrade-fat makes it exhaust the memory limit, which is the
    # non-catchable fatal the op's pre-migration marker exists for.
    upgrade_inc = admin_inc.with_name("upgrade.php")
    upgrade_inc.write_text(
        "<?php\n"
        "function wp_upgrade() {\n"
        "\twpt_stub_rec( 'wp_upgrade' );\n"
        "\tif ( @is_file( ABSPATH . 'wpt-stub-upgrade-fat' ) ) {\n"
        "\t\t// A real migration on a shared host with a modest\n"
        "\t\t// memory_limit: the fatal is NOT catchable, so the\n"
        "\t\t// request dies with the database unmoved and the\n"
        "\t\t// response un-JSON'd.  1 MiB at a time, forever.\n"
        "\t\t$hog = array();\n"
        "\t\twhile ( true ) { $hog[] = str_repeat( 'x', 1024 * 1024 ); }\n"
        "\t}\n"
        "\t// core's own write path (make_db_current_silent() does exactly\n"
        "\t// this), so the harness observes the migration through the\n"
        "\t// same option update every other op uses.\n"
        "\tupdate_option( 'db_version', $GLOBALS['wp_db_version'] );\n"
        "\tif ( @is_file( ABSPATH . 'wpt-stub-upgrade-big-noise' ) ) {\n"
        "\t\techo str_repeat( 'b', 5000 );\n"
        "\t}\n"
        "\tif ( @is_file( ABSPATH . 'wpt-stub-upgrade-binary' ) ) {\n"
        "\t\t// A host whose notices are not UTF-8 (a latin-1 error\n"
        "\t\t// log echoed into the buffer, an old extension).\n"
        "\t\techo \"\\xff\\xfe not utf-8 \\x00\";\n"
        "\t}\n"
        "\tif ( @is_file( ABSPATH . 'wpt-stub-upgrade-noise' ) ) {\n"
        "\t\techo \"stub: a notice the migration printed\\n\";\n"
        "\t}\n"
        "}\n",
        encoding="utf-8",
    )
    (docroot / "wpt-stub-upgrade-target").write_text("60356\n")

    # ------------------------------------------------------------------
    # The file half of a core update (core_upgrade_files).
    #
    # The op loads WordPress's OWN updater: wp-admin/includes/file.php for
    # get_filesystem_method() / WP_Filesystem() / unzip_file() / copy_dir(),
    # the upgrader classes for WP_Upgrader::unpack_package(), and
    # update-core.php for update_core().  Each is written to the docroot as
    # its own file so the op's require_once is the real one, and each is a
    # MODEL of core's body (there is no WordPress install here) — but two
    # of them do the REAL work, because the contract being pinned is which
    # core function the op calls and with what:
    #
    #   * unzip_file() really extracts the uploaded package (through the
    #     unzip binary, since this PHP has no ZipArchive), so the staging
    #     tree the later phases read is a real one;
    #   * copy_dir() really copies the tree onto ABSPATH, applying core's
    #     skip list per directory entry the way core's own loop does.
    #
    # Every call is recorded, which is what lets a test assert the op
    # called core's copy_dir with array('wp-content',
    # 'wp-includes/version.php') and core's unzip_file into
    # wp-content/upgrade/ — the two properties re-implementing placement
    # would have to get right, and the reason wpt does not re-implement it.
    #
    # wpt-stub-fs-method makes get_filesystem_method() answer something
    # else (a site whose files are owned by the FTP user, so core's own
    # updader would block on a credential prompt); wpt-stub-no-update-core
    # removes update-core.php, the trimmed install that has no core update
    # body at all; wpt-stub-core-copy-fails makes copy_dir() fail mid-tree,
    # the mixed old/new ABSPATH a real failed core update leaves behind.
    admin_inc.with_name("file.php").write_text(FILE_PHP_STUB, encoding="utf-8")
    admin_inc.with_name("class-wp-filesystem-base.php").write_text(
        FILESYSTEM_CLASS_STUB, encoding="utf-8")
    admin_inc.with_name("class-wp-filesystem-direct.php").write_text(
        FILESYSTEM_DIRECT_CLASS_STUB, encoding="utf-8")
    admin_inc.with_name("class-wp-upgrader.php").write_text(
        UPGRADER_CLASS_STUB, encoding="utf-8")
    admin_inc.with_name("class-wp-upgrader-skin.php").write_text(
        UPGRADER_SKIN_STUB, encoding="utf-8")
    admin_inc.with_name("class-wp-automatic-upgrader.php").write_text(
        AUTOMATIC_SKIN_STUB, encoding="utf-8")
    admin_inc.with_name("update-core.php").write_text(
        UPDATE_CORE_STUB, encoding="utf-8")
    # A core surface for the phases: a root php file, the version file the
    # copy replaces, the wp-content/index.php every install carries (so the
    # release's own wp-content entry has something it could overwrite, and
    # core's skip list can be shown NOT overwriting it), and the bundled
    # theme the release introduces.
    (docroot / "wp-includes").mkdir(parents=True, exist_ok=True)
    (docroot / "index.php").write_bytes(b"wpt-fixture:index.php\n")
    (docroot / "wp-includes" / "functions.php").write_bytes(
        b"wpt-fixture:functions.php\n")
    (docroot / "wp-content" / "index.php").write_bytes(
        b"wpt-fixture:wp-content-index.php\n")

    # core_md5 fixtures: plain core-style files in the webroot, plus one
    # lexically clean symlink whose realpath lands OUTSIDE the webroot —
    # the realpath containment-layer probe.
    for rel in ("wp-includes/version.php", "xmlrpc.php"):
        p = docroot / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"wpt-core-fixture:" + rel.encode())
    outside = tmp_path / "outside-secret.txt"
    outside.write_bytes(b"wpt-core-fixture:outside-secret.txt")
    os.symlink(outside, docroot / "wp-includes" / "link-out.php")

    src = BRIDGE_SOURCE.read_text(encoding="utf-8")
    assert "'__WPT_TOKEN__'" in src and "'__WPT_EXPIRES__'" in src, (
        "bridge must carry the upload-time placeholders"
    )

    def deploy(name: str, *, token: str = TOKEN, expires: int = EXPIRY_FUTURE) -> None:
        (docroot / name).write_text(
            src.replace("__WPT_TOKEN__", token).replace("__WPT_EXPIRES__", str(expires)),
            encoding="utf-8",
        )

    deploy("bridge-test.php")
    deploy("bridge-expired.php", expires=EXPIRY_PAST)
    deploy("bridge-destruct.php")

    proc, port, log_path, fh = _start_server(docroot, tmp_path, ini)
    return BridgeEnv(docroot, uploads, port, proc, log_path, fh)


class DocrootSource(WalkMixin):
    """The harness docroot as a real :class:`~wpt.types.Source`.

    The end-to-end seam both live defects live behind: the REAL
    ``wpt.wpbridge.client.Bridge`` (upload, token substitution, retry
    state machine, self-destruct) talking to the REAL ``php -S`` instance
    over HTTP, instead of the raw ``requests.post`` the rest of this file
    uses.  Only the storage medium is local.
    """

    def __init__(self, root: Path) -> None:
        self.root = str(root)

    def _abs(self, path: str) -> Path:
        return Path(self.root) / (self._guard_path(path) if path else "")

    def list_dir(self, path: str) -> list[Entry]:
        base = self._abs(path)
        if not base.is_dir():
            return []
        out = []
        for child in sorted(base.iterdir()):
            rel = f"{path.rstrip('/')}/{child.name}" if path else child.name
            out.append(Entry(path=rel, is_dir=child.is_dir(),
                             size=0 if child.is_dir() else child.stat().st_size,
                             is_link=child.is_symlink()))
        return out

    def read_bytes(self, path: str) -> bytes:
        target = self._abs(path)
        if not target.is_file():
            raise SourceError(f"no such file: {path}")
        return target.read_bytes()

    def write_bytes(self, path: str, data: bytes, *, allow_config: bool = False,
                    allow_core: bool = False) -> None:
        self._check_writable(path, allow_config, allow_core)
        self._abs(path).write_bytes(data)

    def delete(self, path: str) -> None:
        self._check_deletable(path)
        target = self._abs(path)
        if target.is_dir():
            for child in sorted(target.rglob("*"), reverse=True):
                child.rmdir() if child.is_dir() else child.unlink()
        target.rmdir() if target.is_dir() else target.unlink()

    def rmdir_recursive(self, path: str) -> None:
        target = self._abs(path)
        for child in sorted(target.rglob("*"), reverse=True):
            child.rmdir() if child.is_dir() else child.unlink()
        target.rmdir()

    def exists(self, path: str) -> bool:
        return self._abs(path).exists()

    def size(self, path: str) -> int:
        return self._abs(path).stat().st_size

    def close(self) -> None:
        pass


@pytest.fixture()
def bridge(tmp_path):
    env = _build(tmp_path)
    try:
        yield env
    finally:
        env.close()


# ---------------------------------------------------------------------------
# Syntax gate + placeholder contract
# ---------------------------------------------------------------------------

def test_bridge_php_lint():
    proc = subprocess.run(["php", "-l", str(BRIDGE_SOURCE)], capture_output=True, text=True)
    assert proc.returncode == 0
    assert "No syntax errors" in proc.stdout


def test_bridge_placeholders_present():
    src = BRIDGE_SOURCE.read_text(encoding="utf-8")
    assert "'__WPT_TOKEN__'" in src
    assert "'__WPT_EXPIRES__'" in src


# ---------------------------------------------------------------------------
# Auth gate
# ---------------------------------------------------------------------------

def test_auth_missing_token_404(bridge):
    r = requests.get(bridge.url(token=None), timeout=10)
    assert r.status_code == 404
    assert r.content == b"nf"
    assert r.headers["Content-Type"].startswith("text/plain")


def test_auth_invalid_token_404(bridge):
    r = requests.get(bridge.url(token="f" * 32), timeout=10)
    assert r.status_code == 404
    assert r.content == b"nf"


def test_auth_expired_token_404(bridge):
    r = requests.get(bridge.url("bridge-expired.php"), timeout=10)
    assert r.status_code == 404
    assert r.content == b"nf"


def test_selfdestruct_unlinks_bridge(bridge):
    target = bridge.docroot / "bridge-destruct.php"
    assert target.exists()
    r = requests.get(bridge.url("bridge-destruct.php", selfdestruct=1), timeout=10)
    assert r.status_code == 200
    assert r.content == b"gone"
    assert not target.exists()
    # the sibling deployments are untouched
    assert (bridge.docroot / "bridge-test.php").exists()


# ---------------------------------------------------------------------------
# L4: opaque 500s become structured JSON
# ---------------------------------------------------------------------------

def test_l4_invalid_json_returns_structured_error(bridge):
    r = bridge.call(body="not-json{")
    assert r.status_code == 200
    assert r.headers["Content-Type"].startswith("application/json")
    data = r.json()
    assert data["ok"] is False
    assert data["type"] == "JsonException"
    assert isinstance(data["line"], int)
    assert data["error"]


def test_l4_handler_throwable_returns_structured_error(bridge):
    # media_delete hits the stub wpdb, whose DELETE for sentinel ID 424242
    # throws; the bridge must answer structured JSON, not an opaque 500.
    before = len(bridge.calls())
    r = bridge.call("media_delete", {"ids": [424242]})
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is False
    assert data["type"] == "RuntimeException"
    assert isinstance(data["line"], int)
    assert "424242" in data["error"]
    new_calls = bridge.calls()[before:]
    assert "START TRANSACTION" in new_calls
    assert "ROLLBACK" in new_calls  # atomic: the transaction is rolled back
    assert "COMMIT" not in new_calls


def test_unknown_action_refused(bridge):
    data = bridge.call("does_not_exist").json()
    assert data["ok"] is False
    assert data["error"] == "unknown action"


def test_missing_action_refused(bridge):
    data = bridge.call(body=json.dumps({"params": {}})).json()
    assert data["ok"] is False
    assert data["error"] == "missing action"


def test_non_object_body_refused(bridge):
    data = bridge.call(body=json.dumps([1, 2])).json()
    assert data["ok"] is False
    assert "JSON object" in data["error"]


# ---------------------------------------------------------------------------
# info
# ---------------------------------------------------------------------------

def test_info(bridge):
    r = bridge.call("info")
    assert r.status_code == 200
    assert r.headers["Content-Type"].startswith("application/json")
    data = r.json()
    assert data["ok"] is True
    assert data["wp_version"] == "6.4.2"
    assert data["siteurl"] == "https://example.test"
    assert data["home"] == "https://example.test"
    assert data["template"] == "twentytwentyfour"
    assert data["stylesheet"] == "twentytwentyfour"
    assert data["blog_public"] == 1
    # [L17] the site locale — WP's own get_locale() over the WPLANG
    # option (the stub models an observed localized migration sites)
    assert data["locale"] == "fr_CA"
    # the harden action's pretty-permalink gate: '' would mean plain
    # ?p=N permalinks (WordPress's own default); the stub site is pretty
    assert data["permalink_structure"] == "/%year%/%monthnum%/%day%/%postname%/"
    plugins = data["plugins"]
    assert set(plugins) == {
        "akismet/akismet.php",
        "litespeed-cache/litespeed-cache.php",
        "hello.php",
        "wp-super-cache/wp-super-cache.php",
    }
    assert plugins["akismet/akismet.php"] == {"name": "Akismet", "version": "5.3.1", "active": True}
    assert plugins["litespeed-cache/litespeed-cache.php"]["active"] is True
    assert plugins["hello.php"] == {"name": "Hello Dolly", "version": "1.7.2", "active": True}
    assert plugins["wp-super-cache/wp-super-cache.php"] == {
        "name": "WP Super Cache", "version": "1.9.4", "active": False,
    }
    assert data["mu_plugins"] == 0
    assert data["uploads_basedir"] == str(bridge.uploads)
    assert data["uploads_error"] == ""
    assert data["abspath"] == str(bridge.docroot) + "/"
    # environment facts (B): live PHP values come from the same php binary
    # that serves the harness; the rest are stubbed.
    php = subprocess.run(
        ["php", "-r", "echo PHP_VERSION, \"\\n\", PHP_VERSION_ID;"],
        capture_output=True, text=True,
    )
    php_version, php_version_id = php.stdout.splitlines()
    assert data["php_version"] == php_version
    assert data["php_version_id"] == int(php_version_id)
    assert isinstance(data["memory_limit"], str) and data["memory_limit"] != ""
    assert isinstance(data["max_execution_time"], str) and data["max_execution_time"] != ""
    assert data["sapi"] == "cli-server"  # the php -S built-in server
    assert isinstance(data["server_software"], str) and data["server_software"] != ""
    assert data["mysql_version"] == "8.0.36"  # stub wpdb db_version()
    assert data["wp_debug"] is True  # stub wp-load defines WP_DEBUG


def test_info_corrupt_option_values_stay_json(bridge):
    """A non-string siteurl / home / template / stylesheet / WPLANG /
    permalink_structure (a corrupt or tampered options row — core hands
    them to the op verbatim) must not be string-cast: PHP's "Array to
    string conversion" notice is printed BEFORE the JSON under the
    bridge's display_errors, which would corrupt the WHOLE info answer
    (SPEC R12) over one bad row.  Every scalar option answers '' through
    the one wpt_option_scalar() owner — the shape each consumer already
    reads as unknown (the harden gate reads '' as plain ?p=N permalinks;
    an empty locale resolves to en_US).  The successful .json() parse
    above IS the R12 regression pin."""
    (bridge.docroot / "wpt-stub-corrupt-options").write_text("")
    r = bridge.call("info")
    assert r.status_code == 200
    data = r.json()          # a printed notice would raise here
    assert data["ok"] is True
    assert data["permalink_structure"] == ""
    assert data["locale"] == ""
    assert data["siteurl"] == ""
    assert data["home"] == ""
    assert data["template"] == ""
    assert data["stylesheet"] == ""
    # An object-valued blog_public is scalar-gated before the int cast, so
    # the answer stays JSON and the fact degrades to 0 (unknown), not a
    # printed "Object of class stdClass could not be converted to int".
    assert data["blog_public"] == 0
    # the rest of the answer is intact — one bad row costs one fact
    assert data["wp_version"] == "6.4.2"


# ---------------------------------------------------------------------------
# db_audit
# ---------------------------------------------------------------------------

def test_db_audit(bridge):
    data = bridge.call("db_audit").json()
    assert data["ok"] is True
    assert {"post_type": "post", "post_status": "publish", "count": 3} in data["posts"]
    assert data["revisions"] == 5
    assert data["expired_transients"] == 2
    assert data["orphan_meta"] == {"postmeta": 4, "termmeta": 1, "commentmeta": 2}
    # scalar counts are measured ints, never null, on a healthy database
    assert {"name": "wp_options", "rows": 42, "size_mb": 0.5, "data_free_kb": 8.0,
            "collation": "utf8mb4_general_ci"} in data["tables"]
    assert {"name": "wp_posts", "rows": 7, "size_mb": 1.25, "data_free_kb": 32.0,
            "collation": "latin1_swedish_ci"} in data["tables"]
    # NULL TABLE_COLLATION becomes "" on the wire (unknown, not a real collation)
    assert {"name": "wp_comments", "rows": 0, "size_mb": 0.03, "data_free_kb": 0.0,
            "collation": ""} in data["tables"]
    assert data["autoload_bytes"] == 123456
    assert data["attachments"] == 7
    assert data["nav_menu_items"] == 2


def test_db_audit_failed_count_is_unknown_not_zero(bridge):
    # A failed COUNT query must stay UNKNOWN (null), never a measured 0.
    # get_var() returns null on failure; an (int) cast would silently turn
    # that into 0, making a broken/unreadable table read as a clean DB — the
    # None=unknown wire contract the Python audit data layer depends on.
    (bridge.docroot / "wpt-stub-count-fails").write_text("")
    data = bridge.call("db_audit").json()
    assert data["ok"] is True
    assert data["revisions"] is None  # query failed -> unknown, NOT 0
    # healthy counts in the same payload are still measured ints
    assert data["expired_transients"] == 2
    assert isinstance(data["autoload_bytes"], int)
    assert data["orphan_meta"] == {"postmeta": 4, "termmeta": 1, "commentmeta": 2}


def test_db_audit_users_admins_only_wire(bridge):
    before = len(bridge.calls())
    data = bridge.call("db_audit").json()
    assert data["ok"] is True
    # admins only (user_level = 10), login-ordered; a NULL user_registered
    # cell stays null on the wire; every entry carries the admin flag
    assert data["users"] == [
        {"login": "admin", "registered": "2019-05-14 09:30:00", "admin": True},
        {"login": "legacy", "registered": None, "admin": True},
        {"login": "site_owner", "registered": "2020-01-02 03:04:05", "admin": True},
    ]
    new_calls = bridge.calls()[before:]
    users_sql = next(c for c in new_calls if "user_level" in c)
    assert "FROM wp_users u" in users_sql
    assert "INNER JOIN wp_usermeta um ON um.user_id = u.ID" in users_sql
    assert "meta_key = 'wp_user_level'" in users_sql  # table-prefix discovery
    assert "meta_value = '10'" in users_sql           # WP's admin level marker
    assert len([c for c in new_calls if "user_level" in c]) == 1  # ONE extra query


def test_db_audit_users_null_when_usermeta_undiscoverable(bridge):
    (bridge.docroot / "wpt-stub-no-usermeta").write_text("")
    data = bridge.call("db_audit").json()
    assert data["ok"] is True
    assert data["users"] is None  # unknown — never a measured []
    # the rest of db_audit is unaffected
    assert data["revisions"] == 5
    assert {"name": "wp_options", "rows": 42, "size_mb": 0.5, "data_free_kb": 8.0,
            "collation": "utf8mb4_general_ci"} in data["tables"]


# ---------------------------------------------------------------------------
# db_clean
# ---------------------------------------------------------------------------

def test_db_clean_unknown_op(bridge):
    data = bridge.call("db_clean", {"ops": ["drop_everything"]}).json()
    assert data["ok"] is False
    assert data["error"] == "unknown op"


def test_db_clean_revisions_hits_canned_wpdb(bridge):
    before = len(bridge.calls())
    data = bridge.call("db_clean", {"ops": ["revisions"]}).json()
    assert data["ok"] is True
    assert data["errors"] == {}
    assert data["results"] == {"revisions": 1}
    new_calls = bridge.calls()[before:]
    assert any(
        c.startswith("DELETE FROM wp_posts") and "'revision'" in c and "'auto-draft'" in c
        for c in new_calls
    )


def test_db_clean_all_ops(bridge):
    data = bridge.call("db_clean", {"ops": ["revisions", "expired_transients", "orphan_meta", "optimize_tables"]}).json()
    assert data["ok"] is True
    assert data["errors"] == {}
    assert data["results"] == {
        "revisions": 1,
        "expired_transients": 1,
        "orphan_meta": 3,
        # one OPTIMIZE per whitelisted table — the stub's WordPress schema
        "optimize_tables": 9,
    }


# ---------------------------------------------------------------------------
# media_map (L5) / media_delete
# ---------------------------------------------------------------------------

def test_l5_media_map_stem_matching(bridge):
    # Ref is a size variant; attachment 101 has _wp_attached_file but NO
    # _wp_attachment_metadata (migrated site). Resolution must go through
    # stem stripping, and variants must come from the on-disk scan.
    r = bridge.call("media_map", {"refs": [
        "2023/10/pic.jpg",           # exact match
        "2023/09/pic.jpg",           # basename match
        "2023/10/pic-300x233.jpg",   # stem match (L5)
    ]})
    data = r.json()
    assert data["ok"] is True
    refs = data["refs"]
    assert refs["2023/10/pic.jpg"] == {"id": 101, "file": "2023/10/pic.jpg"}
    assert refs["2023/09/pic.jpg"] == {"id": 101, "file": "2023/10/pic.jpg"}
    assert refs["2023/10/pic-300x233.jpg"] == {"id": 101, "file": "2023/10/pic.jpg"}
    att = data["attachments"]["101"]
    assert att["file"] == "2023/10/pic.jpg"
    # L5 proof: the on-disk sibling is found without metadata
    assert "2023/10/pic-300x233.jpg" in att["variants"]
    assert "2023/10/pic.jpg" in att["variants"]
    assert not any(v.endswith("unrelated.jpg") for v in att["variants"])


def test_media_map_variants_union_metadata_and_disk(bridge):
    # 102 has a full size map (one size NOT on disk); the union must contain
    # metadata sizes AND same-dir on-disk stem matches.
    data = bridge.call("media_map", {"refs": ["2023/11/alt-scaled.png"]}).json()
    assert data["ok"] is True
    assert data["refs"]["2023/11/alt-scaled.png"]["id"] == 102
    att = data["attachments"]["102"]
    assert att["file"] == "2023/11/alt.png"
    assert att["variants"] == sorted([
        "2023/11/alt.png",          # original (same stem, on disk)
        "2023/11/alt-scaled.png",   # on-disk sibling
        "2023/11/alt-150x150.png",  # metadata size (basename form)
        "2023/11/alt-odd.png",       # metadata size (uploads-relative form, not on disk)
    ])


def test_media_map_db_mode_returns_the_database_reference_set(bridge):
    # media_map mode=db: the OTHER half of the media keep-set.  A page
    # renders only a fraction of its attachment images, so this set is
    # what a walk-only trim would delete (measured live: most of the media files and bytes, database-referenced only).
    data = bridge.call("media_map", {"mode": "db"}).json()
    assert data["ok"] is True
    assert data["db_refs"] == sorted([
        # 1. every attachment's own path (_wp_attached_file)
        "2023/10/pic.jpg",
        "2023/11/alt.png",
        "2023/12/legacy.png",
        # 2. the four load-bearing metadata forms
        "2023/11/alt-150x150.png",   # sizes[*].file, bare basename + anchor
        "2023/11/alt-odd.png",       # sizes[*].file, uploads-relative
        "2023/12/legacy-1024x768.png",  # legacy _wp_attachment_backup_sizes
        # 3. a metadata row with no anchor resolves at the uploads ROOT,
        #    never into a directory it does not belong to
        "orphan-150x150.png",
        # 4. a postmeta value naming an uploads path (elementor-style)
        "2024/01/bg.png",
        # 5. post content, excerpt and guid
        "2023/11/brochure.pdf",
        "2023/11/gallery-1.jpg",
        "2023/11/guid-only.jpg",
        # 6. an option value (theme options / widgets)
        "2024/02/logo.png",
        # 7. term meta (category media)
        "2024/03/category.jpg",
    ])


def test_media_map_db_mode_issues_only_read_only_unbounded_queries(bridge):
    # read-only by construction (SELECT only, no LIMIT: a truncated
    # keep-set is a deletion bug) over $wpdb's own whitelisted tables
    before = len(bridge.calls())
    assert bridge.call("media_map", {"mode": "db"}).json()["ok"] is True
    sql = bridge.calls()[before:]
    assert sql, "the db map must reach the database"
    for statement in sql:
        assert statement.lstrip().upper().startswith("SELECT ")
        assert "LIMIT" not in statement.upper()
    # every reference class is covered by its own query
    assert any("_wp_attached_file" in q for q in sql)
    assert any("_wp_attachment_backup_sizes" in q for q in sql)
    assert any("post_content" in q for q in sql)
    assert any("option_value" in q for q in sql)
    assert any("wp_termmeta" in q for q in sql)


def test_media_map_db_mode_needs_no_refs(bridge):
    # the mode replaces the refs parameter entirely (no refs -> the
    # refs->ids map would be meaningless, and requiring it would make the
    # op unusable for the database map)
    data = bridge.call("media_map", {"mode": "db"}).json()
    assert "refs" not in data and "attachments" not in data
    assert data["db_refs"]


def test_media_map_unknown_mode_is_refused(bridge):
    # the mode is a closed set: a typo must never silently answer the
    # refs->ids map when the caller asked for the database one
    data = bridge.call("media_map", {"mode": "everything"}).json()
    assert data["ok"] is False
    assert "unknown media_map mode" in data["error"]


def test_media_map_unresolvable_ref(bridge):
    data = bridge.call("media_map", {"refs": ["2023/10/nothing-here.jpg"]}).json()
    assert data["refs"]["2023/10/nothing-here.jpg"] == {"id": None, "file": None}
    assert data["attachments"] == {}


def test_media_delete_deletes_posts_and_unlinks(bridge):
    r = bridge.call("media_delete", {"ids": [101], "files": ["2023/10/pic.jpg"]})
    data = r.json()
    assert data["ok"] is True
    assert data["deleted_posts"] == 1
    assert data["deleted_meta"] == 1
    assert data["deleted_termrels"] == 1
    assert data["deleted_files"] == 1
    assert data["skipped_missing"] == 0
    assert data["unlink_failures"] == []  # authoritative: nothing refused
    assert not (bridge.uploads / "2023" / "10" / "pic.jpg").exists()
    assert (bridge.uploads / "2023" / "10" / "pic-300x233.jpg").exists()  # only the listed file
    assert (bridge.docroot / "wp-config.php").exists()


def test_media_delete_reports_unlink_failure(bridge):
    # A file the server cannot unlink must be reported in unlink_failures so
    # the caller verifies the deletion instead of assuming it. Replace the
    # target with a DIRECTORY: unlink() on a directory fails (EISDIR) even for
    # root, faithfully modeling a refused unlink.
    target = bridge.uploads / "2023" / "11" / "alt.png"
    target.unlink()
    target.mkdir()
    data = bridge.call("media_delete", {"ids": [], "files": ["2023/11/alt.png"]}).json()
    assert data["ok"] is True
    assert data["unlink_failures"] == ["2023/11/alt.png"]
    assert data["deleted_files"] == 0
    assert target.exists()  # the refused target is still there


def test_media_delete_traversal_refused(bridge):
    before = len(bridge.calls())
    r = bridge.call("media_delete", {"ids": [101], "files": ["../wp-config.php"]})
    data = r.json()
    assert r.status_code == 200
    assert data["ok"] is False
    assert "refused" in data["error"]
    # nothing was unlinked and nothing was deleted (validate-before-mutate)
    assert (bridge.docroot / "wp-config.php").exists()
    assert (bridge.uploads / "2023" / "10" / "pic.jpg").exists()
    new_calls = bridge.calls()[before:]
    assert not any(c.startswith("DELETE FROM") for c in new_calls)
    assert not any(c == "START TRANSACTION" for c in new_calls)


# The production failure: a real migration's trim-media plan carried many
# unreferenced uploads, among them plugin-owned paths under
# wp-content/uploads/bb-plugin/cache/. The former "must be under YYYY/" rule
# refused every one of them, so EVERY apply failed closed and zero files were
# ever deleted. The rule was a LAYOUT assumption dressed as a safety one; the
# safety claim is "resolves inside the uploads basedir", and that is what the
# op now enforces.

def test_media_delete_non_YYYY_uploads_paths(bridge):
    r = bridge.call("media_delete", {
        "ids": [],
        "files": [
            "bb-plugin/cache/sample-1-square.jpg",
            "flat-root-level.jpg",
        ],
    })
    data = r.json()
    assert data["ok"] is True
    assert data["deleted_files"] == 2
    assert data["unlink_failures"] == []
    assert not (bridge.uploads / "bb-plugin" / "cache"
                / "sample-1-square.jpg").exists()
    assert not (bridge.uploads / "flat-root-level.jpg").exists()
    # the sibling under the SAME plugin cache dir is untouched
    assert (bridge.uploads / "bb-plugin" / "cache" / "thumb.png").exists()


def test_media_delete_containment_is_a_directory_boundary_not_a_prefix(bridge):
    # The containment test must compare against basedir . DIRECTORY_SEPARATOR.
    # A bare string-prefix test would accept a SIBLING directory whose name
    # merely starts with the uploads directory's name — the classic
    # "uploads-evil" confusion — and unlink a file the operator never named.
    evil = bridge.docroot / "wp-content" / "uploads-evil"
    evil.mkdir()
    (evil / "secret.txt").write_bytes(b"wpt-fixture:uploads-evil")
    data = bridge.call("media_delete", {
        "ids": [], "files": ["../uploads-evil/secret.txt"],
    }).json()
    # The lexical ".." pass refuses it first (it is the same traversal
    # shape); the point of the fixture is that the realpath layer alone
    # would not have accepted it either.
    assert data["ok"] is False
    assert "traversal" in data["error"]
    assert (evil / "secret.txt").exists()
    # And with a lexically clean path that still resolves outside uploads,
    # the symlink layer refuses rather than prefix-matching.
    data = bridge.call("media_delete", {
        "ids": [], "files": ["bb-plugin/escape.jpg"],
    }).json()
    assert data["ok"] is False
    # The final component is a link, refused without following it.
    assert "symlink" in data["error"]
    assert (bridge.docroot / "wp-content" / "outside-secret.jpg").exists()
    assert (bridge.uploads / "bb-plugin" / "escape.jpg").is_symlink()


def test_media_delete_windows_shaped_traversal_refused(bridge):
    # The lexical pass must recognize ".." segments on BOTH separator
    # flavours. On a Linux host the backslash form is an ordinary filename
    # character, so the realpath layer alone would simply report the file as
    # missing and tolerate it — the request would then delete the OTHER
    # listed files while the operator's traversal-shaped entry sailed
    # through unexamined. A Windows host, where "\" IS a separator, would
    # have resolved it out of uploads entirely.
    for path in ("..\\..\\wp-config.php", "bb-plugin\\..\\..\\escape.jpg"):
        before = len(bridge.calls())
        data = bridge.call("media_delete", {"ids": [101], "files": [path]}).json()
        assert data["ok"] is False, path
        assert "refused path (traversal)" in data["error"], path
        new_calls = bridge.calls()[before:]
        assert not any(c.startswith("DELETE FROM") for c in new_calls), path


def test_media_delete_symlink_swapped_in_during_the_transaction_is_never_unlinked(bridge):
    # Time-of-check to time-of-use, REPRODUCED. media_delete validates every
    # path, then runs its DB transaction, then unlinks. Anyone who can write
    # inside uploads (an authenticated uploader, a plugin with a file-write
    # bug) can, in that window, rename a validated parent directory aside and
    # drop a symlink in its place: the unlink then lands on an arbitrary
    # file OUTSIDE uploads. The swap is scripted to fire on COMMIT, i.e.
    # exactly at the widest point of the window.
    decoy = bridge.docroot / "wp-content" / "attacker" / "pic.jpg"
    decoy.parent.mkdir(parents=True, exist_ok=True)
    decoy.write_bytes(b"wpt-fixture:must-survive")
    (bridge.docroot / "wpt-stub-swap-on-commit").write_text(json.dumps({
        "dir": str(bridge.uploads / "2023" / "10"),
        "link_to": str(decoy.parent),
    }), encoding="utf-8")
    data = bridge.call("media_delete", {
        "ids": [101], "files": ["2023/10/pic.jpg"],
    }).json()
    assert data["ok"] is True
    # The file OUTSIDE uploads the swapped unlink would have hit is intact.
    assert decoy.exists(), "an uploads path was turned into an outside unlink"
    # The validated file itself was not deleted either — the re-check
    # refused, and the refusal is REPORTED so the caller's apply fails
    # closed instead of claiming a successful deletion.
    assert data["deleted_files"] == 0
    assert data["unlink_failures"] == ["2023/10/pic.jpg"]
    assert "swap-on-commit" in bridge.calls()


def test_media_delete_file_replaced_in_place_during_the_transaction_is_never_unlinked(bridge):
    # The other half of the re-check: the path still resolves inside
    # uploads, but the file AT it is no longer the one that was validated
    # (a freshly uploaded file reusing the name, or the attacker's own
    # swap). Deleting it would remove a file no plan ever named.
    target = bridge.uploads / "2023" / "11" / "alt.png"
    (bridge.docroot / "wpt-stub-swap-on-commit").write_text(json.dumps({
        "replace": str(target),
    }), encoding="utf-8")
    # ids are what make the op run its transaction, and the transaction is
    # where the swap fires — the same window the symlink case uses.
    data = bridge.call("media_delete", {
        "ids": [101], "files": ["2023/11/alt.png"],
    }).json()
    assert data["ok"] is True
    assert data["deleted_files"] == 0
    assert data["unlink_failures"] == ["2023/11/alt.png"]
    assert target.exists()
    assert target.read_bytes() == b"wpt-swap-replacement\n"


def test_media_delete_concurrently_removed_file_is_tolerated_not_a_failure(bridge):
    # The re-check's 'gone' verdict is the pre-existing `skipped_missing`
    # case (a file another request removed between the two passes): it is
    # counted, never reported as an unlink failure, so a harmless race
    # cannot fail an otherwise complete trim.
    target = bridge.uploads / "2023" / "11" / "alt-scaled.png"
    (bridge.docroot / "wpt-stub-swap-on-commit").write_text(json.dumps({
        "unlink": str(target),
    }), encoding="utf-8")
    data = bridge.call("media_delete", {
        "ids": [101], "files": ["2023/11/alt-scaled.png", "flat-root-level.jpg"],
    }).json()
    assert data["ok"] is True
    assert data["skipped_missing"] == 1
    assert data["unlink_failures"] == []
    assert data["deleted_files"] == 1
    assert not (bridge.uploads / "flat-root-level.jpg").exists()


def test_R25_media_delete_refuses_a_final_symlink_and_keeps_its_target(bridge):
    """R25-P1: ``media_delete`` realpath()'d the requested path and unlinked
    the RESOLVED target, leaving the link.  A planned file replaced by a link
    after the plan could delete a protected media file.  The final component
    is inspected unresolved and refused; the link and its target survive."""
    link = bridge.uploads / "2023" / "10" / "link.jpg"
    target = bridge.uploads / "2023" / "10" / "pic.jpg"
    os.symlink("pic.jpg", link)
    before = target.read_bytes()
    data = bridge.call("media_delete", {
        "ids": [], "files": ["2023/10/link.jpg"],
    }).json()
    assert data["ok"] is False
    assert "refused path (symlink)" in data["error"]
    assert link.is_symlink()
    assert target.exists()
    assert target.read_bytes() == before


def test_media_delete_refusal_text_family_and_shapes(bridge):
    # Every refusal keeps the "refused path (...)" text family the callers
    # and the existing tests key on, and the safety refusals survive: an
    # absolute path, a ".." segment, an empty path, and a symlink whose
    # target escapes the uploads basedir.
    for path, marker in (
        ("/etc/passwd", "absolute"),
        ("../../etc/passwd", "traversal"),
        ("bb-plugin/../../wp-config.php", "traversal"),
        ("", "empty"),
        # A final-component link is refused BEFORE resolving what it points
        # at; the target still survives (the old message said "outside
        # uploads" only because it had already resolved the link).
        ("bb-plugin/escape.jpg", "symlink"),
    ):
        before = len(bridge.calls())
        data = bridge.call("media_delete", {"ids": [101], "files": [path]}).json()
        assert data["ok"] is False, path
        assert data["error"].startswith("refused path ("), path
        assert marker in data["error"], (path, data["error"])
        # fail-closed: validate-before-mutate still holds
        new_calls = bridge.calls()[before:]
        assert not any(c.startswith("DELETE FROM") for c in new_calls), path
        assert not any(c == "START TRANSACTION" for c in new_calls), path
    # nothing outside uploads was touched
    assert (bridge.docroot / "wp-content" / "outside-secret.jpg").exists()
    assert (bridge.uploads / "bb-plugin" / "escape.jpg").exists()
    assert (bridge.docroot / "wp-config.php").exists()
    # a NUL byte is stripped BEFORE resolution, so the path still addresses
    # the file it names (and only that one)
    data = bridge.call("media_delete", {"ids": [], "files": [
        "bb-plugin/cache/thumb.png\x00",
    ]}).json()
    assert data["ok"] is True
    assert data["deleted_files"] == 1
    assert not (bridge.uploads / "bb-plugin" / "cache" / "thumb.png").exists()


# ---------------------------------------------------------------------------
# media_map(mode=db) — the ref gate (the observed defect)
# ---------------------------------------------------------------------------

def db_map(bridge):
    data = bridge.call("media_map", {"mode": "db"}).json()
    assert data["ok"] is True
    return data


def test_media_map_db_mode_drops_a_bare_year_directory(bridge):
    # THE LIVE DEFECT: a stale _transient_dirsize_cache option on a real
    # site held many absolute paths to the site's PREVIOUS host, several of
    # them bare YEAR DIRECTORIES ("2018".."2023").  The extractor took a
    # directory as a file reference, the client's all-or-nothing check
    # refused the WHOLE answer, and one junk row silently disabled the
    # union keep-set for the entire site.
    data = db_map(bridge)
    for year in ("2018", "2019", "2020", "2021", "2022", "2023"):
        assert year not in data["db_refs"], year
    assert "2023/10/pic.jpg" in data["db_refs"], "the real file in that row was lost"
    assert data["db_refs_dropped"] >= 6


def test_media_map_db_mode_maps_an_old_host_absolute_path_to_its_uploads_tail(bridge):
    # A site migrated off another host stores paths rooted at the OLD
    # home directory.  The tail after the uploads marker IS this site's
    # path, so the reference survives the migration — dropping it would
    # leave a live image unprotected.
    refs = db_map(bridge)["db_refs"]
    assert "2023/10/pic.jpg" in refs
    assert not any(r.startswith("/") for r in refs)
    assert not any("hostaccount" in r for r in refs)


def test_media_map_db_mode_drops_an_old_host_path_with_a_junk_tail(bridge):
    # No uploads anchor, and a traversing tail: neither names a file in
    # this site's uploads tree, so neither is a reference.
    refs = db_map(bridge)["db_refs"]
    assert not any("wp-images" in r for r in refs)
    assert not any(".." in r or r.startswith("/") for r in refs)
    assert "evil.jpg" not in refs


def test_media_map_db_mode_drops_a_non_media_extension(bridge):
    # A reference must name a file the keep-set can act on: the family is
    # the same media.extensions allowlist the walk/trim gate files by (a
    # ".php" under uploads is exactly the L14 hazard, never media).
    refs = db_map(bridge)["db_refs"]
    assert "2023/10/notes.txt.php" not in refs
    assert not any(r.endswith(".php") for r in refs)
    # ... and the family is the SHIPPED profile default, pinned below.
    assert "2023/11/brochure.pdf" in refs      # a real document IS a ref
    assert "2023/11/alt.png" in refs


def test_media_map_db_mode_drops_an_existing_directory_named_like_a_media_file(bridge):
    # "2024/05/thumbs.jpg" is a real DIRECTORY in the fixture uploads tree
    # (a thumb cache).  A directory in a keep-set protects nothing and
    # makes the answer unreadable, so the on-disk test refuses it even
    # though its extension is in the family.
    assert (bridge.uploads / "2024" / "05" / "thumbs.jpg").is_dir()
    assert "2024/05/thumbs.jpg" not in db_map(bridge)["db_refs"]


def test_media_map_db_mode_survives_a_media_path_with_a_query_string(bridge):
    # "?ver=3" is cache-busting, not part of the name: the ref keeps the
    # file's real path (and the walker/keep-set match it against that).
    refs = db_map(bridge)["db_refs"]
    # three stored paths name that one file (bare tail, old-host absolute,
    # and the "?ver=" form); the answer carries it ONCE, with no query
    assert refs.count("2023/10/pic.jpg") == 1
    assert not any("?" in r or "#" in r for r in refs)


def test_media_map_db_refs_is_a_plain_list_of_strings(bridge):
    # A PHP array key that looks like an integer is silently renumbered,
    # so a path-keyed map would encode as {"2018": ...} and the client
    # would read the WHOLE answer as untrustworthy.  The wire shape is a
    # JSON ARRAY of strings, structurally.
    r = bridge.call("media_map", {"mode": "db"})
    raw = json.loads(r.text)["db_refs"]
    assert isinstance(raw, list)
    assert all(isinstance(entry, str) for entry in raw)
    assert raw == sorted(raw)
    # no numeric-looking key reached the encoding at all
    assert not any(entry.isdigit() for entry in raw)
    # The strval() backstop is deliberately UNREACHABLE while the gate holds
    # (a canonical integer string carries neither a dot nor a slash, so it
    # can never be a gated ref): it is pinned textually so removing it does
    # not quietly make the wire shape depend on the gate alone.
    assert "$out = array_map( 'strval', array_keys( $refs ) );" in \
        BRIDGE_SOURCE.read_text(encoding="utf-8")


def test_media_map_db_mode_one_stale_transient_does_not_kill_the_keep_set(bridge):
    # The end-to-end shape of the live failure, as the CLIENT sees it: the
    # answer is a full, usable keep-set with a reported loss, not a
    # refusal.  (The client's own half of this contract is pinned in
    # tests/test_bridge_client.py.)
    data = db_map(bridge)
    assert data["db_refs"], "the union lost everything over one junk row"
    assert "2023/10/pic.jpg" in data["db_refs"]      # the old-host file
    assert "2023/12/legacy.png" in data["db_refs"]   # untouched surfaces
    assert isinstance(data["db_refs_dropped"], int) and data["db_refs_dropped"] > 0


def test_media_ref_extension_family_is_the_shipped_profile_default():
    # The bridge is DEPLOYED on a host that cannot read the operator's
    # profile, so the family is mirrored here — and mirrored means PINNED:
    # editing wpt/data/profiles/default.json's media.extensions without this
    # list (or the reverse) fails this test.  The mirror is the DEFAULT the
    # effective family is unioned with, i.e. the FLOOR a request can never
    # go below (a read carries the caller's own family on top of it — see
    # test_media_map_db_mode_* below), so the shipped default is still the
    # one list all three copies must agree on.
    from wpt import settings
    default = json.loads((REPO / "wpt" / "data" / "profiles" / "default.json").read_text())
    assert settings.load(str(REPO / "wpt" / "data" / "profiles" / "default.json")).media.extensions \
        == default["media"]["extensions"]
    body = re.search(
        r"function wpt_media_ref_extensions\(.*?\{\s*\$refused = false;"
        r"\s*\$default = array\((.*?)\n\t\);",
        BRIDGE_SOURCE.read_text(encoding="utf-8"), re.S).group(1)
    php = re.findall(r"'([^']+)'", body)
    assert php == default["media"]["extensions"]


def test_media_map_db_mode_gates_with_the_callers_extension_family(bridge):
    """The read CARRIES the caller's family, and the gate widens to it.

    D1, through the real op: the enumeration files uploads media by
    ``settings.media.extensions`` and the shipped default cannot name a
    ``.psd``, so a profile the operator widened made this row invisible to
    the keep-gate — and a database-referenced file deletable.  Asking with
    the widened family keeps it; asking with nothing does not, and the
    answer says which family it measured with (``db_refs_gate``) so the
    client can refuse a keep-set that is not the measurement the run asked
    for.
    """
    default = bridge.call("media_map", {"mode": "db"}).json()
    assert default["db_refs_gate"] == 39
    assert "db_refs_gate_fallback" not in default
    assert "2023/01/design.psd" not in default["db_refs"]

    widened = bridge.call("media_map", {
        "mode": "db",
        "extensions": sorted(json.loads(
            (REPO / "wpt" / "data" / "profiles" / "default.json").read_text()
        )["media"]["extensions"] + ["psd"]),
    }).json()
    assert widened["ok"] is True
    assert "2023/01/design.psd" in widened["db_refs"]
    assert widened["db_refs_gate"] == 40
    assert "db_refs_gate_fallback" not in widened
    # the default's references all survive the widening
    assert set(default["db_refs"]) <= set(widened["db_refs"])


def test_media_map_db_mode_refuses_an_unusable_extension_family(bridge):
    """A refused family leaves the FLOOR in force, and says so.

    The mirrored default is a floor, never a ceiling: a request that is
    empty, mistyped, garbled, oversized or simply absent leaves the shipped
    family answering, so no hand-written request can narrow the gate below
    it (and turn the op into a delete-everything tool).  The refusal rides
    the answer so the client fails closed instead of trusting the set.
    """
    for extensions, label in (
        ([], "an empty list"),
        ("psd", "a bare string"),
        ([".psd"], "a dotted suffix"),
        (["psd", 7], "a non-string entry"),
        (["../etc/passwd"], "a path"),
        (["e%d" % i for i in range(513)], "past the structural bound"),
    ):
        data = bridge.call(
            "media_map", {"mode": "db", "extensions": extensions}).json()
        assert data["ok"] is True, label
        assert data.get("db_refs_gate_fallback") is True, label
        assert data["db_refs_gate"] == 39, label
        assert data["db_refs"], label

    # a family merely NARROWER than the default is not a refusal: the floor
    # widens it back, which can only protect more
    narrowed = bridge.call(
        "media_map", {"mode": "db", "extensions": ["jpg"]}).json()
    assert "db_refs_gate_fallback" not in narrowed
    assert narrowed["db_refs_gate"] == 39
    assert narrowed["db_refs"] == default_refs(bridge)


def default_refs(bridge):
    return bridge.call("media_map", {"mode": "db"}).json()["db_refs"]


def test_media_rewrite_structural_bounds_are_mirrored_in_the_client():
    # The client mirrors the bridge's three bounds so a caller can reason
    # about a batch and about the scan's own door, and this test is what
    # stops the two from drifting.  SCAN_CAP_MAX is the ceiling the op
    # clamps a `scan_cap` request to — and `Bridge.iter_rewrite_refs` is
    # what sends one, so the mirror is a bound a caller compares against,
    # not a comment.
    from wpt.wpbridge import client
    src = BRIDGE_SOURCE.read_text(encoding="utf-8")
    assert "define( 'WPT_MEDIA_REWRITE_SCAN_CAP', 100000 );" in src
    assert "define( 'WPT_MEDIA_REWRITE_SCAN_CAP_MAX', 1000000 );" in src
    assert "define( 'WPT_MEDIA_REWRITE_ROW_MAX', 5000 );" in src
    assert client.REWRITE_REF_SCAN_CAP == 100_000
    assert client.REWRITE_REF_SCAN_CAP_MAX == 1_000_000
    assert client.REWRITE_REF_ROW_MAX == 5_000
    # the door exists on both sides: a parameter the op honours, and a
    # method that can send it
    assert "array_key_exists( 'scan_cap', $params )" in src
    assert "scan_cap: int | None = None" in inspect.getsource(
        client.Bridge.iter_rewrite_refs)


# ---------------------------------------------------------------------------
# media_rewrite_refs (the webp-media reference rewrite)
# ---------------------------------------------------------------------------

#: The scan's exact row objects, in the order the op emits them (the
#: surfaces are resolved in table-name order, so the stream is
#: reproducible).  This is the op's wire contract: one object per row
#: that MAY hold a raster reference, `value` only on a rewritable
#: surface, `gated` only when the row carries one, and the terminal
#: completion object last.
SCAN_ROWS = [
    {
        "table": "wp_comments", "key": "comment_ID", "id": 5,
        "gated": ["look at wp-content/uploads/2023/11/alt.png",
                  "https://example.test/wp-content/uploads/2023/11/alt.png"],
    },
    {
        "table": "wp_options", "key": "option_id", "id": 4,
        "value": 'a:1:{s:16:"background_image";s:35:"/wp-content/uploads/2023/10/pic.jpg";}',
    },
    {
        "table": "wp_postmeta", "key": "meta_id", "id": 11,
        "value": 'a:2:{s:5:"sizes";a:1:{s:9:"thumbnail";a:1:{s:4:"file";s:23:"2023/10/pic-150x150.jpg";}}s:4:"note";s:38:"see wp-content/uploads/2023/10/pic.jpg";}',
    },
    {
        "table": "wp_postmeta", "key": "meta_id", "id": 12,
        "value": "https://example.test/wp-content/uploads/2023/10/pic.jpg",
    },
    {
        "table": "wp_posts", "key": "ID", "id": 7,
        "value": '<p><img src="https://example.test/wp-content/uploads/2023/10/pic.jpg" /></p>',
        "gated": ["cover: wp-content/uploads/2023/10/pic-300x233.jpg"],
    },
    {
        "table": "wp_termmeta", "key": "meta_id", "id": 6,
        "gated": ["wp-content/uploads/2024/04/term.jpg"],
    },
    {
        "table": "wp_usermeta", "key": "umeta_id", "id": 3,
        "gated": ["https://example.test/wp-content/uploads/2024/03/category.jpg"],
    },
]


def scan(bridge, params=None, deployed="bridge-test.php"):
    """One read-mode call, as the parsed NDJSON lines."""
    r = bridge.call("media_rewrite_refs", params or {"apply": False},
                    bridge=deployed)
    assert r.status_code == 200
    assert "x-ndjson" in r.headers["Content-Type"]
    return [json.loads(line) for line in r.text.splitlines() if line]


def test_media_rewrite_refs_scan_streams_one_object_per_reference_row(bridge):
    # THE MISSING OP: `wpt webp-media` calls this on every ftp-mode plan
    # and died with "unknown action" on EVERY site (it could not even
    # plan).  The read mode is the whole reference set the action needs:
    # the rewritable surfaces as `value`, the read-only ones as `gated`.
    lines = scan(bridge)
    assert lines[:-1] == SCAN_ROWS
    assert lines[-1] == {"ok": True, "rows": 7, "gated_cells": 5,
                         "truncated": False}


def test_media_rewrite_refs_clean_scan_body_is_exactly_the_ndjson_lines(bridge):
    # The clean answer, byte for byte: no extra key, no warning, no HTML.
    # Every hardening of the failure path (a clamped cap, an own error
    # line) must leave this answer untouched — a scan nobody asked to change
    # must not have changed.
    r = bridge.call("media_rewrite_refs", {"apply": False})
    assert r.status_code == 200
    assert r.headers["Content-Type"] == "application/x-ndjson"
    expected = [json.dumps(line, separators=(",", ":")) for line in SCAN_ROWS]
    expected.append(json.dumps(
        {"ok": True, "rows": 7, "gated_cells": 5, "truncated": False},
        separators=(",", ":")))
    assert r.text == "".join(line + "\n" for line in expected)


def test_media_rewrite_refs_scan_failure_after_rows_answers_with_its_own_error(bridge):
    # THE L4 ENVELOPE ON THE ONE OP THAT STREAMS.  Once rows are on the wire
    # the dispatcher can no longer send an envelope: header() is too late, and
    # with display_errors on PHP PRINTS "Warning: Cannot modify header
    # information - headers already sent in /var/www/…/bridge-abc.php" first.
    # That warning became the client's FIRST NDJSON line, so the client
    # reported "malformed NDJSON line: Warning: …" and the server's real
    # reason — and its absolute server path — were both lost.
    #
    # The op now answers its own failure as the terminal line. wp_postmeta
    # is the THIRD surface, so wp_comments and wp_options have already
    # streamed by the time its SELECT fails.
    (bridge.docroot / "wpt-stub-ref-scan-fails").write_text("wp_postmeta")
    r = bridge.call("media_rewrite_refs", {"apply": False})
    assert r.status_code == 200
    assert r.headers["Content-Type"] == "application/x-ndjson"
    lines = r.text.splitlines()
    # the rows that DID stream are still there, in order
    assert [json.loads(line) for line in lines[:2]] == SCAN_ROWS[:2]
    # the last line IS the diagnosis
    last = json.loads(lines[-1])
    assert last["ok"] is False
    assert last["error"] == "reference scan failed for wp_postmeta"
    assert last["type"] == "RuntimeException"
    assert isinstance(last["line"], int)
    # and NOTHING between them is a PHP notice: no warning, no HTML, and in
    # particular no line naming the docroot the bridge was deployed into.
    assert len(lines) == 3, lines
    for line in lines:
        assert "Warning" not in line and "<b>" not in line
        assert "docroot" not in line
        assert "header" not in line.lower()
    # the client's own contract then refuses: there is no completion marker.
    for line in lines:
        assert json.loads(line).get("ok") is not True


def test_media_rewrite_refs_own_failure_line_survives_a_hostile_message(bridge):
    # A DIAGNOSTIC MUST NOT BE ABLE TO TAKE DOWN THE DIAGNOSTIC.  The scan's
    # terminal failure line is written INSIDE the catch block, and a driver
    # error is the site's own bytes: a latin1 table or column name echoed
    # back in the message is not valid UTF-8, and the strict
    # JSON_THROW_ON_ERROR encoder THROWS on it — inside the catch, so the
    # line was never written, PHP fatalled on the operator's live site, and
    # the client was left with a stream that simply stopped (its own verdict:
    # "the reference scan ended without its completion marker") with the
    # real cause gone.  The same commit hardened the collided-key label and
    # wpt_bridge_send for exactly this; the failure line is the third
    # encoder on the same path and now uses the lenient one.
    (bridge.docroot / "wpt-stub-ref-scan-fails").write_text("wp_postmeta")
    (bridge.docroot / "wpt-stub-ref-scan-error").write_bytes(
        b"reference scan failed for wp_postmeta: \xff\xfe latin1 \x80 column\n"
        b"and a second line")
    r = bridge.call("media_rewrite_refs", {"apply": False})
    assert r.status_code == 200
    assert r.headers["Content-Type"] == "application/x-ndjson"
    lines = r.text.splitlines()
    # the rows that DID stream are still there, and the LAST line is a
    # well-formed envelope — the whole answer, on one line
    assert [json.loads(line) for line in lines[:2]] == SCAN_ROWS[:2]
    assert len(lines) == 3, lines
    last = json.loads(lines[-1])
    assert last["ok"] is False
    assert last["type"] == "RuntimeException"
    assert isinstance(last["line"], int) and last["line"] > 0
    # the message survives READABLY: the offending bytes are substituted,
    # not dropped and not fatal, and the rest of the sentence is intact
    assert last["error"].startswith("reference scan failed for wp_postmeta: ")
    assert "latin1" in last["error"] and "column" in last["error"]
    assert "�" in last["error"], last["error"]
    # a newline INSIDE the message cannot break the one line the answer
    # travels in: the encoder escapes it, which is why the stream above is
    # still exactly three lines
    assert "and a second line" in last["error"]
    assert lines[-1].count("\\n") == 1, lines[-1]
    # no PHP fatal, and nothing about the deployment leaks
    for line in lines:
        assert "Fatal error" not in line and "Uncaught" not in line
        assert "docroot" not in line and "Warning" not in line
    log = bridge.log_path.read_text(encoding="utf-8", errors="replace")
    assert "Fatal error" not in log, log[-2000:]
    assert "Uncaught" not in log, log[-2000:]
    # ... and the CLIENT's contract is unchanged: the real reason is what it
    # reports, not a truncated stream.
    with live_client(bridge) as client:
        with pytest.raises(BridgeError) as ei:
            list(client.iter_rewrite_refs())
    message = str(ei.value)
    assert "reference scan failed for wp_postmeta" in message, message
    assert "ended without its completion marker" not in message


def test_bridge_send_never_prints_a_header_warning_after_output(bridge):
    # The guard is in wpt_bridge_send itself, so it holds for any op that
    # emitted output before failing — not only the scan.  db_dump streams
    # too: its second table fails, the first is already on the wire, and
    # the answer must still be one JSON envelope with no PHP warning in
    # front of it.
    (bridge.docroot / "wpt-stub-dump-table-fails").write_text("wpt_flat")
    r = bridge.call("db_dump", {"tables": ["wpt_rows", "wpt_flat"]})
    assert r.status_code == 200
    assert "Warning" not in r.text
    assert "<b>" not in r.text
    assert "headers already sent" not in r.text
    lines = r.text.splitlines()
    assert json.loads(lines[0])["create"].startswith("CREATE TABLE `wpt_rows`")
    last = json.loads(lines[-1])
    assert last["ok"] is False
    assert last["type"] == "RuntimeException"


def test_media_rewrite_refs_never_resolves_a_same_suffix_look_alike(bridge):
    # A plugin's "wp_myoptions" ends with "options" exactly like the real
    # options table, and it is registered FIRST. The surface resolution
    # must take the table WORDPRESS resolves ($wpdb->options), never the
    # first suffix match: a rewrite aimed at the decoy would corrupt a
    # plugin's table, and a scan that read it would report references the
    # plan can never move.
    (bridge.docroot / "wpt-stub-decoy-options").write_text("")
    tables = [s for s in scan(bridge) if s.get("table")]
    assert {s["table"] for s in tables} == {
        "wp_posts", "wp_postmeta", "wp_options", "wp_comments",
        "wp_usermeta", "wp_termmeta"}
    assert not any("decoy" in (s.get("value") or "") for s in tables)
    # and the apply will not address it at all
    data = bridge.call("media_rewrite_refs", {"apply": True, "mapping": {
        "2023/10/decoy.jpg": "2023/10/decoy.webp"},
        "rows": [{"table": "wp_myoptions", "key": "option_id", "id": 99}]}).json()
    assert data["ok"] is False
    assert "table not rewritable" in data["error"]


def test_media_rewrite_refs_scan_is_read_only(bridge):
    # No LIMIT is not the point here (the scan is a caller-driven set);
    # the point is that NOTHING is written: the read mode is the only mode
    # the plan may ever run.
    before = len(bridge.calls())
    scan(bridge)
    for statement in bridge.calls()[before:]:
        assert statement.lstrip().upper().startswith("SELECT ")
    assert not any(c.startswith(("UPDATE", "INSERT", "DELETE"))
                   for c in bridge.calls()[before:]), "the read mode wrote"
    store = json.loads((bridge.docroot / "wpt-stub-ref-rows.json").read_text())
    posts = next(r for r in SCAN_ROWS if r["table"] == "wp_posts")
    assert store["wp_posts"]["7"]["post_content"] == posts["value"], \
        "the read mode changed a row"


def test_media_rewrite_refs_scan_reads_only_whitelisted_columns(bridge):
    # Every identifier the scan interpolates comes from information_schema
    # (wpt_table_columns): the table, the key column, the value column and
    # the gated columns, and nothing else.  No arbitrary SQL, no arbitrary
    # identifier.
    before = len(bridge.calls())
    scan(bridge)
    sql = bridge.calls()[before:]
    for statement in sql:
        if "information_schema" in statement:
            continue
        assert statement.startswith("SELECT `")
        # only columns the op's own surface spec names
        named = {"ID", "post_content", "post_excerpt", "meta_id", "meta_value",
                 "option_id", "option_value", "comment_ID", "comment_content",
                 "comment_author_url", "user_url", "umeta_id"}
        columns = [c.strip().strip("`") for c in
                   statement.split(" FROM ")[0][7:].split(",")]
        assert set(columns) <= named, columns
        assert "`wp_" in statement or "`wp_" in statement


def test_media_rewrite_refs_scan_gates_usermeta_instead_of_rewriting_it(bridge):
    # A usermeta row is a REFERENCE SURFACE nothing can rewrite, so it must
    # arrive as `gated` and never as a `value`: a `value` would put the row
    # in the rewrite set and the action would move a reference it cannot
    # actually update.  Same for comments and termmeta.
    rows = {f"{o['table']}[{o['id']}]": o for o in scan(bridge)[:-1]}
    for label in ("wp_usermeta[3]", "wp_comments[5]", "wp_termmeta[6]"):
        assert "value" not in rows[label], label
        assert rows[label]["gated"]
    # ... and the apply refuses to address one at all.
    data = bridge.call("media_rewrite_refs", {"apply": True, "mapping": {
        "2024/03/category.jpg": "2024/03/category.webp"},
        "rows": [{"table": "wp_usermeta", "key": "umeta_id", "id": 3}]}).json()
    assert data["ok"] is False
    assert "table not rewritable" in data["error"]


def test_media_rewrite_refs_truncated_scan_is_marked_not_answered(bridge):
    # A reference set that would exceed the structural cap is NOT
    # answered: the stream ends with the truncation marker instead of the
    # completion line, and the client's contract refuses it (a half-
    # measured set would plan conversions nobody can prove safe).  The
    # cap is lowered by deploying the same source with a smaller define —
    # the real value is pinned separately.
    src = BRIDGE_SOURCE.read_text(encoding="utf-8")
    assert "define( 'WPT_MEDIA_REWRITE_SCAN_CAP', 100000 );" in src
    low = (src.replace("__WPT_TOKEN__", TOKEN)
              .replace("__WPT_EXPIRES__", str(EXPIRY_FUTURE))
              .replace("define( 'WPT_MEDIA_REWRITE_SCAN_CAP', 100000 );",
                       "define( 'WPT_MEDIA_REWRITE_SCAN_CAP', 2 );"))
    (bridge.docroot / "bridge-cap.php").write_text(low, encoding="utf-8")
    lines = scan(bridge, {"apply": False}, deployed="bridge-cap.php")
    assert lines[-1] == {"truncated": True}
    assert len(lines) == 3          # two rows, then the marker
    assert not any("ok" in line for line in lines), "a truncated scan must not claim completion"


def test_media_rewrite_refs_scan_cap_moves_the_truncation_point(bridge):
    # THE OPERATOR DOOR.  The cap used to be a define() in the deployed
    # PHP, so a site with more than 100k image-bearing rows had exactly one
    # way past it: edit the file on the server.  The read mode now takes
    # `scan_cap`, and it is the SAME truncation the define expresses — a
    # set that would exceed it is refused the same way, never answered.
    assert "define( 'WPT_MEDIA_REWRITE_SCAN_CAP_MAX', 1000000 );" in \
        BRIDGE_SOURCE.read_text(encoding="utf-8")
    lines = scan(bridge, {"apply": False, "scan_cap": 2})
    assert lines[-1] == {"truncated": True}
    assert len(lines) == 3
    # ... and a cap that fits answers the whole scan, with no trace of the
    # request on the completion line.
    lines = scan(bridge, {"apply": False, "scan_cap": 500})
    assert lines[-1] == {"ok": True, "rows": 7, "gated_cells": 5,
                         "truncated": False}
    assert "scan_cap_clamped" not in lines[-1]


def test_media_rewrite_refs_scan_cap_above_the_ceiling_is_clamped_and_says_so(bridge):
    # The op never honours more than the ceiling, whatever the request says,
    # and it says ONCE — on the completion line, the one line the client
    # already reads as "the scan finished".  Silently accepting a request
    # it did not honour is how an operator ends up believing a site was
    # fully measured when it was not.
    for asked in (1_000_001, 10_000_000):
        lines = scan(bridge, {"apply": False, "scan_cap": asked})
        assert lines[-1] == {"ok": True, "rows": 7, "gated_cells": 5,
                             "truncated": False, "scan_cap_clamped": 1_000_000}
        # once per answer, and never on a row line
        assert sum("scan_cap_clamped" in line for line in lines) == 1
    # exactly at the ceiling is NOT a clamp: it is honoured as asked.
    lines = scan(bridge, {"apply": False, "scan_cap": 1_000_000})
    assert "scan_cap_clamped" not in lines[-1]
    # ... and a clamped scan is still a refusal at the cap, never a clean
    # answer: lowering the ceiling too proves the truncation is unchanged.
    src = BRIDGE_SOURCE.read_text(encoding="utf-8")
    low = (src.replace("__WPT_TOKEN__", TOKEN)
              .replace("__WPT_EXPIRES__", str(EXPIRY_FUTURE))
              .replace("define( 'WPT_MEDIA_REWRITE_SCAN_CAP_MAX', 1000000 );",
                       "define( 'WPT_MEDIA_REWRITE_SCAN_CAP_MAX', 3 );"))
    (bridge.docroot / "bridge-max.php").write_text(low, encoding="utf-8")
    lines = scan(bridge, {"apply": False, "scan_cap": 1_000_000},
                 deployed="bridge-max.php")
    assert lines[-1] == {"truncated": True}
    assert len(lines) == 4          # three rows, then the marker
    assert not any("ok" in line for line in lines)


@pytest.mark.parametrize("cap", [0, -1, "100", 1.5, True, [], {"n": 1}])
def test_media_rewrite_refs_scan_cap_must_be_a_positive_integer(bridge, cap):
    # A malformed cap is a REFUSAL, not a default: an operator who asked to
    # measure N rows must never be answered as though they had asked for
    # something else, and the scan writes nothing either way.
    r = bridge.call("media_rewrite_refs", {"apply": False, "scan_cap": cap})
    assert r.status_code == 200
    # the refusal is the ordinary JSON envelope, NOT a stream: a request
    # that never began scanning never became one.
    assert r.headers["Content-Type"] == "application/json"
    lines = r.text.splitlines()
    assert len(lines) == 1, lines
    answer = json.loads(lines[0])
    assert answer["ok"] is False
    assert "invalid scan_cap" in answer["error"]
    assert answer["type"] == "InvalidArgumentException"
    assert not any(c.startswith(("UPDATE", "INSERT", "DELETE"))
                   for c in bridge.calls())


def test_media_rewrite_refs_scan_cap_is_a_read_mode_parameter(bridge):
    # The apply never scans, so a cap there is inert — and the strict
    # `apply` gate still decides which mode runs, so sending both cannot
    # turn a write into a read or the reverse.
    data = bridge.call("media_rewrite_refs", {"apply": True, "scan_cap": 2,
        "mapping": {"2023/10/pic.jpg": "2023/10/pic.webp"},
        "rows": [{"table": "wp_posts", "key": "ID", "id": 7}]}).json()
    assert data["ok"] is True
    assert data["rows"][0]["value"].endswith('pic.webp" /></p>')
    assert any(c.startswith("UPDATE `wp_posts`") for c in bridge.calls())


def test_media_rewrite_refs_apply_rewrites_a_posts_row_and_re_reads_it(bridge):
    # A plain post body: the op splices the extension in place (the
    # directory part keeps its original spelling) and answers with the
    # value it READ BACK, which is the proof the caller's verification
    # consumes.
    data = bridge.call("media_rewrite_refs", {"apply": True, "mapping": {
        "2023/10/pic.jpg": "2023/10/pic.webp"},
        "rows": [{"table": "wp_posts", "key": "ID", "id": 7}]}).json()
    assert data["ok"] is True
    assert data["failed"] == []
    assert data["rows"] == [{
        "table": "wp_posts", "id": 7,
        "value": '<p><img src="https://example.test/wp-content/uploads/2023/10/pic.webp" /></p>',
    }]
    # the write really landed in the table (the re-read is not an echo)
    store = json.loads((bridge.docroot / "wpt-stub-ref-rows.json").read_text())
    assert store["wp_posts"]["7"]["post_content"] == data["rows"][0]["value"]
    # ... and the object cache was invalidated: a page rendered after the
    # purge must not be served the pre-rewrite reference from a cache.
    calls = bridge.calls()
    assert "clean_post_cache:7" in calls
    assert any(c.startswith("UPDATE `wp_posts` SET `post_content`") for c in calls)
    # exactly one write, and the re-read follows it
    assert len([c for c in calls if c.startswith("UPDATE ")]) == 1


def test_media_rewrite_refs_apply_rewrites_a_SERIALIZED_value_in_php(bridge):
    # The one rewrite only the server can do.  A serialized value carries
    # byte-length prefixes ("s:38:"); moving .jpg -> .webp makes the
    # string one byte longer, and a client that spliced the text without
    # re-serializing would leave a value WordPress cannot unserialize.
    # The answer's re-read value is the pin.
    data = bridge.call("media_rewrite_refs", {"apply": True, "mapping": {
        "2023/10/pic.jpg": "2023/10/pic.webp"},
        "rows": [{"table": "wp_postmeta", "key": "meta_id", "id": 11}]}).json()
    assert data["ok"] is True and data["failed"] == []
    value = data["rows"][0]["value"]
    assert value == (
        'a:2:{s:5:"sizes";a:1:{s:9:"thumbnail";a:1:{s:4:"file";'
        's:23:"2023/10/pic-150x150.jpg";}}s:4:"note";'
        's:39:"see wp-content/uploads/2023/10/pic.webp";}'
    )
    assert "s:39:" in value, "the s: length prefix was not recomputed"
    assert "pic.jpg" not in value.split('"note"')[1]
    # the whole structure comes back from PHP's own serialize(), so every
    # length in it is one core itself computed — the untouched size-map
    # entry proves the rewrite was a re-serialization, not a text splice
    assert 's:23:"2023/10/pic-150x150.jpg"' in value
    assert value.startswith("a:2:{") and value.endswith("}")
    store = json.loads((bridge.docroot / "wpt-stub-ref-rows.json").read_text())
    assert store["wp_postmeta"]["11"]["meta_value"] == value
    # postmeta owns no cache group of its own: the owning post's meta cache
    # and the post cache are what core would have dropped.
    assert "wp_cache_delete:post_meta:7" in bridge.calls()


def test_media_rewrite_refs_apply_writes_a_client_supplied_value_verbatim(bridge):
    # A row that carries a `value` is written verbatim: the client
    # computed that rewrite, and the op's job is to store it and prove it
    # read back.
    # The mapping deliberately does NOT mention the row's old reference:
    # a client-supplied value wins, the server never re-derives it.
    data = bridge.call("media_rewrite_refs", {"apply": True, "mapping": {
        "2023/10/unrelated.jpg": "2023/10/unrelated.webp"},
        "rows": [{"table": "wp_postmeta", "key": "meta_id", "id": 12,
                  "value": "https://example.test/wp-content/uploads/2023/10/pic.webp"}]}).json()
    assert data["ok"] is True and data["failed"] == []
    assert data["rows"] == [{
        "table": "wp_postmeta", "id": 12,
        "value": "https://example.test/wp-content/uploads/2023/10/pic.webp",
    }]
    store = json.loads((bridge.docroot / "wpt-stub-ref-rows.json").read_text())
    assert store["wp_postmeta"]["12"]["meta_value"].endswith("pic.webp")


def test_media_rewrite_refs_apply_rewrites_a_SERIALIZED_autoloaded_option(bridge):
    # A theme option is a SERIALIZED autoloaded row: the "s:35:" length has
    # to be recomputed by PHP, and the option lives in the `alloptions`
    # cache — a raw SQL write that skips both drops keeps serving the
    # pre-rewrite value to every page render.
    data = bridge.call("media_rewrite_refs", {"apply": True, "mapping": {
        "2023/10/pic.jpg": "2023/10/pic.webp"},
        "rows": [{"table": "wp_options", "key": "option_id", "id": 4}]}).json()
    assert data["ok"] is True and data["failed"] == []
    assert data["rows"][0]["value"] == \
        'a:1:{s:16:"background_image";s:36:"/wp-content/uploads/2023/10/pic.webp";}'
    calls = bridge.calls()
    assert "wp_cache_delete:options:theme_mods_avada" in calls
    assert "wp_cache_delete:options:alloptions" in calls


def test_media_rewrite_refs_apply_refuses_a_write_the_server_rejected(bridge):
    # A refused statement (a lock wait, a dead connection) must be named,
    # never reported as a rewritten row.
    (bridge.docroot / "wpt-stub-rewrite-write-fails").write_text("")
    data = bridge.call("media_rewrite_refs", {"apply": True, "mapping": {
        "2023/10/pic.jpg": "2023/10/pic.webp"},
        "rows": [{"table": "wp_posts", "key": "ID", "id": 7}]}).json()
    assert data["ok"] is True
    assert data["rows"] == []
    assert data["failed"] == ["wp_posts[7] (write failed)"]


def test_media_rewrite_refs_apply_catches_a_write_that_did_not_land(bridge):
    # The silent no-op UPDATE — a stale replica, a swallowed error, a
    # rolled-back transaction — reports success and leaves the row alone.
    # The RE-READ is the only thing that catches it, and the row is named
    # as unverified instead of as rewritten (the caller's own verification
    # then fails the run; the pre-action snapshot is the rollback).
    (bridge.docroot / "wpt-stub-rewrite-write-lies").write_text("")
    data = bridge.call("media_rewrite_refs", {"apply": True, "mapping": {
        "2023/10/pic.jpg": "2023/10/pic.webp"},
        "rows": [{"table": "wp_posts", "key": "ID", "id": 7}]}).json()
    assert data["ok"] is True
    assert data["rows"] == []
    assert data["failed"] == ["wp_posts[7] (did not verify)"]
    store = json.loads((bridge.docroot / "wpt-stub-ref-rows.json").read_text())
    assert "pic.jpg" in store["wp_posts"]["7"]["post_content"]


def test_media_rewrite_refs_apply_reports_a_row_it_cannot_write(bridge):
    # A row that is not there is named, never silently skipped: the caller
    # fails the run on a partial write.
    data = bridge.call("media_rewrite_refs", {"apply": True, "mapping": {
        "2023/10/pic.jpg": "2023/10/pic.webp"},
        "rows": [{"table": "wp_posts", "key": "ID", "id": 4242}]}).json()
    assert data["ok"] is True
    assert data["rows"] == []
    assert data["failed"] == ["wp_posts[4242] (row not found)"]


def test_media_rewrite_refs_php_rewrite_matches_the_python_rule(bridge):
    """The server-side rewrite is a MIRROR of wpt/actions/images_webp.py's
    rewrite_text, and a divergence is a wrong write: the client computes
    plain-row rewrites in Python and serialized-row rewrites in PHP, and
    both must move exactly the same references.

    The value is built HERE (a hand-assembled PHP serialization, so the
    test states the input bytes) and planted in the store, and the
    expected answer is computed with the ACTION'S OWN Python rule.
    """
    from wpt.actions.images_webp import rewrite_text

    mapping = {"2023/10/pic.jpg": "2023/10/pic.webp",
               "2023/11/alt.png": "2023/11/alt.webp"}
    leaf = (
        "url https://example.test/wp-content/uploads/2023/10/pic.jpg?ver=3, "
        'json "2023/11/alt.png", '
        "upper 2023/10/PIC.JPG, "
        "encoded 2023/10/pic%2Ejpg, "
        "unmapped 2023/10/other.png"
    )
    # A hand-assembled PHP serialization (the exact bytes, so the test
    # states its input): a two-element map whose KEY is itself a reference.
    value = 'a:2:{s:3:"key";s:%d:"%s";s:15:"2023/10/pic.jpg";s:1:"x";}' % (
        len(leaf), leaf)
    scan(bridge)   # seeds the stub's table store
    rows_file = bridge.docroot / "wpt-stub-ref-rows.json"
    store = json.loads(rows_file.read_text())
    store["wp_postmeta"]["13"] = {"meta_id": "13", "post_id": "7",
                                  "meta_value": value}
    rows_file.write_text(json.dumps(store))

    data = bridge.call("media_rewrite_refs", {"apply": True, "mapping": mapping,
        "rows": [{"table": "wp_postmeta", "key": "meta_id", "id": 13}]}).json()
    assert data["ok"] is True and data["failed"] == []

    new_leaf, changed = rewrite_text(leaf, mapping)
    assert changed == {"2023/10/pic.jpg", "2023/11/alt.png"}
    # the query string survives the rewrite, the uppercase and the
    # percent-encoded reference are LEFT ALONE (a mangled path is a 404)
    assert "pic.jpg?ver=3, " not in new_leaf
    assert "pic.webp?ver=3" in new_leaf
    assert "pic.webp" in new_leaf
    assert "PIC.JPG" in new_leaf and "pic%2Ejpg" in new_leaf
    assert "other.png" in new_leaf
    # a reference used as an ARRAY KEY is rewritten too (the Python rule
    # reads keys as leaves too), with the s: length re-computed
    assert rewrite_text("2023/10/pic.jpg", mapping)[0] == "2023/10/pic.webp"
    expected = 'a:2:{s:3:"key";s:%d:"%s";s:16:"2023/10/pic.webp";s:1:"x";}' % (
        len(new_leaf), new_leaf)
    assert data["rows"][0]["value"] == expected
    # ... and it is what the table now holds
    assert json.loads(rows_file.read_text())["wp_postmeta"]["13"]["meta_value"] \
        == expected


#: A serialized MAP whose two keys are the two halves of ONE conversion
#: pair: the .jpg key rewrites onto the .webp key that is already there.
#: A PHP array is a map, so a rewrite that stores it keeps ONE member and
#: the other is gone — with the answer claiming success, because the
#: re-read compares against what was just written and so "proves" the loss.
#: Both orders are exercised because a collapse is rewrite-order dependent:
#: the SECOND key is the one that would overwrite the first.
COLLIDING_VALUE = (
    'a:2:{s:15:"2023/10/pic.jpg";a:1:{s:4:"file";s:15:"2023/10/pic.jpg";}'
    's:16:"2023/10/pic.webp";a:1:{s:4:"file";s:16:"2023/10/pic.webp";}}'
)
COLLIDING_VALUE_REVERSED = (
    'a:2:{s:16:"2023/10/pic.webp";a:1:{s:4:"file";s:16:"2023/10/pic.webp";}'
    's:15:"2023/10/pic.jpg";a:1:{s:4:"file";s:15:"2023/10/pic.jpg";}}'
)


@pytest.mark.parametrize("value", [COLLIDING_VALUE, COLLIDING_VALUE_REVERSED],
                         ids=["jpg-first", "webp-first"])
def test_media_rewrite_refs_refuses_a_value_whose_keys_would_collapse(bridge, value):
    # THE SILENT DATA LOSS: a PHP array is a MAP, so two keys that rewrite
    # onto the same value collapse into one and a member is dropped. The
    # pre-fix answer was {"ok":true,"rows":[{… "a:1:" …}],"failed":[]} — the
    # re-read compares against what was just written, so it "proves" the
    # loss, and the caller's verify only looks for SURVIVING stale
    # references, so the lost sibling passed. The whole value is refused
    # instead, nothing is written, and the label names the collided key so
    # the operator can act on it.
    scan(bridge)   # seeds the stub's table store
    rows_file = bridge.docroot / "wpt-stub-ref-rows.json"
    store = json.loads(rows_file.read_text())
    store["wp_options"]["7"] = {"option_id": "7", "option_name": "gallery_map",
                                "autoload": "no", "option_value": value}
    rows_file.write_text(json.dumps(store))
    data = bridge.call("media_rewrite_refs", {"apply": True, "mapping": {
        "2023/10/pic.jpg": "2023/10/pic.webp"},
        "rows": [{"table": "wp_options", "key": "option_id", "id": 7}]}).json()
    assert data["ok"] is True
    assert data["rows"] == []
    assert len(data["failed"]) == 1
    label = data["failed"][0]
    assert label.startswith("wp_options[7] ("), label
    # the collided key is NAMED, so the label is actionable
    assert "2023/10/pic.webp" in label, label
    # ... and no rewrite was attempted at all
    assert not any(c.startswith("UPDATE ") for c in bridge.calls())
    stored = json.loads(rows_file.read_text())["wp_options"]["7"]["option_value"]
    assert stored == value
    assert stored.startswith("a:2:{"), "a member was dropped from the map"
    assert stored.count("a:1:{") == 2, "a member was dropped from the map"


#: A stored value PHP ALREADY reads back smaller than its bytes say.  The
#: duplicate string key is the plainest: ``a:2:`` declares TWO members, the
#: second is written under the first, and the array PHP builds holds one.
#: The three numeric pairs are the SAME collapse through PHP's key cast —
#: ``s:1:"1"`` is not a string key next to ``i:1;``, it IS the key 1 — and
#: ``-1`` proves the rule covers negative integers too, while the
#: "canonical integer" forms that PHP keeps distinct are in the
#: ``KEY_SHAPE_*`` pins below.
STORED_COLLAPSE = [
    ("duplicate string key", 'a:2:{s:3:"foo";s:1:"a";s:3:"foo";s:1:"b";}', 1, "s:foo"),
    ('"1" and 1', 'a:2:{s:1:"1";s:1:"a";i:1;s:1:"b";}', 1, "i:1"),
    ('"0" and 0', 'a:2:{s:1:"0";s:1:"a";i:0;s:1:"b";}', 1, "i:0"),
    ('"-1" and -1', 'a:2:{s:2:"-1";s:1:"a";i:-1;s:1:"b";}', 1, "i:-1"),
    # the same loss one level down: the top level agrees, so a proof that
    # only counted the value's own members would pass it
    ("nested",
     'a:1:{s:1:"k";a:2:{s:3:"foo";s:1:"a";s:3:"foo";s:1:"b";}}', 2, "s:foo"),
]


@pytest.mark.parametrize("name,value,level,key", STORED_COLLAPSE,
                         ids=[case[0] for case in STORED_COLLAPSE])
def test_media_rewrite_refs_refuses_a_value_whose_STORED_form_already_lost_a_member(
        bridge, name, value, level, key):
    # THE SILENT DATA LOSS THE KEY-COLLISION RULE CANNOT SEE.  That rule
    # watches the REWRITE: two keys it maps onto one.  This collapse happens
    # before it — while PHP unserializes the row — so by the time the op
    # looks, the value it holds is already smaller than the bytes on disk,
    # and re-serializing PERSISTS the loss.  The pre-fix answer was
    # {"ok":true,"rows":[{"value":"a:1:{…"}],"failed":[]} with the write
    # DONE: the re-read compares against what was just written, so it
    # "proves" the loss, and the caller's verification only looks for
    # SURVIVING stale references, so the lost sibling passed.  Proven on
    # the real bridge with a mapping that converts NOTHING (see the
    # nothing-to-convert case below).
    scan(bridge)   # seeds the stub's table store
    rows_file = bridge.docroot / "wpt-stub-ref-rows.json"
    store = json.loads(rows_file.read_text())
    store["wp_options"]["21"] = {"option_id": "21", "option_name": "stored_loss",
                                 "autoload": "no", "option_value": value}
    rows_file.write_text(json.dumps(store))
    data = bridge.call("media_rewrite_refs", {"apply": True, "mapping": {
        "2023/10/pic.jpg": "2023/10/pic.webp"},
        "rows": [{"table": "wp_options", "key": "option_id", "id": 21}]}).json()
    assert data["ok"] is True
    assert data["rows"] == []
    assert len(data["failed"]) == 1
    label = data["failed"][0]
    assert label.startswith("wp_options[21] ("), label
    # the LEVEL and the KEY are named, so the operator can go and look at
    # the nesting the value actually has
    assert f"at level {level} " in label, label
    assert f'"{key}"' in label, label
    # ... and nothing was written: the bytes that still describe the lost
    # member are the only copy of it there is
    assert not any(c.startswith("UPDATE ") for c in bridge.calls())
    assert json.loads(rows_file.read_text())["wp_options"]["21"]["option_value"] \
        == value


def test_media_rewrite_refs_refuses_a_stored_loss_the_mapping_never_touches(bridge):
    # The same value, a mapping that converts NOTHING (no reference of this
    # value is in it), and the same refusal.  A lossy round trip is a
    # defect in the VALUE, not in the rewrite: gating the proof on "did the
    # mapping match something" is exactly the bug, because the row that gets
    # re-serialized — and the row that loses a member — is the same either
    # way.  (The op itself refuses an empty MAPPING outright; a mapping that
    # is simply not about this row is the case that reached the rewrite.)
    value = 'a:2:{s:3:"foo";s:1:"a";s:3:"foo";s:1:"b";}'
    scan(bridge)
    rows_file = bridge.docroot / "wpt-stub-ref-rows.json"
    store = json.loads(rows_file.read_text())
    store["wp_options"]["22"] = {"option_id": "22", "option_name": "untouched",
                                 "autoload": "no", "option_value": value}
    rows_file.write_text(json.dumps(store))
    data = bridge.call("media_rewrite_refs", {"apply": True, "mapping": {
        "2023/10/somewhere-else.jpg": "2023/10/somewhere-else.webp"},
        "rows": [{"table": "wp_options", "key": "option_id", "id": 22}]}).json()
    assert data["rows"] == []
    assert len(data["failed"]) == 1
    assert "at level 1 " in data["failed"][0], data["failed"][0]
    assert not any(c.startswith("UPDATE ") for c in bridge.calls())
    assert json.loads(rows_file.read_text())["wp_options"]["22"]["option_value"] \
        == value


def test_media_rewrite_refs_accepts_a_lossless_round_trip_that_only_re_encodes(bridge):
    # STRUCTURE, NOT BYTES.  A stored value is not required to be byte-stable
    # under PHP's own serialize(): the string key "0" comes back as the
    # integer key 0 ("i:0;"), so the rewritten value differs from the stored
    # one byte for byte while holding exactly the same members.  A proof
    # that compared the two strings would refuse this — and refuse EVERY
    # healthy rewrite on a real site, which is the over-correction this
    # test exists to prevent.  This row is written.
    value = 'a:2:{s:1:"0";s:15:"2023/10/pic.jpg";s:3:"one";i:7;}'
    scan(bridge)
    rows_file = bridge.docroot / "wpt-stub-ref-rows.json"
    store = json.loads(rows_file.read_text())
    store["wp_options"]["23"] = {"option_id": "23", "option_name": "reencoded",
                                 "autoload": "no", "option_value": value}
    rows_file.write_text(json.dumps(store))
    data = bridge.call("media_rewrite_refs", {"apply": True, "mapping": {
        "2023/10/pic.jpg": "2023/10/pic.webp"},
        "rows": [{"table": "wp_options", "key": "option_id", "id": 23}]}).json()
    assert data["ok"] is True
    assert data["failed"] == []
    assert data["rows"] == [{
        "table": "wp_options", "id": 23,
        # the reference moved AND the key was re-encoded: i:0; where the
        # stored form said s:1:"0"; — same members, different bytes
        "value": 'a:2:{i:0;s:16:"2023/10/pic.webp";s:3:"one";i:7;}',
    }]
    assert json.loads(rows_file.read_text())["wp_options"]["23"]["option_value"] \
        == data["rows"][0]["value"]


def test_media_rewrite_refs_still_rewrites_a_value_it_cannot_describe(bridge):
    # An OBJECT payload gets no proof — its properties are not array levels
    # and are not string leaves this rule rewrites, so no key comparison
    # there could be honest (SPEC R28) — and the op must then behave exactly
    # as it always did for such a value (rewrite what it can, leave the rest)
    # instead of refusing the row on a shape it could not read.  The rewrite
    # returns an object untouched by contract, and the re-encoded object is
    # what comes back.
    value = ('a:2:{s:3:"map";a:1:{s:15:"2023/10/pic.jpg";s:1:"x";}'
             's:3:"obj";O:8:"stdClass":1:{s:4:"path";'
             's:15:"2023/10/pic.jpg";}}')
    scan(bridge)
    rows_file = bridge.docroot / "wpt-stub-ref-rows.json"
    store = json.loads(rows_file.read_text())
    store["wp_options"]["24"] = {"option_id": "24", "option_name": "with_object",
                                 "autoload": "no", "option_value": value}
    rows_file.write_text(json.dumps(store))
    data = bridge.call("media_rewrite_refs", {"apply": True, "mapping": {
        "2023/10/pic.jpg": "2023/10/pic.webp"},
        "rows": [{"table": "wp_options", "key": "option_id", "id": 24}]}).json()
    assert data["ok"] is True
    assert data["failed"] == []
    written = data["rows"][0]["value"]
    # the array member was rewritten...
    assert 's:16:"2023/10/pic.webp";s:1:"x";' in written
    # ... and the object came back re-encoded, as it always did
    assert written.startswith("a:2:{") and "stdClass" in written


#: PHP's own array-key cast, pinned level by level: which declared keys are
#: the SAME key of the map (and so collapse) and which stay distinct.  The
#: proof above refuses on a collapse, so a wrong answer here is a wrong
#: refusal (or a missed loss) on real data.
KEY_SHAPE_PAIRS = [
    ("1", 1, True),        # a numeric string IS an integer key
    ("0", 0, True),
    ("-1", -1, True),
    ("01", "01", False),   # leading zero: not canonical, stays a string
    ("-0", "-0", False),   # so does a negative zero
    ("+1", "+1", False),
    (" 1", " 1", False),
    ("1.0", "1.0", False),
    ("9223372036854775808", "9223372036854775808", False),   # past PHP_INT_MAX
]


def test_media_rewrite_refs_key_shape_is_php_own_array_key_cast(tmp_path):
    """DIFFERENTIAL: the round-trip proof's key form against PHP itself.

    The proof refuses a value when two declared keys reduce to one, so the
    rule it reduces them by IS the collapse it exists to catch.  Asked of
    real PHP rather than asserted in Python: a table of what "looks
    numeric" means would be an approximation of the very rule that has to
    be exact, and the four forms PHP keeps distinct ("01", "-0", "+1",
    "1.0") are exactly where an approximation refuses a healthy value.
    """
    src = BRIDGE_SOURCE.read_text(encoding="utf-8")
    body = re.search(
        r"function wpt_media_rewrite_key_shape\( \$key \) \{.*?\n\}", src, re.S)
    assert body, "wpt_media_rewrite_key_shape is gone"
    script = tmp_path / "key_shape.php"
    script.write_text(
        "<?php\n" + body.group(0) + "\n"
        + "$in = json_decode( file_get_contents( $argv[1] ), true );\n"
        + "$out = array();\n"
        + "foreach ( $in as $text ) {\n"
        + "\t$map = array( $text => 1 );\n"
        + "\t$out[] = array( wpt_media_rewrite_key_shape( $text ), key( $map ) );\n"
        + "}\n"
        + "echo json_encode( $out ), \"\\n\";\n",
        encoding="utf-8")
    texts = [case[0] for case in KEY_SHAPE_PAIRS]
    cases = tmp_path / "keys.json"
    cases.write_text(json.dumps(texts), encoding="utf-8")
    proc = subprocess.run(["php", str(script), str(cases)],
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    got = json.loads(proc.stdout)
    assert len(got) == len(KEY_SHAPE_PAIRS)
    for (text, php_key, _collapses), answer in zip(KEY_SHAPE_PAIRS, got):
        # The proof's own form says "this is an integer key" for exactly the
        # strings PHP casts to one, and holds the SAME value.
        assert answer[1] == php_key, (text, answer)
        assert answer[0] == ("i:%d" % php_key if isinstance(php_key, int)
                             else "s:%s" % php_key), (text, answer)


def test_media_rewrite_refs_reads_every_level_to_its_end(bridge):
    # The collapse is at the END of a wide level, so a proof that read only
    # the first members of it would pass.  Wide on purpose (1500 members is
    # already a value no stock wp_options row holds): the reader is O(n) per
    # level and iterative, so size costs time and not correctness — and a
    # quadratic one would have shown up here as a slow test, not as a wrong
    # answer, which is why the count is stated rather than timed.
    pairs = [f's:{len(f"k{i}")}:"k{i}";s:1:"v";' for i in range(1500)]
    value = 'a:1502:{' + "".join(pairs) + 's:3:"end";s:1:"x";s:3:"end";s:1:"y";}'
    scan(bridge)
    rows_file = bridge.docroot / "wpt-stub-ref-rows.json"
    store = json.loads(rows_file.read_text())
    store["wp_options"]["25"] = {"option_id": "25", "option_name": "wide",
                                 "autoload": "no", "option_value": value}
    rows_file.write_text(json.dumps(store))
    data = bridge.call("media_rewrite_refs", {"apply": True, "mapping": {
        "2023/10/pic.jpg": "2023/10/pic.webp"},
        "rows": [{"table": "wp_options", "key": "option_id", "id": 25}]}).json()
    assert data["rows"] == []
    assert len(data["failed"]) == 1
    assert 'at level 1 ' in data["failed"][0] and '"s:end"' in data["failed"][0]
    assert not any(c.startswith("UPDATE ") for c in bridge.calls())
    # the same wide value WITHOUT the duplicate is rewritten, so the refusal
    # above is the collapse and not the size
    value = 'a:1500:{' + "".join(pairs) + '}'
    store = json.loads(rows_file.read_text())
    store["wp_options"]["25"]["option_value"] = value
    rows_file.write_text(json.dumps(store))
    data = bridge.call("media_rewrite_refs", {"apply": True, "mapping": {
        "2023/10/pic.jpg": "2023/10/pic.webp"},
        "rows": [{"table": "wp_options", "key": "option_id", "id": 25}]}).json()
    assert data["failed"] == []
    assert data["rows"][0]["value"].startswith("a:1500:{")


# ---------------------------------------------------------------------------
# The shape proof's WALK: bounded, and cycle-safe (the uncatchable fatal)
# ---------------------------------------------------------------------------

#: The functions the shape proof is made of, in dependency order.  The
#: proof is measured by CALLING the deployed code, never by reading it: the
#: defect this covers is not a wrong answer but a process that never answers
#: (the walk) or one that quietly declines to look (the byte reader), and
#: only a run proves either.
SHAPE_FUNCTIONS = (
    "wpt_media_rewrite_has_reference",
    "wpt_media_rewrite_key_shape",
    "wpt_media_rewrite_declared_length",
    "wpt_media_rewrite_declared_token",
    "wpt_media_rewrite_declared_shape",
    "wpt_media_rewrite_array_shape",
    "wpt_media_rewrite_shape_gap",
    "wpt_media_rewrite_shape_loss",
    "wpt_media_rewrite_label_key",
    "wpt_media_rewrite_round_trip",
    "wpt_media_rewrite_shape_proof",
    "wpt_media_rewrite_shape_refusal",
)


def php_str(text: str) -> str:
    """One PHP-serialized string, with the byte length PHP writes."""
    return 's:%d:"%s";' % (len(text.encode("utf-8")), text)


def php_function(source: str, name: str) -> str:
    """One function out of bridge.php, braces matched STRING-AWARE.

    A plain brace counter is not enough for this file: the declared-token
    reader compares against the literal characters ``'{'`` and ``'}'``,
    which are braces to a counter and are not to PHP.  String literals and
    the three comment forms are skipped, or the extraction runs past the
    function it was asked for.
    """
    start = source.index("\nfunction %s(" % name) + 1
    at = source.index("{", start)
    depth = 0
    pos = at
    while pos < len(source):
        char = source[pos]
        if char in "'\"":
            quote = char
            pos += 1
            while pos < len(source) and source[pos] != quote:
                pos += 2 if source[pos] == "\\" else 1
        elif source.startswith("//", pos) or char == "#":
            stop = source.find("\n", pos)
            pos = len(source) if stop < 0 else stop
        elif source.startswith("/*", pos):
            stop = source.find("*/", pos)
            pos = len(source) if stop < 0 else stop + 2
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start:pos + 1]
        pos += 1
    raise AssertionError("unbalanced braces in " + name)


#: How the harness asks the deployed code for a verdict.  The DEPLOYED entry
#: point is one function (wpt_media_rewrite_shape_proof), so the harness calls
#: it — and falls back to composing the two proofs by hand ONLY so that a
#: bridge that does not have it yet still gets MEASURED rather than reported
#: as "the function is gone".  That fallback is what makes the liveness tests
#: below fail with a verdict ("no proof" instead of "agrees") instead of a
#: ValueError: a proof that is not exercised is a proof that is not live, and
#: a test that can only say "the symbol is missing" does not pin that.
SHAPE_PROOF_DISPATCH = r"""
    if ( ! is_array( $value ) ) {
        $proof = array( 'verdict' => 'no proof', 'proof' => '',
            'level' => null, 'key' => null );
    } elseif ( function_exists( 'wpt_media_rewrite_shape_proof' ) ) {
        $proof = wpt_media_rewrite_shape_proof( $raw, $value );
    } else {
        $declared = wpt_media_rewrite_declared_shape( $raw );
        if ( null === $declared ) {
            $proof = array( 'verdict' => 'no proof', 'proof' => '',
                'level' => null, 'key' => null );
        } else {
            $loss = wpt_media_rewrite_shape_loss( $declared, $actual );
            $proof = array(
                'verdict' => ( null === $loss ) ? 'agrees' : 'refused',
                'proof'   => 'stored form',
                'level'   => ( null === $loss ) ? null : $loss[0],
                'key'     => ( null === $loss ) ? null : $loss[1],
            );
        }
    }
    $label = ( function_exists( 'wpt_media_rewrite_shape_refusal' ) )
        ? wpt_media_rewrite_shape_refusal( $proof ) : null;
"""


def shape_functions_in(source: str) -> list:
    """The shape-proof family this bridge actually defines, in order.

    A function of the family that is GONE is not an error here: the harness
    measures what the bridge does, and a bridge without the entry point falls
    back to composing the two proofs itself (see SHAPE_PROOF_DISPATCH).
    """
    return [name for name in SHAPE_FUNCTIONS
            if "\nfunction %s(" % name in source]


def shape_proof(tmp_path: Path, payloads: dict) -> dict:
    """The deployed proof over ``payloads`` -> what it did with each.

    Per payload: the ``verdict`` the caller acts on (``"agrees"``,
    ``"no proof"`` — there is nothing to compare, so the caller performs none
    — or ``"refused at level N on key K"``), WHICH proof spoke, the
    operator's ``label``, and the paths the actual-value walk RECORDED, so a
    test can assert what it read and not only what it concluded.  Run under a
    LOW memory limit: the previous version of the walk exhausted it, and a
    test that cannot fail on a runaway is not a test.

    The decoding is done here with PHP's own ``@unserialize`` — the very
    call ``maybe_unserialize()`` makes in the op — so the harness exercises
    the deployed proof and not a re-implementation of it.
    """
    source = BRIDGE_SOURCE.read_text(encoding="utf-8")
    bounds = re.findall(r"^define\( 'WPT_MEDIA_SHAPE_\w+', \d+ \);$",
                        source, re.M)
    assert len(bounds) == 2, "the shape walk no longer declares its bounds"
    script = tmp_path / "shape-proof.php"
    script.write_text(
        "<?php\nerror_reporting(E_ALL);\n"
        + "\n".join(bounds) + "\n"
        + "\n\n".join(php_function(source, name)
                      for name in shape_functions_in(source)) + "\n"
        + "$in = json_decode(file_get_contents($argv[1]), true);\n"
        + "$out = array();\n"
        + "foreach ($in as $name => $raw) {\n"
        + "    $value = @unserialize($raw);\n"
        + "    $actual = array();\n"
        + "    $complete = true;\n"
        # A value the walk cannot read within its WORK BUDGET is REFUSED by
        # a throw, and the harness reports that refusal as the verdict the
        # op would answer with — the same channel, so a payload that spends
        # the budget is MEASURED here (its memory and its time are read out
        # with the verdict) instead of being tolerated.
        + "    $spent = null;\n"
        + "    $label = null;\n"
        + "    try {\n"
        + "    if (is_array($value)) {\n"
        + "        $actual = wpt_media_rewrite_array_shape($value, $complete);\n"
        + "    }\n"
        + SHAPE_PROOF_DISPATCH
        + "    } catch (Throwable $e) {\n"
        + "        $spent = $e->getMessage();\n"
        + "        $proof = array('verdict' => 'refused', 'proof' => 'work budget',\n"
        + "            'level' => null, 'key' => null);\n"
        + "    }\n"
        + "    $verdict = $proof['verdict'];\n"
        + "    if ('refused' === $verdict && null !== $proof['level']) {\n"
        + "        $verdict .= ' at level ' . $proof['level'] . ' on key '\n"
        + "            . wpt_media_rewrite_label_key($proof['key']);\n"
        + "    }\n"
        + "    $out[$name] = array(\n"
        + "        'verdict' => $verdict,\n"
        + "        'proof'   => $proof['proof'],\n"
        + "        'label'   => ('refused' === $proof['verdict'])\n"
        + "            ? $label : null,\n"
        + "        'complete' => $complete,\n"
        + "        'levels'  => count($actual),\n"
        + "        'paths'   => array_keys($actual),\n"
        + "        'spent'   => $spent,\n"
        + "        'memory'  => memory_get_peak_usage(true),\n"
        + "    );\n"
        + "}\n"
        + "echo json_encode($out), \"\\n\";\n",
        encoding="utf-8")
    payload_file = tmp_path / "shape-payloads.json"
    payload_file.write_text(json.dumps(payloads), encoding="utf-8")
    proc = subprocess.run(
        ["php", "-d", "memory_limit=32M", str(script), str(payload_file)],
        capture_output=True, text=True, timeout=180)
    assert proc.returncode == 0, (
        "the deployed shape proof did not answer: " + proc.stderr[-2000:])
    return json.loads(proc.stdout)


def nested_arrays(levels: int, leaf: str = "N;") -> str:
    """``levels`` nested one-member arrays around ``leaf``."""
    inner = leaf
    for _ in range(levels):
        inner = "a:1:{i:0;%s}" % inner
    return inner


def cyclic_chain(levels: int) -> str:
    """``levels`` nested arrays whose innermost member is the ROOT.

    Every level holds a back-reference to the array being decoded, so this
    is one cycle ``levels`` long — a cycle the walk must descend ``levels``
    levels before it can recognize, and so the case a short re-entry window
    would let through to the depth cap.
    """
    inner = "R:1;"
    for _ in range(levels):
        inner = "a:1:{s:1:\"k\";%s}" % inner
    return inner


#: ``a:2:{s:1:"k";R:1;s:5:"sizes";i:9;}`` decoded by PHP is an array whose
#: member "k" IS the array itself ($d['k'] === $d).  A walk that follows
#: member positions re-enters it at "0.", "0.0.", "0.0.0." ... and, being
#: iterative and unbounded, never stopped: PHP ran out of memory, which is
#: a FATAL no catch (Throwable) can see — so the op had already written the
#: rows before this one and the client read a truncated stream, no answer.
SELF_REFERENCE = 'a:2:{s:1:"k";R:1;s:5:"sizes";i:9;}'
#: The same defect one level down: a member that points at an ANCESTOR that
#: is not its parent, so the walk has to compare a member with the whole
#: chain above it, not only with its parent.
TWO_CYCLE = 'a:1:{s:1:"a";a:1:{s:1:"b";R:1;}}'
#: A cycle LENGTH: 200 nested arrays, innermost member the root.
LONG_CYCLE = cyclic_chain(200)


def test_media_rewrite_shape_walk_terminates_on_a_cyclic_array(tmp_path):
    """A back-reference to an enclosing array must not end the host.

    The defect is a hang, not a wrong answer, so the assertions are about
    what the deployed code DOES: it answers.  Every payload here is
    answered under a 32 MB memory limit — the limit the previous version
    exhausted (measured: "PHP Fatal error: Allowed memory size of 32MB
    exhausted" inside wpt_media_rewrite_array_shape, uncatchable, so the
    op's own catch (Throwable) never ran).

    And what it answers is a REFUSAL, which is the fail-closed direction:
    the array PHP reads back holds a level at the member the stored bytes
    wrote as a single back-reference, and a re-store would replace that one
    member with a whole subtree — a structural change the proof exists to
    catch, reported with the level and the key to go and look at.
    """
    wide = "a:6:{%s}" % "".join(
        php_str("k%d" % i) + "R:1;" for i in range(6))
    proof = shape_proof(tmp_path, {
        "self-reference": SELF_REFERENCE,
        "two-cycle": TWO_CYCLE,
        "long-cycle": LONG_CYCLE,
        # a WIDE cycle, which a depth cap alone does not stop: every level
        # re-expands the whole level, so it is the NODE count that runs away
        "wide-cycle": wide,
    })
    # the verdict, pinned: the level the disagreement is at, and the key an
    # operator would go and look at
    assert proof["self-reference"]["verdict"] == "refused at level 2 on key s:k"
    # PHP cannot serialize a recursive pair a second time on every build;
    # when the round trip itself refuses, the verdict carries no level/key.
    # The safety answer is still a refusal, and the row is left untouched.
    assert proof["two-cycle"]["verdict"].startswith("refused")
    assert proof["long-cycle"]["verdict"] == "refused at level 3 on key s:k"
    assert proof["wide-cycle"]["verdict"].startswith("refused at level 2 ")
    # and the walk STOPPED at the cycle: two levels (the value and the
    # member it loops to), not the 4096 the depth cap would have allowed
    assert proof["self-reference"]["paths"] == ["0.", ""]
    assert proof["long-cycle"]["paths"] == ["0.", ""]
    assert proof["wide-cycle"]["levels"] == 7


def test_media_rewrite_shape_walk_still_reads_a_healthy_value(tmp_path):
    """The bounds cost a healthy value nothing.

    A cap that also refused real values would be a different defect, so the
    shapes the walk is there to read are read: a 5000-member level, a value
    nested 200 deep, two SIBLING arrays that happen to be equal (the cycle
    guard compares a member with its ANCESTORS, never with a value that
    merely looks like one — two equal subtrees are two subtrees), and an
    ordinary size map.
    """
    pairs = "".join("i:%d;%s" % (i, php_str("v")) for i in range(5000))
    proof = shape_proof(tmp_path, {
        "5000 members": "a:5000:{%s}" % pairs,
        "200 deep": nested_arrays(200),
        "equal siblings": 'a:2:{i:0;a:1:{i:0;%s}i:1;a:1:{i:0;%s}}'
                          % (php_str("x"), php_str("x")),
        "a size map": "a:2:{s:4:\"file\";%ss:5:\"sizes\";a:1:{s:9:\"thumbnail\";"
                      "a:1:{s:4:\"file\";%s}}}"
                      % (php_str("2023/10/pic.jpg"), php_str("pic-150x150.jpg")),
    })
    for name in ("5000 members", "200 deep", "a size map"):
        assert proof[name]["verdict"] == "agrees", (name, proof[name])
    # every level of each is read, none of them cut short — this is the
    # cycle guard's own contract, so it is asserted on the SHAPE and not on
    # the verdict, and "equal siblings" is the case that would break a guard
    # comparing a member with any value that merely looks like an ancestor
    assert proof["5000 members"]["levels"] == 1
    assert proof["200 deep"]["levels"] == 200
    assert proof["equal siblings"]["paths"] == ["", "1.", "0."]
    assert proof["a size map"]["paths"] == ["", "1.", "1.0."]


# ---------------------------------------------------------------------------
# [C] THE WALK IS BOUNDED BY WORK, not by depth — and the walk is O(1) per
# level
#
# The bound this replaces was a DEPTH CAP set at PHP's own nesting limit,
# which is not a bound: the walk's cost is quadratic in the depth, because
# every level's path is a string that grows with the depth and the answer
# is one entry per level.  Measured through the REAL op on one row value,
# pre-fix: 300 levels 0.05 s, 1 000 levels 0.71 s, 2 000 levels 2.88 s,
# 4 000 levels past the client\'s own 10 s timeout on a single row — a
# stored cell (a DB write, no privilege beyond that) hanging every run.
#
# The cyclic shape is NOT what spends it, and this suite says so by
# measuring it: PHP\'s own ``===`` raises "Nesting level too deep -
# recursive dependency?" on a recursive pair, which the walk catches, so a
# cycle of ANY length is refused at the first level.  The value that spent
# the host\'s memory was the DEEP one, where the cycle window has nothing to
# complain about.
# ---------------------------------------------------------------------------


def test_the_shape_walk_spends_bounded_work_on_every_cycle_length(tmp_path):
    """Periods 1..200 through the DEPLOYED function: a verdict, and a
    bounded cost, for every one of them.

    A single case would only prove that ONE length is handled; the class is
    "a length the window does not reach", so the sweep is the test.  Each
    payload is answered under the harness\'s 32 MB limit, and every answer
    is a REFUSAL (never a hang, never a partial shape handed back as a
    proof) with a peak and a duration that do not grow with the period.
    """
    periods = list(range(1, 201))
    proof = shape_proof(tmp_path, {
        "cycle%d" % n: cyclic_chain(n) for n in periods
    })
    assert len(proof) == len(periods)
    for n in periods:
        got = proof["cycle%d" % n]
        assert got["verdict"].startswith("refused"), (n, got)
        # the walk read the value and its first member, and no more: the
        # cycle is caught where it closes, not walked to
        assert got["levels"] == 2, (n, got)
        assert got["spent"] is None, (n, got)
        # ... and the MEMORY is flat in the period, under the harness limit
        # that a runaway PHP would exhaust.  (Memory, never the clock: a
        # wall-clock assertion is a flake generator, and the one this file
        # was built to be rid of — see the failure report on the harness's
        # own determinism.)
        assert got["memory"] < 32 * 1024 * 1024, (n, got)


def _shape_work_budget() -> int:
    """The deployed shape walk's work budget, read from bridge.php itself.

    ONE owner for the number (the PHP ``define``) and a single reader here,
    so a test can never plant a fixture sized against a stale copy of it.
    """
    source = BRIDGE_SOURCE.read_text(encoding="utf-8")
    return int(re.search(
        r"define\( \'WPT_MEDIA_SHAPE_WORK_BUDGET\', (\d+) \);", source
    ).group(1))


def test_a_value_deeper_than_the_work_budget_is_refused_with_the_budget(
        tmp_path):
    """The bound, and the two halves of it: within the budget a deep value
    is read IN FULL, past it the walk refuses and NAMES the number.

    Both directions are pinned, because a bound that only ever fires is a
    false-refusal machine and one that never fires is the defect.  The
    healthy end is the pinned 200-level fixture (below, five times over);
    the refusing end is a value the budget cannot read, and the message
    has to carry the number so an operator can see the bound is a bound and
    not a mysterious failure.
    """
    budget = _shape_work_budget()
    # both halves in ONE process: same fixtures, one PHP start
    proof = shape_proof(tmp_path, {
        "inside": nested_arrays(budget - 1),
        "outside": nested_arrays(budget + 1),
    })
    # just inside: read whole
    inside = proof["inside"]
    assert inside["verdict"] == "agrees"
    assert inside["levels"] == budget - 1
    assert inside["spent"] is None
    assert inside["memory"] < 32 * 1024 * 1024
    # just outside: refused, with the budget in the message
    got = proof["outside"]
    assert got["verdict"] == "refused"
    assert got["proof"] == "work budget"
    assert str(budget) in got["spent"]
    assert "work budget" in got["spent"]
    assert "left exactly as it is" in got["spent"]
    # the value is nowhere near PHP\'s own nesting limit, so the refusal
    # is this walk\'s bound and not PHP\'s
    assert budget + 1 < 4096


def test_a_value_at_php_s_own_nesting_limit_is_refused_not_spent(tmp_path):
    """THE MEASUREMENT THAT MATTERS: the deepest value PHP itself will hand
    this walk, under a 32 MB limit.

    4096 levels is ``unserialize()``\'s own limit ("Maximum depth of 4096
    exceeded" on the next one), so this is the largest shape the deployed
    code can ever be asked to read — the top of the input space, not a
    contrived one.  Pre-fix the depth cap sat at exactly that number, so the
    walk was bounded at a cost that is QUADRATIC in the depth: measured
    through the real op, one such row cost 4.6 s and 24 MB of transient
    strings per walk, the proof makes three walks per serialized row, and
    the process exhausted the limit — an uncatchable FATAL, so the op
    answered nothing, the client read a truncated stream, and the bridge it
    had deployed stayed on the site.

    So this extreme value is run here under a 32 MB limit and the answer
    must be: a REFUSAL that names the budget, bounded time, and bounded
    memory.  A memory fatal here is exactly the regression.  This test owns
    the 4096-level boundary; the just-over-budget end-to-end case is owned
    by test_end_to_end_a_value_the_proof_cannot_spend_answers_and_leaves_nothing,
    so the extreme cost is paid once.
    """
    # 4096 is the DEEPEST value this walk can ever be handed: PHP's own
    # unserialize() refuses the 4097th ("Maximum depth of 4096 exceeded"),
    # so nothing above it reaches the code at all (asserted below, which is
    # why the budget may sit below PHP's limit without hiding anything).
    # It is the only depth this test needs: the just-over-budget refusal is
    # owned by test_a_value_deeper_than_the_work_budget_is_refused_with_the_budget,
    # and 2048 in between adds no distinct invariant.
    proof = shape_proof(tmp_path, {
        "deep4096": nested_arrays(4096),
        # a healthy size map in the same batch, so the refusal cannot be
        # "everything in this run is refused" (built with php_str so its
        # s:NN: lengths are PHP\'s own)
        "a size map": 'a:2:{s:4:"file";%ss:5:"sizes";a:1:{s:9:"thumbnail";'
                      'a:1:{s:4:"file";%s}}}'
                      % (php_str("2023/10/pic.jpg"),
                         php_str("pic-150x150.jpg")),
    })
    got = proof["deep4096"]
    assert got["verdict"] == "refused", got
    assert got["proof"] == "work budget", got
    assert "work budget of" in got["spent"], got
    assert got["memory"] < 32 * 1024 * 1024, got
    # BOUNDED is the whole claim, and the memory ceiling is where it is
    # proven: pre-fix this payload exhausted the 32 MB limit (the walk
    # held one path string per level, growing with the depth, three walks
    # per row) and the harness died with an uncatchable FATAL.  The
    # remaining cost is the cycle guard\'s own ``===``, which PHP performs
    # recursively and therefore prices by the value\'s depth — bounded, in
    # proportion to PHP\'s own 4096, by the same ceiling.  Asserted as
    # MEMORY and as the verdict, never as a duration: a wall-clock bound in
    # a shared-CPU suite is a flake generator, and this file\'s whole
    # determinism finding is about exactly that.
    # the healthy value beside it is still read and agreed with
    assert proof["a size map"]["verdict"] == "agrees"
    assert proof["a size map"]["levels"] == 3
    # and PHP itself refuses the next one, so the walk is never handed a
    # value deeper than the one measured above
    assert shape_proof(tmp_path, {"over": nested_arrays(4097)})[
        "over"]["verdict"] == "no proof"


# ---------------------------------------------------------------------------
# The proof is LIVE: what it says about the values a real site actually holds
# ---------------------------------------------------------------------------


def php_pairs(*members) -> str:
    """``a:N:{…}`` from (key, value) byte-string pairs, counted by PHP's rule."""
    return "a:%d:{%s}" % (len(members), "".join(k + v for k, v in members))


THUMBNAIL = php_pairs(
    (php_str("file"), php_str("2023/10/pic-150x150.jpg")),
    (php_str("width"), "i:150;"),
    (php_str("height"), "i:150;"),
    (php_str("mime-type"), php_str("image/jpeg")),
)
POPULATED_SIZES = php_pairs((php_str("thumbnail"), THUMBNAIL))
#: What WordPress writes for an image it generated NO extra size for: the
#: sizes map exists and is EMPTY.  This is not a contrived payload — it is
#: the shape of every attachment row on a site whose thumbnail regeneration
#: failed or was never run, and it is the shape that made the proof inert.
EMPTY_SIZES = "a:0:{}"
IMAGE_META = php_pairs(
    (php_str("aperture"), "d:2.8;"),
    (php_str("credit"), php_str("x")),
    (php_str("created_int"), "i:1699999999;"),
    (php_str("orientation"), "i:1;"),
    (php_str("caption"), php_str("")),
)

#: An ordinary ``_wp_attachment_metadata`` value, in the two forms a real
#: site holds: with the size map WordPress generated, and with the EMPTY one
#: (EMPTY_SIZES).  The second is the one this whole section exists for.
ATTACHMENT_METADATA = {
    "sizes generated": php_pairs(
        (php_str("file"), php_str("2023/10/pic.jpg")),
        (php_str("sizes"), POPULATED_SIZES),
        (php_str("image_meta"), IMAGE_META)),
    "sizes empty": php_pairs(
        (php_str("file"), php_str("2023/10/pic.jpg")),
        (php_str("sizes"), EMPTY_SIZES),
        (php_str("image_meta"), IMAGE_META)),
}
#: The real-meta shape, ``sizes`` FOLLOWED BY ``image_meta`` — the two
#: members in the order WordPress writes them, which is also the order that
#: puts the empty ``a:0:{}`` in a NON-FINAL member position.
REAL_META = {
    "sizes empty": php_pairs(
        (php_str("sizes"), EMPTY_SIZES),
        (php_str("image_meta"), IMAGE_META)),
    "sizes generated": php_pairs(
        (php_str("sizes"), POPULATED_SIZES),
        (php_str("image_meta"), IMAGE_META)),
}
#: A plain size map: the level the rewrite touches most often.
SIZE_MAP = {
    "sizes generated": php_pairs(
        (php_str("file"), php_str("2023/10/pic.jpg")),
        (php_str("sizes"), POPULATED_SIZES)),
    "sizes empty": php_pairs(
        (php_str("file"), php_str("2023/10/pic.jpg")),
        (php_str("sizes"), EMPTY_SIZES)),
}

#: name -> (payload, the levels the walk must RECORD).  One table, so the
#: verdict test and the levels test cannot drift apart, and so a payload's
#: expected structure is stated next to the payload itself.  The paths are
#: member POSITIONS from the root, not keys: a collapse SHIFTS the keys that
#: survive it, and a path built from keys would move with them.
REAL_VALUE_SHAPES = {
    "metadata: sizes generated": (
        ATTACHMENT_METADATA["sizes generated"],
        ["", "2.", "1.", "1.0."]),
    "metadata: sizes empty": (
        ATTACHMENT_METADATA["sizes empty"],
        ["", "2.", "1."]),
    "real-meta: sizes generated": (
        REAL_META["sizes generated"],
        ["", "1.", "0.", "0.0."]),
    "real-meta: sizes empty": (
        REAL_META["sizes empty"],
        ["", "1.", "0."]),
    "size-map: sizes generated": (
        SIZE_MAP["sizes generated"],
        ["", "1.", "1.0."]),
    "size-map: sizes empty": (
        SIZE_MAP["sizes empty"],
        ["", "1."]),
}
#: The empty size map IS a level, and reading it is the defect: the pre-fix
#: reader pushed no frame for it, so its own "}" was read as a member key of
#: the level above and the whole value came back "no proof" — which is why
#: the "sizes empty" rows expect the sizes level and no level inside it.


@pytest.mark.parametrize("name", sorted(REAL_VALUE_SHAPES))
def test_media_rewrite_shape_proof_reads_a_real_value(tmp_path, name):
    """THE FEATURE IS LIVE.  Pin the verdict, not the absence of a crash.

    The pre-fix proof answered ``"no proof"`` for every value in this table
    whose size map is empty, and a caller that gets ``"no proof"`` proves
    NOTHING: the guarantee the module documents — a rewritten structure is
    never returned smaller than the one it came from — was never exercised
    on any real WordPress value, so the loss it exists to prevent was
    fail-OPEN.  A proof whose failure mode is "I did not look" is
    indistinguishable from a proof that has nothing to report, which is why
    the assertion here is the VERDICT, and never merely "it did not crash".
    """
    payload, _levels = REAL_VALUE_SHAPES[name]
    proof = shape_proof(tmp_path, {name: payload})[name]
    assert proof["verdict"] == "agrees", (name, proof)
    assert proof["proof"] == "stored form", (name, proof)


def test_media_rewrite_shape_proof_answers_every_level_of_a_real_value(tmp_path):
    """A verdict is not enough: assert the levels it READ.

    ``"agrees"`` on a value whose reader silently stopped at the first level
    would be a proof of nothing, so the paths the walk recorded are pinned
    against the structure of the value WordPress writes.
    """
    proof = shape_proof(tmp_path, {name: payload
                                   for name, (payload, _l) in REAL_VALUE_SHAPES.items()})
    for name, (_payload, levels) in REAL_VALUE_SHAPES.items():
        assert proof[name]["paths"] == levels, (name, proof[name])


#: A collapse PHP made while READING the row: the same key DECLARED twice,
#: and the three numeric pairs that are ONE key through PHP's own key cast.
#: The expected verdict is IN the table rather than derived from the name, so
#: a change to either side of the expectation is visible in the diff.
COLLAPSED_LEVEL = {
    "duplicate string key": ('a:2:{s:3:"foo";s:1:"a";s:3:"foo";s:1:"b";}', "s:foo"),
    '"1" beside 1': ('a:2:{s:1:"1";s:1:"a";i:1;s:1:"b";}', "i:1"),
    '"0" beside 0': ('a:2:{s:1:"0";s:1:"a";i:0;s:1:"b";}', "i:0"),
    '"-1" beside -1': ('a:2:{s:2:"-1";s:1:"a";i:-1;s:1:"b";}', "i:-1"),
}


def collapse_in_metadata(collapsed: str) -> str:
    """A real attachment metadata value whose image_meta level COLLAPSED."""
    return php_pairs(
        (php_str("file"), php_str("2023/10/pic.jpg")),
        (php_str("sizes"), EMPTY_SIZES),
        (php_str("image_meta"),
         php_pairs((php_str("aperture"), "d:2.8;"), (php_str("credit"), collapsed))))


@pytest.mark.parametrize("name", sorted(COLLAPSED_LEVEL))
def test_media_rewrite_shape_proof_refuses_a_pre_existing_collapse(tmp_path, name):
    """The collapse PHP made before wpt was offered the value.

    Not the one the rewrite makes — wpt_media_rewrite_leaves owns that — but
    the one made while the row was READ: the bytes declare a member the
    array PHP builds cannot hold, so it is already gone by the time anything
    downstream of ``unserialize()`` exists.  Re-storing the value is what
    makes it permanent, and PHP's own round trip CANNOT see this: both of
    its sides are already post-``unserialize()``, so they agree perfectly on
    a value that has quietly lost a member.  Only a reader of the bytes can.

    These four shapes are a REGRESSION pin rather than a pre-fix failure: a
    flat value was already refused, because the pre-fix reader only gave up
    on a value holding a nested array that is followed by a sibling.  The
    same loss ONE LEVEL DOWN, inside a real attachment metadata value, is the
    case that was written with the member gone — see
    test_media_rewrite_refs_refuses_a_collapse_inside_a_real_size_map, which
    also pins that nothing is written.
    """
    payload, key = COLLAPSED_LEVEL[name]
    proof = shape_proof(tmp_path, {name: payload})[name]
    assert proof["verdict"] == "refused at level 1 on key " + key, (name, proof)
    # and it is the BYTE side that found it, which the operator is told: a
    # loss already in the row is not something this run can recover
    assert proof["proof"] == "stored form", (name, proof)


def test_media_rewrite_refusal_says_which_proof_failed(bridge):
    """The wording an operator acts on, for both refusals the op can issue.

    "A member would be lost" is not actionable on its own: a loss already IN
    THE ROW cannot be recovered by anything this run holds (restore it from a
    snapshot), while one the WRITE would introduce means the proof is telling
    us about the value's own encoding.  Both refusals say which, and the
    second one — a value PHP cannot encode twice at all — has no level and no
    key, because there is no disagreement to point at.
    """
    value = collapse_in_metadata(COLLAPSED_LEVEL["duplicate string key"][0])
    scan(bridge)   # seeds the stub's table store
    rows_file = bridge.docroot / "wpt-stub-ref-rows.json"
    store = json.loads(rows_file.read_text())
    store["wp_options"]["41"] = {"option_id": "41", "option_name": "collapsed",
                                 "autoload": "no", "option_value": value}
    rows_file.write_text(json.dumps(store))
    label = bridge.call("media_rewrite_refs", {
        "apply": True, "mapping": {"2023/10/pic.jpg": "2023/10/pic.webp"},
        "rows": [{"table": "wp_options", "key": "option_id", "id": 41}]}
    ).json()["failed"][0]
    assert ("its stored form and the array PHP reads back disagree on the key"
            in label), label
    assert "(a PHP array holds each key once)" in label, label

    # a healthy value is proved by the byte side, and the round trip is run
    # on it as well: neither of them refuses a value PHP itself re-encodes
    # faithfully, which is what makes the pair safe to run on every row
    proof = shape_proof(bridge.docroot, {
        "healthy": REAL_VALUE_SHAPES["metadata: sizes generated"][0]})["healthy"]
    assert proof["verdict"] == "agrees", proof



@pytest.mark.parametrize("name", sorted(COLLAPSED_LEVEL))
def test_media_rewrite_refs_refuses_a_collapse_inside_a_real_size_map(bridge, name):
    """THE OP, on the value a real site holds.  Nothing is written.

    The same collapse one level down inside a real ``_wp_attachment_metadata``
    whose size map is EMPTY — so the top level agrees, a proof that only
    counted the value's own members would pass it, and the pre-fix reader
    gave up on the whole value rather than read the level where the loss is.
    The pre-fix answer was ``{"ok":true,"rows":[{… "a:1:" …}],"failed":[]}``
    with the write DONE: the re-read compares against what was just written,
    so it "proves" the loss, and the caller's verification only looks for
    SURVIVING stale references, so the lost sibling passed.
    """
    value = collapse_in_metadata(COLLAPSED_LEVEL[name][0])
    scan(bridge)   # seeds the stub's table store
    rows_file = bridge.docroot / "wpt-stub-ref-rows.json"
    store = json.loads(rows_file.read_text())
    store["wp_options"]["40"] = {"option_id": "40", "option_name": "collapsed",
                                 "autoload": "no", "option_value": value}
    rows_file.write_text(json.dumps(store))
    data = bridge.call("media_rewrite_refs", {"apply": True, "mapping": {
        "2023/10/pic.jpg": "2023/10/pic.webp"},
        "rows": [{"table": "wp_options", "key": "option_id", "id": 40}]}).json()
    assert data["ok"] is True
    assert data["rows"] == [], data
    assert len(data["failed"]) == 1, data
    label = data["failed"][0]
    assert label.startswith("wp_options[40] ("), label
    # the LEVEL and the KEY are named, so the operator goes and looks at the
    # nesting the value actually has: the collapsed level is image_meta's
    # "credit" member, which is the value's THIRD level
    assert "at level 3 " in label, label
    assert "its stored form and the array PHP reads back disagree" in label, label
    # ... and nothing was written: those bytes are the only copy of the
    # member there is
    assert not any(c.startswith("UPDATE ") for c in bridge.calls())
    assert json.loads(rows_file.read_text())["wp_options"]["40"]["option_value"] \
        == value


def healthy_sweep(tmp_path: Path, count: int) -> dict:
    """``count`` randomized HEALTHY payloads -> the ones the proof refused.

    The values are built in PHP and encoded by ``serialize()`` itself, so
    every one of them is collapse-free BY CONSTRUCTION (a PHP array cannot
    hold a duplicate key) and a refusal is a false positive by definition.
    The generator is seeded, so a failure is reproducible, and it is
    deliberately full of the things a hand-written reader gets wrong: keys
    that LOOK numeric but are not canonical (``01``, ``-0``, ``+1``,
    ``" 1"``, ``1.0``, a value past ``PHP_INT_MAX``), a key ``""``, non-ASCII
    keys, NUL and high bytes in values, ``null``/bool/float leaves including
    ``INF``/``NAN``/``-0.0``, and EMPTY arrays — the level shape that made
    the previous reader give up.
    """
    source = BRIDGE_SOURCE.read_text(encoding="utf-8")
    bounds = re.findall(r"^define\( 'WPT_MEDIA_SHAPE_\w+', \d+ \);$",
                        source, re.M)
    assert len(bounds) == 2, "the shape walk no longer declares its bounds"
    script = tmp_path / "healthy-sweep.php"
    script.write_text(
        "<?php\nerror_reporting(E_ALL);\n"
        + "\n".join(bounds) + "\n"
        + "\n\n".join(php_function(source, name)
                      for name in shape_functions_in(source))
        + r"""
$KEYS = array(0, 1, -1, 7, '0', '1', '-1', '01', '-0', '+1', ' 1', '1.0',
              '9223372036854775808', 'file', 'sizes', 'image_meta', 'thumb',
              "cle", "k", '', 'a.b.jpg');
$LEAVES = array('N;', 'b:1;', 'b:0;', 'i:0;', 'i:-1;', 'i:9223372036854775807;',
                'd:0;', 'd:-0;', 'd:1.5;', 'd:1.0E+25;', 'd:INF;', 'd:-INF;',
                'd:NAN;', 's:0:"";', 's:4:"text";', 's:3:"2023/10/pic.jpg";');
function wpt_sweep_value( $depth ) {
    global $KEYS, $LEAVES;
    $out = array();
    $n   = mt_rand( 0, 5 );
    for ( $i = 0; $i < $n; $i++ ) {
        $k = $KEYS[ mt_rand( 0, count( $KEYS ) - 1 ) ];
        if ( 0 === mt_rand( 0, 3 ) ) {
            $out[ $k ] = ( $depth > 0 ) ? wpt_sweep_value( $depth - 1 ) : array();
        } else {
            $out[ $k ] = $LEAVES[ mt_rand( 0, count( $LEAVES ) - 1 ) ];
        }
    }
    return $out;
}
mt_srand( 20240917 );
$bad  = array();
$seen = 0;
$agreed = 0;
$n    = (int) $argv[1];
for ( $i = 0; $i < $n; $i++ ) {
    $raw   = serialize( wpt_sweep_value( mt_rand( 0, 4 ) ) );
    $value = @unserialize( $raw );
    if ( ! is_array( $value ) ) {
        $bad[] = $i . ': PHP cannot read back its own serialize() output';
        continue;
    }
    $seen++;
    $actual = wpt_media_rewrite_array_shape( $value );
""" + SHAPE_PROOF_DISPATCH + r"""
    if ( 'agrees' === $proof['verdict'] ) {
        $agreed++;
    } else {
        $bad[] = $i . ': ' . $proof['verdict'] . ' via ' . $proof['proof']
            . ' at level ' . var_export( $proof['level'], true )
            . ' on ' . var_export( $proof['key'], true ) . ' :: ' . $raw;
    }
}
echo json_encode( array( 'asked' => $n, 'decoded' => $seen, 'agreed' => $agreed,
    'refused' => $bad ) ), "\n";
""",
        encoding="utf-8")
    proc = subprocess.run(
        ["php", "-d", "memory_limit=256M", str(script), str(count)],
        capture_output=True, text=True, timeout=600)
    assert proc.returncode == 0, (
        "the deployed proof did not answer the sweep: " + proc.stderr[-2000:])
    return json.loads(proc.stdout)


def test_media_rewrite_shape_proof_refuses_nothing_it_should_not(tmp_path):
    """THE ANTI-FALSE-POSITIVE GATE: 4000 healthy values, zero refusals.

    A proof that is too eager is its own silent data loss — a real site
    cannot be rewritten because rows WordPress itself wrote were refused —
    and it is the failure a "refuse on doubt" implementation produces
    without anyone noticing, because the refusals look like defects in the
    site.  The gate is stated as a COUNT (4000 values, 0 refusals) rather
    than a sample, and every one of them is a value PHP built and PHP
    encoded, so a refusal is a false positive by construction: there is no
    collapse in any of them to find.

    ``"no proof"`` counts as a refusal here on purpose.  It is not a loss, so
    it cannot lose data — but it IS the pre-fix failure mode (the reader
    declining a value it should have read), and letting it pass unnoticed is
    how the previous version of this proof shipped inert.
    """
    report = healthy_sweep(tmp_path, 4000)
    assert report["decoded"] == 4000, report["decoded"]
    assert report["agreed"] == 4000, (report["agreed"], report["refused"][:5])
    assert report["refused"] == [], report["refused"][:5]



def test_media_rewrite_shape_proof_accepts_a_lossless_re_encoding(tmp_path):
    """A re-encoding is not a loss, and must not be mistaken for one.

    ``s:1:"0"`` is stored as a string key and comes back as the integer key
    0, so the round trip is not byte-stable on a perfectly healthy value —
    ``a:2:{s:1:"0";…}`` is written back as ``a:2:{i:0;…}``.  A proof
    comparing bytes would refuse this, and would refuse EVERY healthy
    rewrite on a real site, which is the over-correction this pins.
    """
    proof = shape_proof(tmp_path, {
        'a numeric string key': 'a:2:{s:1:"0";s:15:"2023/10/pic.jpg";s:3:"one";i:7;}',
        'a float that re-encodes': 'a:2:{s:3:"one";d:1.0E+25;s:3:"two";d:-0;}',
        'a bool and a null': 'a:3:{s:1:"a";b:0;s:1:"b";N;s:1:"c";i:0;}',
    })
    for name, case in proof.items():
        assert case["verdict"] == "agrees", (name, case)


def php_edge_values(tmp_path: Path) -> dict:
    """Values only PHP can BUILD -> what the round trip says about each.

    A serialized row cannot express a true PHP reference, so the shapes this
    builds are unreachable from the op — which is exactly why they belong
    here: the round trip is a function of VALUES, and the one behaviour of
    it nobody can reach through a stored row is the one worth pinning
    directly.  A real ``$a['self'] = &$a`` is the case PHP's ``serialize()``
    CAN write (as ``R:``), so it round-trips; an ``R:``-DECODED self-
    reference is a value that merely CONTAINS itself, and ``serialize()``
    either replaces that member with ``N;`` — a silent loss the round trip's
    own comparison catches — or, one level deeper, walks until the stack is
    exhausted and raises.  Both are refusals; neither may hang, and neither
    may take the op down.
    """
    source = BRIDGE_SOURCE.read_text(encoding="utf-8")
    bounds = re.findall(r"^define\( 'WPT_MEDIA_SHAPE_\w+', \d+ \);$",
                        source, re.M)
    assert len(bounds) == 2, "the shape walk no longer declares its bounds"
    script = tmp_path / "php-edge-values.php"
    script.write_text(
        "<?php\nerror_reporting(E_ALL);\n"
        + "\n".join(bounds) + "\n"
        + "\n\n".join(php_function(source, name) for name in SHAPE_FUNCTIONS)
        + r"""
$out = array();
// a REAL PHP self-reference: serialize() writes it as R:, so it round-trips
$a = array( 'file' => '2023/10/pic.jpg' );
$a['self'] = &$a;
$out['php self-reference'] = wpt_media_rewrite_round_trip( $a );
unset( $a['self'] );
// two members of the same root
$b = array( 'k' => 1 );
$b['x'] = &$b;
$b['y'] = &$b;
$out['two members to root'] = wpt_media_rewrite_round_trip( $b );
// a self-reference hidden inside an object: the object is not a level
$o       = new stdClass();
$o->me   = $o;
$out['object self-reference'] = wpt_media_rewrite_round_trip( array( 'obj' => $o ) );
// the two shapes an R: DECODED row produces, and one level deeper
foreach ( array(
    'R to parent'  => 'a:1:{s:3:"map";a:2:{s:15:"2023/10/pic.jpg";s:1:"x";s:1:"k";R:1;}}',
    'R to self'    => 'a:2:{s:1:"k";R:1;s:5:"sizes";i:9;}',
    'R two levels' => 'a:1:{s:1:"a";a:1:{s:1:"b";R:1;}}',
) as $name => $raw ) {
    $value = @unserialize( $raw );
    $proof = wpt_media_rewrite_round_trip( $value );
    $proof['label'] = wpt_media_rewrite_shape_refusal( $proof );
    $out[ $name ] = $proof;
}
$out['plain'] = wpt_media_rewrite_round_trip(
    array( 'a' => 1, 'b' => array( 'c' => null ) ) );
echo json_encode( $out ), "\n";
""",
        encoding="utf-8")
    proc = subprocess.run(
        ["php", "-d", "memory_limit=32M", str(script)],
        capture_output=True, text=True, timeout=180)
    assert proc.returncode == 0, (
        "the round trip did not answer: " + proc.stderr[-2000:])
    return json.loads(proc.stdout)


def test_media_rewrite_round_trip_is_defined_on_every_self_reference(tmp_path):
    """A cycle must produce a VERDICT — never a hang, never a fatal.

    The D2 bounds cover the walk; this covers the ENCODER, which is a
    different machine with a different failure: PHP's ``serialize()`` of a
    value that merely contains itself replaces that member with ``N;``
    (measured: ``a:2:{s:1:"k";R:1;s:5:"sizes";i:9;}`` re-encodes as
    ``a:2:{s:1:"k";N;s:5:"sizes";i:9;}``) or, one level deeper, raises
    ``Error: Maximum call stack size of 8339456 bytes … Infinite
    recursion?``.  That Error is a Throwable, so the round trip CATCHES it
    and refuses the value — and it must: ``maybe_serialize()`` would raise
    the very same Error at the write, taking the whole batch's answer with
    it.
    """
    got = php_edge_values(tmp_path)
    # a real PHP self-reference is encoded faithfully (R:) and survives: no
    # refusal, because there is nothing to refuse
    assert got["php self-reference"]["verdict"] == "agrees", got["php self-reference"]
    assert got["two members to root"]["verdict"] == "agrees", got["two members to root"]
    assert got["plain"]["verdict"] == "agrees", got["plain"]
    # an object member is not a level either, so there is nothing to compare
    assert got["object self-reference"]["verdict"] == "no proof", \
        got["object self-reference"]
    # the R:-decoded shapes are all REFUSED, and the two ways PHP fails are
    # both refusals: a silent N; is caught by the comparison (with the level
    # and key of the member that became null) and a stack overflow by the
    # catch (with no level, because there is no disagreement to point at)
    assert got["R to self"] == {"verdict": "refused", "proof": "round trip",
                               "level": 2, "key": "s:k",
                               "label": got["R to self"]["label"]}, got["R to self"]
    assert got["R to parent"] == {"verdict": "refused", "proof": "round trip",
                                  "level": None, "key": None,
                                  "label": got["R to parent"]["label"]}, \
        got["R to parent"]
    assert got["R two levels"] == {"verdict": "refused", "proof": "round trip",
                                   "level": None, "key": None,
                                   "label": got["R two levels"]["label"]}, \
        got["R two levels"]
    # the Wording, because the two refusals are not the same operator news:
    # one member became null (named, at a level), and one value cannot be
    # encoded a second time at all (no level, no key — there is no
    # disagreement to point at)
    assert 'at level 2 its own serialize()/unserialize() round trip loses the ' \
        'key "s:k"' in got["R to self"]["label"], got["R to self"]["label"]
    for name in ("R to parent", "R two levels"):
        assert got[name]["label"] == (
            "refused: this value cannot be re-stored at all — PHP cannot "
            "encode it for storage a second time (a self-reference its own "
            "unserialize() produced), and the row is left exactly as it is"
        ), (name, got[name]["label"])
    # a verdict with no level must not reach an operator as a broken label
    assert "at level " not in got["R to parent"]["label"], got["R to parent"]



def test_media_rewrite_refs_refuses_a_cyclic_row_the_round_trip_cannot_encode(bridge):
    """THE OP, on a row PHP cannot write twice — answered, not fatal.

    A batch of three rows where the second is a cycle one level deep, so the
    round trip is the proof that refuses it (the byte reader refuses the
    shallower form first, and this is the row that reaches the encoder).  The
    contract is the one the operator sees: a structured answer, the cyclic
    row named, the other two written, and no half-written stream.
    """
    healthy = SIZE_MAP["sizes generated"]
    cyclic = php_pairs((php_str("map"), php_pairs(
        (php_str("2023/10/pic.jpg"), php_str("x")),
        (php_str("k"), "R:1;"))))
    scan(bridge)   # seeds the stub's table store
    rows_file = bridge.docroot / "wpt-stub-ref-rows.json"
    store = json.loads(rows_file.read_text())
    for option_id in (50, 52):
        store["wp_options"][str(option_id)] = {
            "option_id": str(option_id), "option_name": "ok-%d" % option_id,
            "autoload": "no", "option_value": healthy,
        }
    store["wp_options"]["51"] = {"option_id": "51", "option_name": "cyclic",
                                 "autoload": "no", "option_value": cyclic}
    rows_file.write_text(json.dumps(store))
    data = bridge.call("media_rewrite_refs", {
        "apply": True, "mapping": {"2023/10/pic.jpg": "2023/10/pic.webp"},
        "rows": [{"table": "wp_options", "key": "option_id", "id": i}
                 for i in (50, 51, 52)]}).json()
    assert data["ok"] is True
    assert sorted(row["id"] for row in data["rows"]) == [50, 52], data
    assert len(data["failed"]) == 1, data
    assert "cannot be re-stored" in data["failed"][0]
    # ... and the cyclic row is left EXACTLY as it was
    assert json.loads(rows_file.read_text())["wp_options"]["51"]["option_value"] \
        == cyclic


#: An OBJECT inside an otherwise ordinary attachment metadata value, and the
#: same value with a collapse INSIDE the object's properties.  The second is
#: R28's accepted limit: the property names PHP materializes are not the ones
#: the bytes declare (a private property is stored mangled, with NUL bytes),
#: so no key comparison there could be honest, and the op must neither claim
#: a proof over it nor refuse the row.
OBJECT_IN_METADATA = php_pairs(
    (php_str("file"), php_str("2023/10/pic.jpg")),
    (php_str("sizes"), EMPTY_SIZES),
    (php_str("image_meta"), IMAGE_META),
    (php_str("obj"), 'O:8:"stdClass":2:{s:4:"path";' + php_str("2023/10/pic.jpg")
     + 's:3:"map";a:2:{s:3:"foo";s:1:"a";s:3:"foo";s:1:"b";}}'))
#: A row that IS an object, which is the shape that reaches no walk at all:
#: the op only proves an array, so this is unproven for a second and
#: independent reason (there is no array level to compare).
COLLAPSED_OBJECT = php_pairs(
    (php_str("obj"), 'O:8:"stdClass":1:{s:3:"map";a:2:{s:3:"foo";s:1:"a";'
     's:3:"foo";s:1:"b";}}'))


@pytest.mark.parametrize("name,payload,complete", [
    ("an object member", OBJECT_IN_METADATA, False),
    ("an object that already lost a member", COLLAPSED_OBJECT, False),
], ids=["object-member", "collapsed-object"])
def test_media_rewrite_shape_proof_never_claims_a_proof_over_an_object(
        tmp_path, name, payload, complete):
    """NO PROOF over an object, and no refusal either — stated and pinned.

    Which of the two is the honest verdict is a decision, so it is made
    explicitly and pinned here: ``"no proof"``.  The walk cannot read an
    object's properties, so ``"agrees"`` would be a proof of a question
    nobody asked; and refusing would be a FALSE refusal, because the rewrite
    leaves an object untouched by contract, so a site whose plugin serialized
    an object into an option row would become unrewritable over a loss that
    happened long before wpt read it.  A loss inside the object's properties
    is therefore neither proven nor caught (SPEC R28) — and the answer must
    not claim otherwise.
    """
    proof = shape_proof(tmp_path, {name: payload})[name]
    assert proof["verdict"] == "no proof", (name, proof)
    assert proof["proof"] == "", (name, proof)
    # the walk says WHY: it saw a member whose properties are not levels
    assert proof["complete"] is complete, (name, proof)


def test_media_rewrite_shape_proof_never_proves_a_value_that_is_not_an_array(
        tmp_path):
    """A row that IS an object is unproven, for the stated reason.

    The op proves an array and nothing else (a scalar payload is returned
    untouched before any proof is offered, and an object payload is rewritten
    by contract), so the honest answer for a top-level object is the same
    ``"no proof"`` — pinned so a future change that starts "proving" one
    cannot pass a verdict it never earned.
    """
    payload = 'O:8:"stdClass":1:{s:3:"map";a:1:{s:3:"foo";s:1:"a";}}'
    proof = shape_proof(tmp_path, {"object row": payload})["object row"]
    assert proof["verdict"] == "no proof", proof
    assert proof["paths"] == [], proof



def test_media_rewrite_refs_still_rewrites_a_value_it_cannot_prove(bridge):
    """"no proof" is not a refusal: the row is still rewritten.

    The op's contract for a value it cannot prove is unchanged from the day
    it shipped — rewrite what it can, leave the rest, and do not refuse a
    row over a shape it could not read — so an object-bearing row is still
    written.  What is NEW is that the proof no longer silently declines the
    real values (see the section above), so "cannot prove" now means what it
    says: an object, and only an object.
    """
    value = php_pairs(
        (php_str("file"), php_str("2023/10/pic.jpg")),
        (php_str("sizes"), EMPTY_SIZES),
        (php_str("image_meta"), IMAGE_META),
        (php_str("obj"), 'O:8:"stdClass":1:{s:4:"path";'
         + php_str("2023/10/pic.jpg") + '}'))
    scan(bridge)   # seeds the stub's table store
    rows_file = bridge.docroot / "wpt-stub-ref-rows.json"
    store = json.loads(rows_file.read_text())
    store["wp_options"]["53"] = {"option_id": "53", "option_name": "with_object",
                                 "autoload": "no", "option_value": value}
    rows_file.write_text(json.dumps(store))
    data = bridge.call("media_rewrite_refs", {"apply": True, "mapping": {
        "2023/10/pic.jpg": "2023/10/pic.webp"},
        "rows": [{"table": "wp_options", "key": "option_id", "id": 53}]}).json()
    assert data["ok"] is True
    assert data["failed"] == [], data
    written = data["rows"][0]["value"]
    # the ARRAY members were rewritten and proven, the object came back
    # re-encoded (which is what it has always done), and nothing was refused
    assert php_str("2023/10/pic.webp") in written
    assert "stdClass" in written
    # the empty sizes level survived the rewrite, which it could not have
    # done had the proof stopped reading at it
    assert "a:0:{}" in written, written



def test_media_rewrite_refs_answers_a_cyclic_row_it_cannot_store(bridge):
    """THE OP, over a real php -S, under a memory limit it cannot dodge.

    The walk above is measured in isolation; this is the failure the
    operator would see.  A batch of three rows where the SECOND is cyclic:
    the fatal is unrecoverable, so the contract is that the client gets an
    answer — the cyclic row refused, the other two written — and never a
    half-written stream.  The built-in server runs with memory_limit=-1, so
    without the lowered limit this test would take the machine down instead
    of failing.
    """
    value = ("a:2:{s:4:\"file\";%ss:5:\"sizes\";a:1:{s:9:\"thumbnail\";"
             "a:1:{s:4:\"file\";%s}}}"
             % (php_str("2023/10/pic.jpg"), php_str("pic-150x150.jpg")))
    # the reference the mapping moves, plus a member that points back at the
    # value itself: re-storing it would replace that one member with a whole
    # subtree, which is what the proof refuses
    cyclic = ("a:1:{s:3:\"map\";a:2:{%ss:1:\"x\";s:1:\"k\";R:1;}}"
              % php_str("2023/10/pic.jpg"))
    scan(bridge)   # seeds the stub's table store
    rows_file = bridge.docroot / "wpt-stub-ref-rows.json"
    store = json.loads(rows_file.read_text())
    for option_id in (30, 32):
        store["wp_options"][str(option_id)] = {
            "option_id": str(option_id), "option_name": "ok-%d" % option_id,
            "autoload": "no", "option_value": value,
        }
    store["wp_options"]["31"] = {
        "option_id": "31", "option_name": "cyclic", "autoload": "no",
        "option_value": cyclic,
    }
    rows_file.write_text(json.dumps(store))

    logs = bridge.docroot / "limited-logs"
    logs.mkdir(exist_ok=True)
    limited = _start_server(bridge.docroot, logs,
                            ini=["-d", "memory_limit=32M"])
    try:
        env = BridgeEnv(bridge.docroot, bridge.uploads, limited[1], limited[0],
                        limited[2], limited[3])
        response = env.call("media_rewrite_refs", {
            "apply": True,
            "mapping": {"2023/10/pic.jpg": "2023/10/pic.webp"},
            "rows": [{"table": "wp_options", "key": "option_id", "id": i}
                     for i in (30, 31, 32)]})
    finally:
        limited[0].terminate()
        limited[0].wait(timeout=5)
        limited[3].close()
    assert response.status_code == 200, response.text[:400]
    data = response.json()
    # a STRUCTURED answer, not a truncated stream: the two healthy rows are
    # written and the cyclic one is named
    assert data["ok"] is True
    assert sorted(row["id"] for row in data["rows"]) == [30, 32]
    assert len(data["failed"]) == 1
    label = data["failed"][0]
    assert "cannot be re-stored" in label
    if "losing a member" in label:
        assert 'at level 3 ' in label and 'key "s:map"' in label
    else:
        # PHP 8.3 cannot compare/serialize this recursive pair a second time;
        # the round-trip proof refuses before a level/key can be named, and
        # the row is still left untouched.
        assert "cannot encode it for storage a second time" in label
    store = json.loads(rows_file.read_text())
    assert php_str("2023/10/pic.webp") in store["wp_options"]["30"]["option_value"]
    # the cyclic row is left EXACTLY as it was
    assert store["wp_options"]["31"]["option_value"] == cyclic


def test_media_rewrite_refs_refusal_label_survives_a_hostile_key(bridge):
    # The refusal NAMES the collided key, so those bytes reach a `failed`
    # label — and the apply's answer is encoded with JSON_THROW_ON_ERROR,
    # so a byte that is not valid UTF-8 would make the whole answer FATAL,
    # and a control character would break the one line the label lives in.
    # A key long enough to smuggle a data dump into the label is bounded.
    # (A byte sequence that is not valid UTF-8 cannot travel through this
    # harness's JSON-backed table, so that half of the contract is pinned
    # directly on the PHP in the next test.)
    tail = "\x07" + "x" * 300
    key_b = "2023/10/pic.webp" + tail
    key_a = "2023/10/pic.jpg" + tail      # rewrites onto key_b
    value = ('a:2:{s:%d:"%s";s:1:"a";s:%d:"%s";s:1:"b";}'
             % (len(key_a), key_a, len(key_b), key_b))
    scan(bridge)   # seeds the stub's table store
    rows_file = bridge.docroot / "wpt-stub-ref-rows.json"
    store = json.loads(rows_file.read_text())
    store["wp_options"]["9"] = {"option_id": "9", "option_name": "hostile",
                                "autoload": "no", "option_value": value}
    rows_file.write_text(json.dumps(store))
    r = bridge.call("media_rewrite_refs", {"apply": True, "mapping": {
        "2023/10/pic.jpg": "2023/10/pic.webp"},
        "rows": [{"table": "wp_options", "key": "option_id", "id": 9}]})
    # the answer is JSON at all: a fatal would have replaced it
    assert r.headers["Content-Type"] == "application/json"
    data = r.json()
    assert data["ok"] is True
    assert data["rows"] == []
    assert len(data["failed"]) == 1
    label = data["failed"][0]
    assert label.startswith("wp_options[9] (refused: two keys"), label
    for control in "\n\r\x00\x07":
        assert control not in label, repr(label)
    # the collided key is still recognisable, and BOUNDED to 200 characters
    # (the surrounding prose is fixed), so a 300-byte key cannot smuggle a
    # data dump into the one line the operator reads
    quoted = label.split('"')[1]
    assert quoted.startswith("2023/10/pic.webp")
    assert len(quoted) == 200
    assert json.loads(rows_file.read_text())["wp_options"]["9"]["option_value"] \
        == value


def test_media_rewrite_refs_label_key_is_always_encodable(tmp_path):
    """``wpt_media_rewrite_label_key`` on the bytes a latin1 table really
    hands over.  Run directly, because the harness's JSON-backed table
    cannot carry a byte sequence that is not valid UTF-8 — and this is the
    input that would make the apply's JSON_THROW_ON_ERROR encode throw, i.e.
    turn a refusal into a fatal with no answer at all.
    """
    src = BRIDGE_SOURCE.read_text(encoding="utf-8")
    body = re.search(
        r"function wpt_media_rewrite_label_key\( \$key \) \{.*?\n\}", src, re.S)
    assert body, "wpt_media_rewrite_label_key is gone"
    # The cases travel BASE64-encoded: a JSON file cannot carry a byte
    # sequence that is not valid UTF-8, which is the very input under test.
    script = tmp_path / "label_key.php"
    script.write_text(
        "<?php\n" + body.group(0) + "\n"
        + "$in = json_decode(file_get_contents($argv[1]), true);\n"
        + "$out = array();\n"
        + "foreach ($in as $k) { $out[] = wpt_media_rewrite_label_key(base64_decode($k)); }\n"
        + "echo json_encode($out, JSON_THROW_ON_ERROR), \"\\n\";\n",
        encoding="utf-8")
    cases = [
        b"2023/10/pic.webp",                        # plain
        b"line\nbreak",                             # control characters
        b"\x00\x07\x1f\x7f",                        # every control class
        b"2023/10/qw\xe9.webp",                      # latin1 e-acute: NOT UTF-8
        b"2023/10/\xff\xfe.webp",                    # invalid on its own
        "café/2023/10/pic.webp".encode(),      # valid multi-byte
        "é".encode() * 400,                     # 400 CHARACTERS of multi-byte
    ]
    cases_file = tmp_path / "cases.json"
    cases_file.write_text(json.dumps(
        [base64.b64encode(case).decode() for case in cases]), encoding="utf-8")
    proc = subprocess.run(["php", str(script), str(cases_file)],
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    got = json.loads(proc.stdout)
    assert len(got) == 7
    assert got[0] == "2023/10/pic.webp"
    assert got[1] == "line break"
    assert got[2] == " "          # the four control bytes collapse
    # the invalid sequences are REPLACED, not dropped and not fatal: the
    # encode above would have thrown otherwise
    assert got[3] == "2023/10/qw?.webp", got[3]
    assert got[4] == "2023/10/??.webp", got[4]
    assert got[5] == "café/2023/10/pic.webp"
    # 400 characters of a 2-byte codepoint is 800 bytes: bounded by
    # CHARACTERS, and never cut in the middle of one
    assert len(got[6]) == 200
    json.loads(proc.stdout)   # the answer is encodable, which is the point


def test_media_rewrite_refs_keeps_two_LIST_values_that_rewrite_alike(bridge):
    # A VALUE collision is not a key collision: a list of two paths that
    # both rewrite to the same twin is two members of an array, and PHP
    # keeps both. Only dict keys collide, so this must still succeed and
    # must still hold two elements.
    value = ('a:2:{i:0;s:15:"2023/10/pic.jpg";i:1;s:16:"2023/10/pic.webp";}')
    scan(bridge)   # seeds the stub's table store
    rows_file = bridge.docroot / "wpt-stub-ref-rows.json"
    store = json.loads(rows_file.read_text())
    store["wp_postmeta"]["16"] = {"meta_id": "16", "post_id": "7",
                                  "meta_value": value}
    rows_file.write_text(json.dumps(store))
    data = bridge.call("media_rewrite_refs", {"apply": True, "mapping": {
        "2023/10/pic.jpg": "2023/10/pic.webp"},
        "rows": [{"table": "wp_postmeta", "key": "meta_id", "id": 16}]}).json()
    assert data["ok"] is True
    assert data["failed"] == []
    assert data["rows"] == [{
        "table": "wp_postmeta", "id": 16,
        "value": 'a:2:{i:0;s:16:"2023/10/pic.webp";i:1;s:16:"2023/10/pic.webp";}',
    }]
    stored = json.loads(rows_file.read_text())["wp_postmeta"]["16"]["meta_value"]
    assert stored.startswith("a:2:{"), "a list member was dropped"
    assert stored.count("2023/10/pic.webp") == 2


def test_media_rewrite_refs_keeps_both_keys_when_only_one_is_rewritten(bridge):
    # The regression's other direction: a normal two-key option whose ONE
    # reference key is rewritten comes back with BOTH keys. A collision
    # check that fired on "a key changed" instead of "a key landed on
    # another" would refuse this and silently stop rewriting every size map
    # on a real site.
    value = ('a:2:{s:15:"2023/10/pic.jpg";s:4:"hero";s:4:"note";s:4:"kept";}')
    scan(bridge)   # seeds the stub's table store
    rows_file = bridge.docroot / "wpt-stub-ref-rows.json"
    store = json.loads(rows_file.read_text())
    store["wp_options"]["8"] = {"option_id": "8", "option_name": "hero_map",
                                "autoload": "no", "option_value": value}
    rows_file.write_text(json.dumps(store))
    data = bridge.call("media_rewrite_refs", {"apply": True, "mapping": {
        "2023/10/pic.jpg": "2023/10/pic.webp"},
        "rows": [{"table": "wp_options", "key": "option_id", "id": 8}]}).json()
    assert data["ok"] is True
    assert data["failed"] == []
    assert data["rows"] == [{
        "table": "wp_options", "id": 8,
        "value": 'a:2:{s:16:"2023/10/pic.webp";s:4:"hero";s:4:"note";s:4:"kept";}',
    }]
    stored = json.loads(rows_file.read_text())["wp_options"]["8"]["option_value"]
    assert stored == 'a:2:{s:16:"2023/10/pic.webp";s:4:"hero";s:4:"note";s:4:"kept";}'
    assert stored.count("s:4:") == 3


@pytest.mark.parametrize("scalar", ["i:5;", "b:0;", "b:1;", "d:1.5;", "N;"])
def test_media_rewrite_refs_leaves_a_scalar_payload_exactly_as_it_is(bridge, scalar):
    # maybe_serialize() hands a SCALAR back UNSERIALIZED, so "storing the
    # rewrite" of "i:5;" would replace a five with the character "5" — and
    # "b:0;" with an empty string. A scalar payload holds no string leaf, so
    # there is nothing to rewrite and the value is returned untouched (the
    # answer still proves the row by re-reading it).
    scan(bridge)   # seeds the stub's table store
    rows_file = bridge.docroot / "wpt-stub-ref-rows.json"
    store = json.loads(rows_file.read_text())
    store["wp_options"]["5"] = {"option_id": "5", "option_name": "scalar",
                                "autoload": "no", "option_value": scalar}
    rows_file.write_text(json.dumps(store))
    data = bridge.call("media_rewrite_refs", {"apply": True, "mapping": {
        "2023/10/pic.jpg": "2023/10/pic.webp"},
        "rows": [{"table": "wp_options", "key": "option_id", "id": 5}]}).json()
    assert data["ok"] is True and data["failed"] == []
    assert data["rows"] == [{"table": "wp_options", "id": 5, "value": scalar}]
    assert json.loads(rows_file.read_text())["wp_options"]["5"]["option_value"] \
        == scalar


def test_media_rewrite_refs_never_rewrites_an_unreadable_value_into_nothing(bridge):
    # A value core's is_serialized() accepts but unserialize() rejects makes
    # maybe_unserialize() return false — and serializing THAT would store an
    # empty value, silently blanking a post body. The row is named as failed
    # and left exactly as it was. (The caller already refuses to send such a
    # row: an unparseable value is GATED there, never rewritten.)
    #
    # The fixture is TRUNCATED INSIDE the length prefix and CLOSED, so core
    # really does say "serialized": a value that merely LOOKS serialized
    # (core says no) is a plain rewrite, which the next test pins. A stub
    # is_serialized() loose enough to accept the open-brace form would have
    # made this test prove a refusal the server never issues.
    broken = 'a:2:{s:3:"key";s:9999:"truncated payload";}'
    scan(bridge)   # seeds the stub's table store
    rows_file = bridge.docroot / "wpt-stub-ref-rows.json"
    store = json.loads(rows_file.read_text())
    store["wp_postmeta"]["14"] = {"meta_id": "14", "post_id": "7",
                                  "meta_value": broken}
    rows_file.write_text(json.dumps(store))
    data = bridge.call("media_rewrite_refs", {"apply": True, "mapping": {
        "2023/10/pic.jpg": "2023/10/pic.webp"},
        "rows": [{"table": "wp_postmeta", "key": "meta_id", "id": 14}]}).json()
    assert data["ok"] is True
    assert data["rows"] == []
    assert data["failed"] == ["wp_postmeta[14] (value is serialized but unreadable)"]
    assert not any(c.startswith("UPDATE ") for c in bridge.calls())
    assert json.loads(rows_file.read_text())["wp_postmeta"]["14"]["meta_value"] == broken


def test_media_rewrite_refs_rewrites_a_plain_value_that_only_LOOKS_serialized(bridge):
    # The same stub is_serialized() that accepted a bare "s:" prefix would
    # call this "serialized but unreadable" — a refusal production never
    # issues.  core's real predicate says NOT serialized (the last byte is
    # neither ';' nor '}'), so this is the plain rewrite it looks like, and
    # the row is written.  (The space matters to the REWRITE, not to the
    # verdict: wpt_media_rewrite_text's token is "s:" on its own, so the
    # reference in it is found and moved.)
    plain = "s: 2023/10/pic.jpg"
    scan(bridge)   # seeds the stub's table store
    rows_file = bridge.docroot / "wpt-stub-ref-rows.json"
    store = json.loads(rows_file.read_text())
    store["wp_postmeta"]["15"] = {"meta_id": "15", "post_id": "7",
                                  "meta_value": plain}
    rows_file.write_text(json.dumps(store))
    data = bridge.call("media_rewrite_refs", {"apply": True, "mapping": {
        "2023/10/pic.jpg": "2023/10/pic.webp"},
        "rows": [{"table": "wp_postmeta", "key": "meta_id", "id": 15}]}).json()
    assert data["ok"] is True
    assert data["failed"] == []
    assert data["rows"] == [{"table": "wp_postmeta", "id": 15,
                             "value": "s: 2023/10/pic.webp"}]
    assert json.loads(rows_file.read_text())["wp_postmeta"]["15"]["meta_value"] \
        == "s: 2023/10/pic.webp"


#: A probe the docroot serves: it loads the SAME stub wp-load.php every
#: bridge call loads and asks core's three serialization helpers for their
#: verdicts on the values below.  Not a bridge op — the differential test
#: is about the HARNESS's copies of those functions, so it asks them
#: directly instead of inferring them from a rewrite's side effects.
SERDE_PROBE = r"""<?php
require_once __DIR__ . '/wp-load.php';
$cases = json_decode( (string) @file_get_contents( __DIR__ . '/wpt-stub-serde-cases.json' ), true );
$out   = array();
foreach ( (array) $cases as $value ) {
	$un = maybe_unserialize( $value );
	$out[] = array(
		'strict'        => is_serialized( $value ),
		'loose'         => is_serialized( $value, false ),
		'type'          => gettype( $un ),
		'value'         => is_object( $un ) ? get_class( $un ) : $un,
		'serialized'    => maybe_serialize( $value ),
	);
}
header( 'Content-Type: application/json' );
echo json_encode( $out ), "\n";
"""

#: The tricky values, each with CORE's documented verdict (src/wp-includes/
#: functions.php, is_serialized/maybe_unserialize/maybe_serialize).  The
#: table STATES core's answer, so the harness cannot drift from it silently:
#:   strict    is_serialized( $v )          — the predicate the op branches on
#:   loose     is_serialized( $v, false )   — maybe_serialize's own guard
#:   un        what maybe_unserialize() gives back
#:   ser       what maybe_serialize( $v ) gives back
#: Every `ser` that is NOT the value itself is core's DOUBLE-SERIALIZATION
#: branch (ticket #12930) — the one the harness stub used to drop.
SERDE_CASES = [
    # plain text that happens to start with a type letter and a colon: the
    # harness's old `preg_match('/^[aOsbdiC]:/')` called this SERIALIZED, and
    # an unreadable one became a "value is serialized but unreadable"
    # refusal production never issues.
    ("plain s: text",
     "s:2023/10/photo.jpg", False, False, ("string", "s:2023/10/photo.jpg"),
     "s:2023/10/photo.jpg"),
    # a REAL serialized string: serialized, unserializes to its contents,
    # and maybe_serialize DOUBLE-serializes it (that is the branch).
    ("serialized string",
     's:15:"2023/10/pic.jpg";', True, True, ("string", "2023/10/pic.jpg"),
     's:23:"s:15:"2023/10/pic.jpg";";'),
    # b:0; is serialized AND unserializes to false — the one serialized
    # value that legitimately reads as false, which the op must not mistake
    # for an unreadable one.
    ("false", "b:0;", True, True, ("boolean", False), 's:4:"b:0;";'),
    ("int", "i:5;", True, True, ("integer", 5), 's:4:"i:5;";'),
    ("float", "d:1.5;", True, True, ("double", 1.5), 's:6:"d:1.5;";'),
    # "N;" short-circuits BEFORE the length check, in the loose branch too.
    ("null", "N;", True, True, ("NULL", None), 's:2:"N;";'),
    ("nested array",
     'a:2:{s:3:"key";s:15:"2023/10/pic.jpg";s:4:"size";a:1:{s:3:"big";b:1;}}',
     True, True,
     ("array", {"key": "2023/10/pic.jpg", "size": {"big": True}}),
     None),                                # `ser` asserted structurally
    # TRUNCATED inside the length prefix but CLOSED: core says serialized
    # (the last byte is '}') and unserialize() then fails.  This is the only
    # shape the op's "serialized but unreadable" refusal is really about;
    # the same value with its brace missing is NOT serialized at all.
    ("truncated array", 'a:2:{s:3:"key";s:9999:"truncated";}', True, True,
     ("boolean", False), 's:35:"a:2:{s:3:"key";s:9999:"truncated";}";'),
    # an unterminated string: NOT serialized (the byte before ";" is not a
    # quote) yet it IS loose-serialized, so maybe_serialize double-wraps it.
    ("unterminated string", 's:5:"abc;', False, True,
     ("string", 's:5:"abc;'), 's:9:"s:5:"abc;";'),
]


def test_harness_serialization_helpers_agree_with_core(bridge):
    """DIFFERENTIAL: the harness's is_serialized / maybe_unserialize /
    maybe_serialize must return CORE's verdicts, on the values where the two
    are most likely to differ.

    The stub used to be `preg_match('/^[aOsbdiC]:/')`, which disagreed with
    core in BOTH directions on a real site: a plain-text value beginning
    "s:" read as serialized (so a fixture "proved" a refusal core never
    issues), and maybe_serialize's `is_serialized($data, false)` branch —
    core's double-serialization — was missing, so a value core double-wraps
    came back unwrapped.  Both are now core's own bodies, copied verbatim
    from src/wp-includes/functions.php (identical in the 6.8 tag and in
    trunk), and this table states the verdict each one must give.
    """
    values = [case[1] for case in SERDE_CASES]
    (bridge.docroot / "wpt-stub-serde-cases.json").write_text(
        json.dumps(values), encoding="utf-8")
    (bridge.docroot / "serde-probe.php").write_text(SERDE_PROBE, encoding="utf-8")
    r = requests.get(bridge.url("serde-probe.php"), timeout=10)
    assert r.status_code == 200, r.text
    answers = r.json()
    assert len(answers) == len(SERDE_CASES)
    for (name, value, strict, loose, un, ser), got in zip(SERDE_CASES, answers):
        assert got["strict"] is strict, (name, value, got)
        assert got["loose"] is loose, (name, value, got)
        assert (got["type"], got["value"]) == un, (name, value, got)
        if ser is None:
            # the nested array: core DOUBLE-serializes the raw string, so the
            # result is a serialized STRING wrapping exactly those bytes.
            # PHP's serialize() does NOT escape the inner quotes, so the
            # inner a:2:{…} travels verbatim.
            assert got["serialized"] == 's:%d:"%s";' % (len(value), value), name
        else:
            assert got["serialized"] == ser, (name, value, got)


def test_media_rewrite_refs_is_serialized_decides_which_rows_are_gated(bridge):
    """The differential table, read through the OP: the two rows whose core
    verdict differs from the old stub's must come out differently.

    ``s:2023/10/photo.jpg`` (plain text) and ``a:2:{s:3:"key";s:9999:"…"}``
    (serialized, unreadable) are BOTH "serialized" to the old stub and BOTH
    unserializable, so the old harness could not tell them apart and the one
    refusal it pinned was the wrong one.  Production tells them apart: one
    is rewritten as plain text, the other is named and left alone.
    """
    plain = "photo s: 2023/10/pic.jpg"
    unreadable = 'a:2:{s:3:"key";s:9999:"truncated";}'
    scan(bridge)   # seeds the stub's table store
    rows_file = bridge.docroot / "wpt-stub-ref-rows.json"
    store = json.loads(rows_file.read_text())
    store["wp_postmeta"]["17"] = {"meta_id": "17", "post_id": "7",
                                  "meta_value": plain}
    store["wp_postmeta"]["18"] = {"meta_id": "18", "post_id": "7",
                                  "meta_value": unreadable}
    rows_file.write_text(json.dumps(store))
    mapping = {"2023/10/pic.jpg": "2023/10/pic.webp"}
    data = bridge.call("media_rewrite_refs", {"apply": True, "mapping": mapping,
        "rows": [{"table": "wp_postmeta", "key": "meta_id", "id": 17},
                 {"table": "wp_postmeta", "key": "meta_id", "id": 18}]}).json()
    assert data["ok"] is True
    assert [row["id"] for row in data["rows"]] == [17]
    assert data["rows"][0]["value"] == "photo s: 2023/10/pic.webp"
    assert data["failed"] == ["wp_postmeta[18] (value is serialized but unreadable)"]
    stored = json.loads(rows_file.read_text())["wp_postmeta"]
    assert stored["17"]["meta_value"] == "photo s: 2023/10/pic.webp"
    assert stored["18"]["meta_value"] == unreadable


@pytest.mark.parametrize("row,marker", [
    ({"table": "wp_evil", "key": "ID", "id": 1}, "table not rewritable"),
    ({"table": "wp_posts", "key": "post_name", "id": 7}, "unexpected key column"),
    ({"table": "wp_posts", "key": "ID", "id": 0}, "invalid row id"),
    ({"table": "wp_posts", "key": "ID", "id": "seven"}, "invalid row id"),
    ({"table": "wp_posts", "key": "ID", "id": 7, "value": 42}, "must be a string"),
    ({"table": "wp_posts", "id": 7}, "unexpected key column"),
])
def test_media_rewrite_refs_apply_refuses_a_malformed_row(bridge, row, marker):
    # Fail-closed, BEFORE the first write: a request that names something
    # the op may not touch writes nothing at all (db_restore_table's
    # discipline), so a bad row can never leave a half-applied rewrite.
    before = len(bridge.calls())
    data = bridge.call("media_rewrite_refs", {"apply": True, "mapping": {
        "2023/10/pic.jpg": "2023/10/pic.webp"}, "rows": [row]}).json()
    assert data["ok"] is False
    assert marker in data["error"]
    assert not any(c.startswith("UPDATE ") for c in bridge.calls()[before:])


def test_media_rewrite_refs_apply_validates_every_row_before_writing_any(bridge):
    # The good row comes FIRST: a per-row write loop would have written it
    # before the refusal on the second one.
    data = bridge.call("media_rewrite_refs", {"apply": True, "mapping": {
        "2023/10/pic.jpg": "2023/10/pic.webp"}, "rows": [
        {"table": "wp_posts", "key": "ID", "id": 7},
        {"table": "wp_evil", "key": "ID", "id": 1},
    ]}).json()
    assert data["ok"] is False
    assert not any(c.startswith("UPDATE ") for c in bridge.calls())


@pytest.mark.parametrize("mapping,marker", [
    ([], "empty mapping"),
    ("2023/10/pic.jpg", "missing or non-array"),
    ({"2023/10/pic.jpg": 7}, "invalid mapping entry"),
    ({"": "x.webp"}, "invalid mapping entry"),
    ({"../escape.jpg": "x.webp"}, "traversal"),
    ({2018: "x.webp"}, "invalid mapping entry"),
])
def test_media_rewrite_refs_apply_refuses_a_malformed_mapping(bridge, mapping, marker):
    data = bridge.call("media_rewrite_refs", {"apply": True, "mapping": mapping,
        "rows": [{"table": "wp_posts", "key": "ID", "id": 7}]}).json()
    assert data["ok"] is False
    assert marker in data["error"]


def test_media_rewrite_refs_apply_refuses_over_the_row_ceiling(bridge):
    # The batch bound is enforced (the caller batches at 100; the op
    # refuses at 5000) and the mirror is pinned, so the two cannot drift.
    assert "define( 'WPT_MEDIA_REWRITE_ROW_MAX', 5000 );" in \
        BRIDGE_SOURCE.read_text(encoding="utf-8")
    rows = [{"table": "wp_posts", "key": "ID", "id": 1}] * 5001
    data = bridge.call("media_rewrite_refs", {"apply": True, "mapping": {
        "a.jpg": "a.webp"}, "rows": rows}).json()
    assert data["ok"] is False
    assert "too many rows" in data["error"]


def test_media_rewrite_refs_apply_flag_is_strict(bridge):
    # Strict booleans, like reconcile_active_plugins: the string "true"
    # is not consent to write.
    for flag in ("true", 1, "1", "yes"):
        r = bridge.call("media_rewrite_refs", {"apply": flag, "mapping": {
            "2023/10/pic.jpg": "2023/10/pic.webp"},
            "rows": [{"table": "wp_posts", "key": "ID", "id": 7}]})
        assert "x-ndjson" in r.headers["Content-Type"]
        # answered as the READ mode: the scan's own completion line, and
        # no write anywhere
        assert json.loads(r.text.splitlines()[-1])["truncated"] is False
    assert not any(c.startswith("UPDATE ") for c in bridge.calls())


def test_media_rewrite_refs_surface_table_mirrors_the_action(bridge):
    """The surfaces must be the ACTION's, or the rewrite reaches a
    different column than the plan measured (wpt/actions/images_webp.py's
    _REWRITABLE_TABLES + _GATED_TABLES, matched by table-name SUFFIX)."""
    from wpt.actions.images_webp import _GATED_TABLES, _REWRITABLE_TABLES
    src = BRIDGE_SOURCE.read_text(encoding="utf-8")
    body = re.search(
        r"function wpt_media_rewrite_tables\(\) \{\s*return array\((.*?)\n\t\);",
        src, re.S).group(1)
    php = {}
    for line in body.strip().splitlines():
        m = re.match(
            r"""\s*'([^']+)'\s*=>\s*array\(\s*'key'\s*=>\s*'([^']+)',\s*"""
            r"""'value'\s*=>\s*'([^']*)',\s*'gated'\s*=>\s*array\(([^)]*)\)\s*\)""",
            line)
        assert m, f"unparsed surface line: {line!r}"
        gated = re.findall(r"'([^']+)'", m.group(4))
        php[m.group(1)] = (m.group(2), m.group(3), tuple(gated))
    expected = {}
    for suffix, (key, value) in _REWRITABLE_TABLES.items():
        expected[suffix] = (key, value, tuple(_GATED_TABLES.get(suffix, ())))
    for suffix, gated in _GATED_TABLES.items():
        expected.setdefault(suffix, (None, "", tuple(gated)))
    # the action's own key column for a rewritable surface
    for suffix, (key, value, gated) in list(expected.items()):
        if value and not key:
            expected[suffix] = (None, value, gated)
    assert set(php) == set(expected), (sorted(php), sorted(expected))
    for suffix, spec in php.items():
        key, value, gated = expected[suffix]
        if value:
            assert spec[0] == key and spec[1] == value, suffix
        assert spec[2] == gated, suffix


# ---------------------------------------------------------------------------
# db_dump (NDJSON stream)
# ---------------------------------------------------------------------------

def test_db_dump_ndjson(bridge):
    r = bridge.call("db_dump", {"tables": ["wpt_rows"]})
    assert r.status_code == 200
    assert r.headers["Content-Type"].startswith("application/x-ndjson")
    lines = r.content.decode("utf-8").splitlines()
    assert len(lines) == 4
    first = json.loads(lines[0])
    assert first["table"] == "wpt_rows"
    assert "CREATE TABLE" in first["create"]
    row1 = json.loads(lines[1])
    row2 = json.loads(lines[2])
    assert row1 == {"table": "wpt_rows", "row": ["1", "hello"]}
    assert row2 == {"table": "wpt_rows", "row": ["2", "wörld"]}  # multibyte-safe
    done = json.loads(lines[3])
    assert done == {"table": "wpt_rows", "done": 2}


def test_db_dump_batched_by_pk_offset(bridge):
    before = len(bridge.calls())
    r = bridge.call("db_dump", {"tables": ["wpt_rows"], "chunk_rows": 1})
    lines = r.content.decode("utf-8").splitlines()
    assert len(lines) == 4  # create + 2 rows + done
    assert json.loads(lines[3]) == {"table": "wpt_rows", "done": 2}
    new_calls = bridge.calls()[before:]
    assert "SELECT * FROM `wpt_rows` ORDER BY `id` LIMIT 1 OFFSET 0" in new_calls
    assert "SELECT * FROM `wpt_rows` ORDER BY `id` LIMIT 1 OFFSET 1" in new_calls
    assert "SELECT * FROM `wpt_rows` ORDER BY `id` LIMIT 1 OFFSET 2" in new_calls  # terminating empty batch


def test_db_dump_pkless_table_unbatched(bridge):
    before = len(bridge.calls())
    r = bridge.call("db_dump", {"tables": ["wpt_flat"]})
    lines = r.content.decode("utf-8").splitlines()
    assert len(lines) == 3
    assert json.loads(lines[0])["table"] == "wpt_flat"
    assert json.loads(lines[1]) == {"table": "wpt_flat", "row": ["x", "y"]}
    assert json.loads(lines[2]) == {"table": "wpt_flat", "done": 1}
    new_calls = bridge.calls()[before:]
    assert any(c.startswith("SELECT * FROM `wpt_flat`") for c in new_calls)


def test_db_dump_table_not_whitelisted(bridge):
    data = bridge.call("db_dump", {"tables": ["mysql.user"]}).json()
    assert data["ok"] is False
    assert "table not allowed" in data["error"]


# ---------------------------------------------------------------------------
# db_restore_table
# ---------------------------------------------------------------------------

RID = "a1b2c3d4"  # deterministic 8-hex restore token for assertions
STAGING = f"wpt_rows__wpt_{RID}__s"
OLD = f"wpt_rows__wpt_{RID}__o"


def test_db_restore_table(bridge):
    # A full single-call restore: stage the rows, prove the count, then swap
    # atomically. The live table is NEVER truncated (TRUNCATE cannot roll back).
    before = len(bridge.calls())
    r = bridge.call("db_restore_table", {
        "table": "wpt_rows",
        "rows": [[3, "new"], [4, "wörld"]],
        "restore_id": RID,
        "total_rows": 2,
        "truncate_first": True,
        "finalize": True,
    })
    data = r.json()
    assert data == {"ok": True, "table": "wpt_rows", "inserted": 2,
                    "swapped": True, "old_left": False}
    new_calls = bridge.calls()[before:]
    assert not any("TRUNCATE" in c for c in new_calls)
    assert f"CREATE TABLE `{STAGING}` LIKE `wpt_rows`" in new_calls
    inserts = [c for c in new_calls if c.startswith(f"INSERT INTO `{STAGING}`")]
    assert len(inserts) == 1
    assert "( '3', 'new' )" in inserts[0]
    assert "'wörld'" in inserts[0]
    assert f"RENAME TABLE `wpt_rows` TO `{OLD}`, `{STAGING}` TO `wpt_rows`" in new_calls
    assert f"DROP TABLE IF EXISTS `{OLD}`" in new_calls


def test_db_restore_table_multi_call_atomic_swap(bridge):
    # Chunked restore: the first call creates the owned staging table and
    # inserts, a middle call appends, and only the finalize call (after the
    # count matches total_rows) performs the single atomic RENAME. No reader
    # ever sees the live table emptied, and any failure before finalize
    # leaves it untouched.
    before = len(bridge.calls())
    d1 = bridge.call("db_restore_table", {
        "table": "wpt_rows", "rows": [[1, "a"]], "restore_id": RID,
        "total_rows": 3, "truncate_first": True,
    }).json()
    assert d1["swapped"] is False
    d2 = bridge.call("db_restore_table", {
        "table": "wpt_rows", "rows": [[2, "b"]], "restore_id": RID, "total_rows": 3,
    }).json()
    assert d2["swapped"] is False
    d3 = bridge.call("db_restore_table", {
        "table": "wpt_rows", "rows": [[3, "c"]], "restore_id": RID,
        "total_rows": 3, "finalize": True,
    }).json()
    assert d3["swapped"] is True
    new_calls = bridge.calls()[before:]
    # staging created exactly once, one atomic rename at the end, no truncate
    assert sum(1 for c in new_calls if c.startswith("CREATE TABLE")) == 1
    assert sum(1 for c in new_calls if c.startswith("RENAME TABLE")) == 1
    assert not any("TRUNCATE" in c for c in new_calls)
    # every insert targets the owned staging table, never the live table
    assert all(c.startswith(f"INSERT INTO `{STAGING}`")
               for c in new_calls if c.startswith("INSERT INTO"))


def test_db_restore_table_refuses_incomplete_staging(bridge):
    # THE completeness proof: staging holds fewer rows than the declared
    # total_rows, so the swap must be refused and the live table untouched.
    # This is what makes a premature finalize (begin + finalize on a partial
    # table) fail closed.
    bridge.call("db_restore_table", {
        "table": "wpt_rows", "rows": [[1, "a"]], "restore_id": RID,
        "total_rows": 5, "truncate_first": True,
    })
    data = bridge.call("db_restore_table", {
        "table": "wpt_rows", "rows": [[2, "b"]], "restore_id": RID,
        "total_rows": 5, "finalize": True,
    }).json()
    assert data["ok"] is False
    assert "swap refused" in data["error"]
    # the live table was NOT renamed over
    assert "RENAME TABLE" not in "\n".join(bridge.calls())


def test_db_restore_table_duplicate_staging_fails_closed(bridge):
    # An ambiguous network retry re-sends the finalize chunk, so the staged
    # count EXCEEDS total_rows; the swap is refused (no duplicates swapped
    # into a PK-less table).
    bridge.call("db_restore_table", {
        "table": "wpt_rows", "rows": [[1, "a"]], "restore_id": RID,
        "total_rows": 1, "truncate_first": True,
    })
    data = bridge.call("db_restore_table", {
        "table": "wpt_rows", "rows": [[1, "a"]], "restore_id": RID,
        "total_rows": 1, "finalize": True,
    }).json()
    assert data["ok"] is False
    assert "swap refused" in data["error"]


def test_db_restore_table_concurrent_tokens_isolated(bridge):
    # Two concurrent restores of the same table use DIFFERENT restore_ids, so
    # they never share or clobber each other's staging.
    rid_a, rid_b = "aaaaaaaa", "bbbbbbbb"
    stg_a = f"wpt_rows__wpt_{rid_a}__s"
    stg_b = f"wpt_rows__wpt_{rid_b}__s"
    bridge.call("db_restore_table", {
        "table": "wpt_rows", "rows": [[1, "a"]], "restore_id": rid_a,
        "total_rows": 1, "truncate_first": True,
    })
    bridge.call("db_restore_table", {
        "table": "wpt_rows", "rows": [[9, "z"]], "restore_id": rid_b,
        "total_rows": 1, "truncate_first": True,
    })
    calls = bridge.calls()
    # both staging tables were created independently, neither dropped the other
    assert any(f"CREATE TABLE `{stg_a}`" in c for c in calls)
    assert any(f"CREATE TABLE `{stg_b}`" in c for c in calls)
    # restore A finalizes ITS OWN staging (completes: 1 row staged)
    d = bridge.call("db_restore_table", {
        "table": "wpt_rows", "rows": [[1, "a"]], "restore_id": rid_a,
        "total_rows": 2, "finalize": True,
    }).json()
    assert d["swapped"] is True  # A staged 1 + this row = 2 == total_rows
    # restore B's staging is untouched by A's swap and can still complete
    d = bridge.call("db_restore_table", {
        "table": "wpt_rows", "rows": [[9, "z"]], "restore_id": rid_b,
        "total_rows": 2, "finalize": True,
    }).json()
    assert d["swapped"] is True


def test_db_restore_table_empty_table_swaps(bridge):
    # A zero-row table still restores: stage an empty table and swap it in.
    data = bridge.call("db_restore_table", {
        "table": "wpt_rows", "rows": [], "restore_id": RID,
        "total_rows": 0, "truncate_first": True, "finalize": True,
    }).json()
    assert data["ok"] is True
    assert data["inserted"] == 0
    assert data["swapped"] is True


def test_db_restore_table_refuses_fk(bridge):
    # A plugin-added foreign key makes a RENAME-based swap unsafe, so the
    # restore is refused instead of corrupting the schema.
    (bridge.docroot / "wpt-stub-has-fk").write_text("")
    data = bridge.call("db_restore_table", {
        "table": "wpt_rows", "rows": [[1, "a"]], "restore_id": RID,
        "total_rows": 1, "truncate_first": True, "finalize": True,
    }).json()
    assert data["ok"] is False
    assert "atomic swap is unsafe" in data["error"]


def test_db_restore_table_refuses_fk_when_metadata_unreadable(bridge):
    # Fail CLOSED: an unreadable FK/trigger metadata query is UNKNOWN, not
    # "safe" — (int) null would coerce a failed query to 0.
    (bridge.docroot / "wpt-stub-fk-unreadable").write_text("")
    data = bridge.call("db_restore_table", {
        "table": "wpt_rows", "rows": [[1, "a"]], "restore_id": RID,
        "total_rows": 1, "truncate_first": True,
    }).json()
    assert data["ok"] is False
    assert "could not verify" in data["error"]


def test_db_restore_table_refuses_trigger(bridge):
    # Triggers are not reproduced by CREATE TABLE ... LIKE and do not move
    # with the swap, so a triggered table is refused too.
    (bridge.docroot / "wpt-stub-has-trigger").write_text("")
    data = bridge.call("db_restore_table", {
        "table": "wpt_rows", "rows": [[1, "a"]], "restore_id": RID,
        "total_rows": 1, "truncate_first": True, "finalize": True,
    }).json()
    assert data["ok"] is False
    assert "atomic swap is unsafe" in data["error"]


def test_db_restore_table_finalize_without_begin_fails_closed(bridge):
    # A finalize with no staging for this token must fail closed rather than
    # swap an absent table.
    data = bridge.call("db_restore_table", {
        "table": "wpt_rows", "rows": [[1, "a"]], "restore_id": RID,
        "total_rows": 1, "finalize": True,
    }).json()
    assert data["ok"] is False
    assert "must start with truncate_first" in data["error"]


def test_db_restore_table_rejects_bad_restore_id(bridge):
    # The token must be validated: it scopes ownership of the scratch names.
    data = bridge.call("db_restore_table", {
        "table": "wpt_rows", "rows": [[1, "a"]], "restore_id": "zz; DROP",
        "total_rows": 1, "truncate_first": True,
    }).json()
    assert data["ok"] is False
    assert "invalid restore_id" in data["error"]


def test_db_restore_table_only_drops_its_own_token_staging(bridge):
    # Ownership is by the EXACT restore_id token. A different token-shaped
    # user table ("...deadbeefdeadbeef__s") must survive a restore that uses
    # its own token; only "wpt_rows__wpt_<our-id>__s" is ours to drop.
    (bridge.docroot / "wpt-stub-user-scratch-table").write_text("")
    other = "wpt_rows__wpt_deadbeefdeadbeef__s"
    d = bridge.call("db_restore_table", {
        "table": "wpt_rows", "rows": [[1, "a"]], "restore_id": RID,
        "total_rows": 1, "truncate_first": True, "finalize": True,
    }).json()
    assert d["ok"] is True and d["swapped"] is True
    after = set(json.loads((bridge.docroot / "wpt-stub-tables.json").read_text()))
    assert other in after, "a different token's table was clobbered!"
    assert f"wpt_rows__wpt_{RID}__s" not in after  # our staging was consumed


def test_db_audit_hides_owned_scratch_tables(bridge):
    # Stage a restore (leaves an owned staging table), then audit: the
    # bridge's own scratch table must not appear as a site table. The
    # registry assert first proves the staging table really exists, so this
    # is not a vacuous pass (old truncate code creates no staging).
    bridge.call("db_restore_table", {
        "table": "wpt_rows", "rows": [[1, "a"]], "restore_id": RID,
        "total_rows": 1, "truncate_first": True,
    })
    reg = json.loads((bridge.docroot / "wpt-stub-tables.json").read_text())
    assert f"wpt_rows__wpt_{RID}__s" in reg, "no staging was created"
    raw = bridge.call("db_audit").json()
    names = {t["name"] for t in raw["tables"]}
    assert not any(n.endswith("__s") or n.endswith("__o") for n in names), (
        f"owned scratch leaked into audit: {names}"
    )
    assert "wpt_rows" in names  # the real table IS still listed


def test_db_restore_table_refuses_name_too_long_for_staging(bridge):
    # Identifiers are capped at 64 chars; a live name that cannot carry the
    # tokenized suffix is refused (identifiers are never silently truncated).
    (bridge.docroot / "wpt-stub-long-name").write_text("")
    data = bridge.call("db_restore_table", {
        "table": "wpt_" + "x" * 48, "rows": [[1, "a"]], "restore_id": RID,
        "total_rows": 1, "truncate_first": True, "finalize": True,
    }).json()
    assert data["ok"] is False
    assert "too long for atomic staging" in data["error"]


def test_db_restore_table_null_and_binary_cells(bridge):
    before = len(bridge.calls())
    r = bridge.call("db_restore_table", {
        "table": "wpt_rows",
        "rows": [[5, None], [6, ["__wpt_b64__", "aMOp"]]],
        "restore_id": RID,
        "total_rows": 2,
        "truncate_first": True,
        "finalize": True,
    })
    data = r.json()
    assert data["ok"] is True
    assert data["inserted"] == 2
    inserts = [c for c in bridge.calls()[before:] if c.startswith(f"INSERT INTO `{STAGING}`")]
    assert len(inserts) == 1
    assert "( '5', NULL )" in inserts[0]        # NULL survives as SQL NULL, not ''
    assert "( '6', 'h\u00e9' )" in inserts[0]   # base64 marker decodes to the raw UTF-8 bytes


def test_db_restore_table_refuses_over_5000_rows(bridge):
    before = len(bridge.calls())
    rows = [[str(i), f"x{i}"] for i in range(5001)]
    data = bridge.call("db_restore_table", {"table": "wpt_rows", "rows": rows}).json()
    assert data["ok"] is False
    assert "too many rows" in data["error"]
    new_calls = bridge.calls()[before:]
    assert not any(c.startswith(("INSERT INTO", "CREATE TABLE", "RENAME TABLE")) for c in new_calls)


def test_db_restore_table_unknown_table(bridge):
    data = bridge.call("db_restore_table", {"table": "secret_table", "rows": [["1"]]}).json()
    assert data["ok"] is False
    assert "table not allowed" in data["error"]


def test_db_restore_table_row_width_mismatch(bridge):
    data = bridge.call("db_restore_table", {"table": "wpt_rows", "rows": [[1, "a", "b"]],
                                           "restore_id": RID, "total_rows": 1}).json()
    assert data["ok"] is False
    assert "row width mismatch" in data["error"]


# ---------------------------------------------------------------------------
# plugin_deactivate / purge_cache / fileperms
# ---------------------------------------------------------------------------

def test_plugin_deactivate(bridge):
    before = len(bridge.calls())
    data = bridge.call("plugin_deactivate", {"slugs": ["litespeed-cache"]}).json()
    assert data["ok"] is True
    assert data["before"] == 3
    assert data["after"] == 2
    assert data["removed"] == ["litespeed-cache/litespeed-cache.php"]
    assert data["updated"] is True
    assert "update_option:active_plugins" in bridge.calls()[before:]

    # dirless single-file plugins match by filename
    data = bridge.call("plugin_deactivate", {"slugs": ["hello.php"]}).json()
    assert data["removed"] == ["hello.php"]

    # "folder/file.php" slugs match by dirname
    data = bridge.call("plugin_deactivate", {"slugs": ["akismet/akismet.php"]}).json()
    assert data["removed"] == ["akismet/akismet.php"]

    # nothing matches -> no update_option call
    before = len(bridge.calls())
    data = bridge.call("plugin_deactivate", {"slugs": ["not-installed"]}).json()
    assert data["ok"] is True
    assert data["removed"] == []
    assert data["updated"] is None
    assert "update_option:active_plugins" not in bridge.calls()[before:]


# ---------------------------------------------------------------------------
# reconcile_active_plugins
# ---------------------------------------------------------------------------

def _active_plugins_file(bridge):
    return bridge.docroot / "wpt-stub-active-plugins.json"


def _seed_active_plugins(bridge, *files):
    """Activate plugin files that need not be installed, persistently."""
    _active_plugins_file(bridge).write_text(json.dumps(list(files)),
                                            encoding="utf-8")


def _active_plugins_now(bridge):
    """The PERSISTED option value (the harness's file-backed store)."""
    return json.loads(_active_plugins_file(bridge).read_text(encoding="utf-8"))


def test_reconcile_active_plugins_drops_a_present_plugin_the_inventory_skips(bridge):
    # Core's own repair (wp-admin's validate_plugin()) has THREE criteria,
    # and the third IS the plugin-header inventory: a main file that exists
    # but whose header get_plugins() cannot read — an unreadable file, a
    # headerless stray .php, a truncated transfer — is deactivated by
    # wp-admin too ('no_plugin_header'). The op must match it: the plugin
    # is still LOADED by the front end (wp_get_active_and_valid_plugins
    # only asks file_exists), so this is the one place where "what the
    # runtime does" and "what wp-admin repairs" disagree, and matching
    # wp-admin is the op's stated contract. The action plans every entry by
    # name, the operator confirms, the snapshot reverts it, and the apply
    # re-reads the option.
    _seed_active_plugins(
        bridge,
        "akismet/akismet.php",
        "headerless/headerless.php",
        "locked/locked.php",
        "all-in-one-wp-migration/all-in-one-wp-migration.php",
    )
    dry = bridge.call("reconcile_active_plugins").json()
    assert dry["ok"] is True
    # Four header-bearing plugins on disk; the two present-but-skipped files
    # are NOT in the inventory, so the inventory is 4 and core's repair
    # drops all three failures.
    assert dry["installed"] == 4
    assert dry["missing"] == [
        "headerless/headerless.php",
        "locked/locked.php",
        "all-in-one-wp-migration/all-in-one-wp-migration.php",
    ]
    data = bridge.call("reconcile_active_plugins", {"apply": True}).json()
    assert data["ok"] is True
    assert data["removed"] == dry["missing"]
    assert _active_plugins_now(bridge) == ["akismet/akismet.php"]
    assert data["active_now"] == ["akismet/akismet.php"]
    # The file itself is untouched: this op rewrites the option, it never
    # deletes plugin code (that is clean-files' job).
    assert (bridge.docroot / "wp-content" / "plugins" / "headerless"
            / "headerless.php").exists()


def test_reconcile_active_plugins_drops_exactly_what_core_would(bridge):
    # wp-admin's validate_plugin() order: empty entry, invalid path, main
    # file not on disk, no valid header. The op must reproduce that SET,
    # and the plan/apply contract (the action) then carries every name.
    (bridge.docroot / "wp-content" / "plugins" / "notaplugin").mkdir()
    (bridge.docroot / "wp-content" / "plugins" / "notaplugin" / "readme.txt").write_text(
        "no main file here\n", encoding="utf-8")
    (bridge.docroot / "wp-content" / "plugins" / "loose-script.php").write_text(
        "<?php\n/*\nPlugin Name: Loose\nVersion: 1.0\n*/\n", encoding="utf-8")
    _seed_active_plugins(
        bridge,
        "akismet/akismet.php",       # keep: listed and on disk
        "loose-script.php",          # keep: a root-level single-file plugin
        "",                          # drop: core's empty entry
        "notaplugin/readme.txt",     # drop: no main file on disk
        "../../../wp-config.php",    # drop: validate_file() rejects the path
        "gone/gone.php",             # drop: main file not on disk
    )
    data = bridge.call("reconcile_active_plugins", {"apply": True}).json()
    assert data["ok"] is True
    assert data["removed"] == [
        "", "notaplugin/readme.txt", "../../../wp-config.php", "gone/gone.php",
    ]
    assert _active_plugins_now(bridge) == [
        "akismet/akismet.php", "loose-script.php",
    ]


def test_reconcile_active_plugins_corrupt_option_fails_loudly(bridge):
    # A non-list option is an UNREADABLE state, not an empty one. Answering
    # [] would make the plan claim "every active plugin is installed" and the
    # run exit 0 on a site whose active_plugins is corrupt — a successful,
    # reassuring reconciliation of nothing. The absent option (get_option's
    # false) is the one legitimate empty state and must stay silent.
    # A JSON list written into the option by hand is the realistic version
    # of this corruption; the bare string and the scalars are the others.
    for literal in (r"""'["akismet/akismet.php"]'""", '"akismet/akismet.php"',
                    "1", "''", '"a, b"', "0"):
        (bridge.docroot / "wpt-stub-active-plugins-raw").write_text(
            "<?php return " + literal + ";", encoding="utf-8")
        before = len(bridge.calls())
        data = bridge.call("reconcile_active_plugins", {"apply": True}).json()
        assert data["ok"] is False, literal
        assert "not a list" in data["error"], literal
        # Read-only too: the refusal must not depend on the apply flag.
        assert bridge.call("reconcile_active_plugins").json()["ok"] is False
        # ... and nothing was written.
        assert not any(c.startswith("update_option:active_plugins")
                       for c in bridge.calls()[before:])
    # The ABSENT option — get_option's false, which is what a site that
    # never activated a plugin returns — is empty, not corrupt: no refusal,
    # nothing to reconcile, and a write that is never attempted.
    (bridge.docroot / "wpt-stub-active-plugins-raw").write_text(
        "<?php return false;", encoding="utf-8")
    before = len(bridge.calls())
    data = bridge.call("reconcile_active_plugins", {"apply": True}).json()
    assert data["ok"] is True
    assert data["active_before"] == 0
    assert data["missing"] == []
    assert data["active_now"] == []
    assert not any(c.startswith("update_option:active_plugins")
                   for c in bridge.calls()[before:])


def test_R18_active_plugins_non_string_entry_is_json_refusal_never_strval(
        bridge):
    """R18-P2: an array entry in active_plugins emitted "Array to string
    conversion" BEFORE info's JSON (every audit fact lost), and the mutating
    ops wrote the literal "Array" into the option.  The shared list owner
    refuses the corrupt set as valid JSON, before any write."""
    (bridge.docroot / "wpt-stub-active-plugins-raw").write_text(
        "<?php return array('akismet/akismet.php', array('x'));",
        encoding="utf-8")

    info = bridge.call("info")
    assert info.status_code == 200
    data = info.json()          # a printed warning would raise here
    assert data["ok"] is False
    assert "active_plugins" in data["error"]
    assert "not a string" in data["error"]

    before = len(bridge.calls())
    deactivate = bridge.call("plugin_deactivate", {"slugs": ["akismet"]})
    assert deactivate.json()["ok"] is False
    reconcile = bridge.call("reconcile_active_plugins", {"apply": True})
    assert reconcile.json()["ok"] is False
    assert not any(c.startswith("update_option:active_plugins")
                   for c in bridge.calls()[before:])


def test_R18_upgrade_marker_non_scalar_timestamps_are_unknown_not_1(bridge):
    """R18-P2: a marker ``started``/``finished`` array was cast with
    ``(int)`` — a printed warning and a fabricated 1.  Unknown stays null."""
    (bridge.docroot / "wpt-stub-marker.json").write_text(json.dumps({
        "started": ["not", "a", "time"],
        "finished": {"nope": True},
        "from_db_version": "1",
    }), encoding="utf-8")
    data = bridge.call("info").json()   # a warning would break the parse
    assert data["ok"] is True
    assert data["upgrade_marker"]["started"] is None
    assert data["upgrade_marker"]["finished"] is None


def test_reconcile_active_plugins_refuses_without_the_plugin_inventory(bridge):
    # Fail-closed precondition: if get_plugins() cannot answer, the op must
    # refuse outright. Treating an unavailable inventory as "nothing is
    # installed" would classify EVERY active plugin as missing and, on an
    # apply, deactivate the whole site in one write.
    (bridge.docroot / "wp-content" / "plugins" / "akismet" / "akismet.php").unlink()
    (bridge.docroot / "wpt-stub-no-plugins").write_text("")
    _seed_active_plugins(bridge, "akismet/akismet.php", "gone/gone.php")
    before = len(bridge.calls())
    for params in ({}, {"apply": True}):
        data = bridge.call("reconcile_active_plugins", params).json()
        assert data["ok"] is False, params
        assert data["error"] == "plugin inventory unavailable"
    assert not any(c.startswith("update_option:active_plugins")
                   for c in bridge.calls()[before:])
    assert _active_plugins_now(bridge) == ["akismet/akismet.php", "gone/gone.php"]


def test_reconcile_active_plugins_dry_run_is_read_only(bridge):
    # The migration state: an option that still lists a plugin whose
    # directory clean-files removed.
    _seed_active_plugins(
        bridge,
        "akismet/akismet.php",
        "all-in-one-wp-migration/all-in-one-wp-migration.php",
        "velvet-blues-update-urls/velvet.php",
        "hello.php",
    )
    before = len(bridge.calls())
    data = bridge.call("reconcile_active_plugins").json()
    assert data["ok"] is True
    assert data["installed"] == 4  # the stub's get_plugins()
    assert data["active_before"] == 4
    assert data["missing"] == [
        "all-in-one-wp-migration/all-in-one-wp-migration.php",
        "velvet-blues-update-urls/velvet.php",
    ]
    # READ-ONLY: no apply flag, no write, nothing removed, option untouched.
    assert data["applied"] is False
    assert data["updated"] is None
    assert data["removed"] == []
    assert data["active_after"] == 4
    assert "update_option:active_plugins" not in bridge.calls()[before:]
    assert _active_plugins_now(bridge) == [
        "akismet/akismet.php",
        "all-in-one-wp-migration/all-in-one-wp-migration.php",
        "velvet-blues-update-urls/velvet.php",
        "hello.php",
    ]


def test_reconcile_active_plugins_rewrites_the_option(bridge):
    _seed_active_plugins(
        bridge,
        "akismet/akismet.php",
        "all-in-one-wp-migration/all-in-one-wp-migration.php",
        "hello.php",
    )
    before = len(bridge.calls())
    data = bridge.call("reconcile_active_plugins", {"apply": True}).json()
    assert data["ok"] is True
    assert data["applied"] is True
    assert data["updated"] is True
    assert data["removed"] == [
        "all-in-one-wp-migration/all-in-one-wp-migration.php",
    ]
    assert data["active_after"] == 2
    new_calls = bridge.calls()[before:]
    assert "update_option:active_plugins" in new_calls
    # Core-faithful: the 2-argument update_option() (autoload untouched);
    # a third argument would set autoload=off on WP 6.6+.
    assert not any(c.startswith("update_option:argcount=") for c in new_calls)
    # The rewrite is PERSISTED, and the op re-read the option itself.
    assert _active_plugins_now(bridge) == ["akismet/akismet.php", "hello.php"]
    assert data["active_now"] == ["akismet/akismet.php", "hello.php"]

    # The independent verification read the action performs: the option no
    # longer lists anything absent, in ANY later request.
    after = bridge.call("reconcile_active_plugins").json()
    assert after["missing"] == []
    assert after["active_before"] == 2
    assert after["applied"] is False


def test_reconcile_active_plugins_nothing_missing(bridge):
    _seed_active_plugins(bridge, "akismet/akismet.php", "hello.php")
    before = len(bridge.calls())
    data = bridge.call("reconcile_active_plugins", {"apply": True}).json()
    assert data["ok"] is True
    assert data["missing"] == []
    assert data["removed"] == []
    # Nothing to reconcile -> no write at all (deactivate-plugin's rule)
    assert data["updated"] is None
    assert "update_option:active_plugins" not in bridge.calls()[before:]


def test_reconcile_active_plugins_apply_flag_is_strict(bridge):
    # "apply" is a STRICT boolean: a truthy non-boolean must not write.
    _seed_active_plugins(bridge, "akismet/akismet.php", "gone/gone.php")
    for value in ("true", 1, ["yes"]):
        before = len(bridge.calls())
        data = bridge.call(
            "reconcile_active_plugins", {"apply": value}).json()
        assert data["ok"] is True, value
        assert data["applied"] is False, value
        assert data["updated"] is None, value
        assert data["missing"] == ["gone/gone.php"], value
        assert "update_option:active_plugins" not in bridge.calls()[before:]


# ---------------------------------------------------------------------------
# users_reset
# ---------------------------------------------------------------------------

def test_users_reset_dry_run_is_read_only(bridge):
    before = len(bridge.calls())
    data = bridge.call("users_reset").json()
    assert data["ok"] is True
    results = data["results"]
    assert results["count"] == 3
    assert [row["login"] for row in results["users"]] == [
        "admin", "editor", "author",
    ]
    assert results["users"][0] == {
        "login": "admin",
        "email": "admin@example.test",
        "roles": ["administrator"],
    }
    # READ-ONLY: no password exists at all, and no session was touched.
    assert all("password" not in row for row in results["users"])
    new_calls = bridge.calls()[before:]
    assert not any(c.startswith("wp_set_password") for c in new_calls)
    assert not any(c.startswith("session_tokens_destroy_all") for c in new_calls)


def test_users_reset_resets_every_user(bridge):
    before = len(bridge.calls())
    data = bridge.call("users_reset", {"apply": True}).json()
    assert data["ok"] is True
    results = data["results"]
    assert results["count"] == 3
    rows = results["users"]
    assert [row["login"] for row in rows] == ["admin", "editor", "author"]
    assert [row["email"] for row in rows] == [
        "admin@example.test", "editor@example.test", "author@legacy.test",
    ]
    assert rows[2]["roles"] == ["author", "subscriber"]
    # EVERY user got a DISTINCT password, generated by the site's own
    # generator (the stub's deterministic form) and set with core's setter.
    passwords = [row["password"] for row in rows]
    assert all(p.startswith("wpt-stub-pw-") for p in passwords)
    assert len(set(passwords)) == 3
    new_calls = bridge.calls()[before:]
    assert [c for c in new_calls if c.startswith("wp_set_password")] == [
        "wp_set_password:1", "wp_set_password:2", "wp_set_password:7",
    ]
    # Session invalidation is the point: core's wp_set_password does not do
    # it, so the op calls the per-user session manager itself.
    assert [c for c in new_calls
            if c.startswith("session_tokens_destroy_all")] == [
        "session_tokens_destroy_all:1",
        "session_tokens_destroy_all:2",
        "session_tokens_destroy_all:7",
    ]
    assert all(row["sessions_destroyed"] is True for row in rows)
    # The password RETURNED is the password that was set (compared by
    # digest, so the call log never holds a credential).
    expected_digests = [
        f"user_pass_set:{id_}:{hashlib.md5(pw.encode()).hexdigest()}"
        for id_, pw in zip(("1", "2", "7"), passwords)
    ]
    assert [c for c in new_calls if c.startswith("user_pass_set:")] == \
        expected_digests


def test_users_reset_without_the_session_manager_degrades(bridge):
    # A stripped-down install without the WP_Session_Tokens class must not
    # fatal: the passwords are still reset and sessions_destroyed says so.
    (bridge.docroot / "wpt-stub-no-sessions").write_text("")
    data = bridge.call("users_reset", {"apply": True}).json()
    assert data["ok"] is True
    assert [row["sessions_destroyed"] for row in data["results"]["users"]] == [
        False, False, False,
    ]
    assert all(row["password"] for row in data["results"]["users"])
    assert not any(c.startswith("session_tokens_destroy_all")
                   for c in bridge.calls())


def test_users_reset_reads_roles_before_the_rewrite(bridge):
    # roles come from core's get_userdata() (the capabilities meta), and a
    # user with no role row reports an empty list — never a guess. The
    # 'author' fixture carries the name => true map WP_User::set_role()
    # leaves behind, so the answer is role NAMES in both core shapes.
    data = bridge.call("users_reset", {"apply": True}).json()
    roles = {row["login"]: row["roles"] for row in data["results"]["users"]}
    assert roles == {
        "admin": ["administrator"],
        "editor": ["editor"],
        "author": ["author", "subscriber"],
    }


def test_users_reset_unreadable_users_table_refused(bridge):
    # A failed query is UNKNOWN, never "this site has no users": the op
    # must fail closed instead of reporting an empty, successful reset.
    (bridge.docroot / "wpt-stub-users-query-fails").write_text("")
    data = bridge.call("users_reset", {"apply": True}).json()
    assert data["ok"] is False
    assert "users table" in data["error"]
    assert not any(c.startswith("wp_set_password") for c in bridge.calls())


def test_users_reset_dry_run_targets_named_logins(bridge):
    # A targeted READ-ONLY call lists only the named account (matched
    # case-insensitively) and still generates nothing.
    before = len(bridge.calls())
    data = bridge.call("users_reset", {"logins": ["EDITOR"]}).json()
    assert data["ok"] is True
    results = data["results"]
    assert results["count"] == 1
    assert [row["login"] for row in results["users"]] == ["editor"]
    assert "password" not in results["users"][0]
    new_calls = bridge.calls()[before:]
    assert not any(c.startswith("wp_set_password") for c in new_calls)
    assert not any(c.startswith("session_tokens_destroy_all") for c in new_calls)


def test_users_reset_targets_named_logins(bridge):
    # The targeted APPLY resets exactly the named account: one core setter,
    # one session manager, and the canonical (stored) login in the answer.
    before = len(bridge.calls())
    data = bridge.call("users_reset",
                       {"apply": True, "logins": ["EDITOR"]}).json()
    assert data["ok"] is True
    results = data["results"]
    assert results["count"] == 1
    assert [row["login"] for row in results["users"]] == ["editor"]
    assert results["users"][0]["password"].startswith("wpt-stub-pw-")
    new_calls = bridge.calls()[before:]
    assert [c for c in new_calls if c.startswith("wp_set_password")] == [
        "wp_set_password:2",
    ]
    assert [c for c in new_calls
            if c.startswith("session_tokens_destroy_all")] == [
        "session_tokens_destroy_all:2",
    ]
    # the OTHER users were not touched
    assert not any(c.startswith("wp_set_password:1")
                   or c.startswith("wp_set_password:7") for c in new_calls)


def test_users_reset_targets_all_users_when_every_login_is_named(bridge):
    data = bridge.call("users_reset", {
        "apply": True, "logins": ["admin", "editor", "author"],
    }).json()
    assert data["ok"] is True
    assert data["results"]["count"] == 3


def test_users_reset_unknown_login_refused_whole(bridge):
    # One unknown login refuses the WHOLE op: a typo must never silently
    # reset the other named accounts while the caller believes otherwise.
    before = len(bridge.calls())
    data = bridge.call("users_reset",
                       {"apply": True, "logins": ["admin", "ghost"]}).json()
    assert data["ok"] is False
    assert "no such user: ghost" in data["error"]
    new_calls = bridge.calls()[before:]
    assert not any(c.startswith("wp_set_password") for c in new_calls)


def test_users_reset_unknown_login_refused_on_a_dry_run(bridge):
    data = bridge.call("users_reset", {"logins": ["ghost"]}).json()
    assert data["ok"] is False
    assert "no such user: ghost" in data["error"]


def test_users_reset_per_user_failure_returns_the_complete_rows(bridge):
    """C12: a Throwable after user 1 used to reach the global envelope with
    NO rows, so every password already set was lost.  The failing account is
    named, every COMPLETE row (and its live password) is returned, and users
    after the failure still get reset."""
    (bridge.docroot / "wpt-stub-password-fails").write_text("2")
    before = len(bridge.calls())
    data = bridge.call("users_reset", {"apply": True}).json()

    assert data["ok"] is False
    assert data["failed"] == ["editor"]
    assert "editor" in data["error"]
    rows = {row["login"]: row for row in data["results"]["users"]}
    assert set(rows) == {"admin", "author"}
    assert all(row["password"].startswith("wpt-stub-pw-")
               for row in rows.values())
    assert rows["admin"]["sessions_destroyed"] is True
    # The failed account's setter threw BEFORE its session token call, and
    # the run did not stop the remaining accounts.
    new_calls = bridge.calls()[before:]
    assert [c for c in new_calls if c.startswith("wp_set_password")] == [
        "wp_set_password:1", "wp_set_password:2", "wp_set_password:7",
    ]
    assert "session_tokens_destroy_all:2" not in new_calls
    assert "session_tokens_destroy_all:7" in new_calls


def test_R16_users_reset_scrubs_every_encoded_password_form(
        bridge, caplog, tmp_path):
    """R16-P1: a throwing hook receives the plaintext password and can embed
    it in its own message.  Every failure path scrubs raw/HTML/URL/JSON forms
    before the envelope, log or report can carry a live credential."""
    import logging

    (bridge.docroot / "wpt-stub-password-special").write_text("")
    (bridge.docroot / "wpt-stub-password-echoes-encoded").write_text("")
    with caplog.at_level(logging.DEBUG, logger="wpt.wpbridge.client"):
        data = bridge.call("users_reset", {
            "apply": True, "logins": ["admin"],
        }).json()
    assert data["ok"] is False
    assert data["failed"] == ["admin"]
    # The per-login scrubbed reason is EMITTED (it used to be a dead
    # assignment while the test's forms could never appear in the answer).
    assert set(data["failed_reasons"]) == {"admin"}
    assert "password" in data["failed_reasons"]["admin"]
    password = "Abc&Def!9"
    envelope = json.dumps(data)
    forms = (
        password,
        "Abc&amp;Def!9",
        "Abc&#038;Def!9",
        "Abc&#38;Def!9",
        "Abc%26Def%219",
        json.dumps(password)[1:-1],
        json.dumps(password),
    )
    for form in forms:
        assert form not in envelope, (form, envelope)
        assert form not in caplog.text, (form, caplog.text)

    from wpt.actions.registry import write_failure_report
    from wpt.cli import Ctx
    from wpt.settings import load

    report = tmp_path / "users-reset.md"
    ctx = Ctx(source="ftp://h", settings=load(), command="users_reset",
              report_path=report)
    assert write_failure_report(
        ctx, "users_reset", f"users_reset failed: {data['error']}",
        title="wpt users_reset") == 0
    for face in (report.read_text(encoding="utf-8"),
                 report.with_suffix(".json").read_text(encoding="utf-8")):
        for form in forms:
            assert form not in face, (form, face)


def test_users_reset_a_throwing_role_read_keeps_completed_credentials(
        bridge):
    """R11-P1-2: get_userdata() ran OUTSIDE the per-user try.  A throw on
    user 2 after user 1 was reset reached the global envelope with no rows,
    losing user 1's live password.  The whole body is contained now."""
    (bridge.docroot / "wpt-stub-userdata-throws").write_text("2")
    before = len(bridge.calls())
    data = bridge.call("users_reset", {"apply": True}).json()

    assert data["ok"] is False
    assert data["failed"] == ["editor"]
    # The global envelope names only the failed logins; the per-user reason
    # is contained but the completed rows are the contract that matters.
    assert "users_reset failed for editor" in data["error"]
    rows = {row["login"]: row for row in data["results"]["users"]}
    assert set(rows) == {"admin", "author"}
    assert rows["admin"]["password"].startswith("wpt-stub-pw-")
    new_calls = bridge.calls()[before:]
    assert [c for c in new_calls if c.startswith("wp_set_password")] == [
        "wp_set_password:1", "wp_set_password:7",
    ]


def test_users_reset_a_throwing_session_manager_returns_the_partial_row(
        bridge):
    """R11-P1-2: session-token acquisition is after the password write; a
    throw there must return THAT user's live credential with ok:false, not
    lose it to the global envelope."""
    (bridge.docroot / "wpt-stub-session-instance-throws").write_text("1")
    data = bridge.call("users_reset", {"apply": True}).json()

    assert data["ok"] is False
    assert data["failed"] == ["admin"]
    rows = {row["login"]: row for row in data["results"]["users"]}
    assert set(rows) == {"admin", "editor", "author"}
    assert rows["admin"]["password"].startswith("wpt-stub-pw-")
    assert rows["admin"]["sessions_destroyed"] is False
    assert rows["editor"]["sessions_destroyed"] is True


def test_users_reset_a_throwing_generator_is_contained(bridge):
    """R11-P1-2: the generator runs inside the per-user try; its failure
    skips only that account and still returns the completed rows."""
    (bridge.docroot / "wpt-stub-password-generate-fails").write_text("2")
    data = bridge.call("users_reset", {"apply": True}).json()

    assert data["ok"] is False
    assert data["failed"] == ["editor"]
    rows = {row["login"]: row for row in data["results"]["users"]}
    assert set(rows) == {"admin", "author"}
    assert all(row["password"].startswith("wpt-stub-pw-")
               for row in rows.values())


@pytest.mark.parametrize("logins", [[], "admin", [""], ["  "], [7]])
def test_users_reset_bad_logins_param_refused(bridge, logins):
    # An empty list must never be read as "everyone" (the dangerous
    # default), and a malformed entry is a request error, not a filter.
    before = len(bridge.calls())
    data = bridge.call("users_reset",
                       {"apply": True, "logins": logins}).json()
    assert data["ok"] is False
    assert "logins" in data["error"]
    new_calls = bridge.calls()[before:]
    assert not any(c.startswith("wp_set_password") for c in new_calls)


# ---------------------------------------------------------------------------
# user_create
# ---------------------------------------------------------------------------


def test_user_create_dry_run_validates_without_writing(bridge):
    # READ-ONLY: the account that WOULD be created is answered (with the
    # SANITIZED login), and neither a password nor a row exists.
    before = len(bridge.calls())
    data = bridge.call("user_create", {
        "login": "<b>New</b> Admin", "email": "new@example.test",
        "role": "administrator",
    }).json()
    assert data["ok"] is True
    assert data["results"]["apply"] is False
    assert data["results"]["user"] == {
        "login": "New Admin", "email": "new@example.test",
        "roles": ["administrator"],
    }
    new_calls = bridge.calls()[before:]
    assert not any(c.startswith("wp_insert_user") for c in new_calls)
    assert not any(c.startswith("user_pass_set:") for c in new_calls)


def test_user_create_readback_failure_returns_the_live_credential(bridge):
    """C12: wp_insert_user succeeded, so the account and password ARE live;
    a throwing/failing read-back must answer ok:false WITH the credential,
    never let the global Throwable envelope lose it."""
    (bridge.docroot / "wpt-stub-user-readback-fails").write_text("")
    data = bridge.call("user_create", {
        "apply": True, "login": "newadmin", "email": "new@example.test",
        "role": "administrator",
    }).json()

    assert data["ok"] is False
    assert data["created"] is True
    assert "could not be read back" in data["error"]
    user = data["results"]["user"]
    assert user["login"] == "newadmin"
    assert user["password"].startswith("wpt-stub-pw-")
    assert user["roles"] == []
    assert any(c.startswith("wp_insert_user:")
               for c in bridge.calls())


def test_user_create_hook_failure_after_insert_returns_the_live_credential(
        bridge):
    """C12: a user_register hook throwing after core wrote the row must not
    reach the global envelope, which cannot carry the generated password.
    The op recovers the account by (sanitized login, email) and returns it
    with ok:false."""
    (bridge.docroot / "wpt-stub-insert-throws-after").write_text("")
    data = bridge.call("user_create", {
        "apply": True, "login": "newadmin", "email": "new@example.test",
        "role": "administrator",
    }).json()

    assert data["ok"] is False
    assert data["created"] is True
    assert "after writing the account" in data["error"]
    user = data["results"]["user"]
    assert user["login"] == "newadmin"
    assert user["email"] == "new@example.test"
    assert user["roles"] == ["administrator"]
    assert user["password"].startswith("wpt-stub-pw-")


def test_R20_user_create_never_reports_a_concurrent_row_with_a_dead_password(
        bridge):
    """R20-P2: the login/email fallback ran even when add_action existed, so
    a concurrent duplicate that made the insert throw (before user_register)
    was returned as ``created:true`` with a generated password that was
    never set.  The fallback is double-gated now: only without add_action,
    and only when the generated password is proven live on the row."""
    (bridge.docroot / "wpt-stub-insert-concurrent").write_text("")
    data = bridge.call("user_create", {
        "apply": True, "login": "newadmin", "email": "new@example.test",
        "role": "administrator",
    }).json()

    assert data["ok"] is False
    assert data.get("created") is not True
    # The generated password is not proven live, so no credential may be
    # published; the scrubber therefore withholds the hook's diagnostic.
    assert "wpt-stub-pw-" not in json.dumps(data)
    assert "password" not in (data.get("results") or {}).get("user", {})


def test_R19_user_create_recovers_by_user_register_id_through_filters(
        bridge):
    """R19-P2: core applies pre_user_login/pre_user_email before the
    insert.  A plugin that rewrote either field made the old recovery
    (search by the REQUEST's sanitized login + email) find nothing after
    a throwing user_register hook, losing a live password.  The earliest
    user_register callback captures the id before later hooks run."""
    (bridge.docroot / "wpt-stub-insert-throws-after").write_text("")
    (bridge.docroot / "wpt-stub-user-filters").write_text("")
    data = bridge.call("user_create", {
        "apply": True, "login": "newadmin", "email": "new@example.test",
        "role": "administrator",
    }).json()

    assert data["ok"] is False
    assert data["created"] is True
    user = data["results"]["user"]
    # The written row carries the FILTERED fields; the credential is live
    # and must be returned with it.
    assert user["login"] == "filtered-newadmin"
    assert user["email"] == "filtered-new@example.test"
    assert user["password"].startswith("wpt-stub-pw-")


def test_user_create_a_throwing_recovery_read_still_returns_the_credential(
        bridge):
    """R11-P1-2: after wp_insert_user wrote the row and threw, the recovery
    get_userdata() could throw too.  The account/password are live, so the
    op answers ok:false WITH the credential instead of the global envelope."""
    (bridge.docroot / "wpt-stub-insert-throws-after").write_text("")
    (bridge.docroot / "wpt-stub-userdata-throws").write_text("8")
    data = bridge.call("user_create", {
        "apply": True, "login": "newadmin", "email": "new@example.test",
        "role": "administrator",
    }).json()

    assert data["ok"] is False
    assert data["created"] is True
    assert "recovery read failed" in data["error"]
    user = data["results"]["user"]
    assert user["login"] == "newadmin"
    assert user["email"] == "new@example.test"
    assert user["roles"] == ["administrator"]
    assert user["password"].startswith("wpt-stub-pw-")


def test_R12_user_create_scrubs_the_plaintext_from_error_log_and_report(
        bridge, caplog, tmp_path):
    """R12-P1-4: a user_register hook can throw the plaintext password into
    its message after the row is written.  The bridge knows the secret and
    must scrub it from the envelope; the client log and the failure report
    (markdown + JSON) then cannot carry it."""
    (bridge.docroot / "wpt-stub-insert-throws-password").write_text("")
    with caplog.at_level(logging.DEBUG, logger="wpt.wpbridge.client"):
        data = bridge.call("user_create", {
            "apply": True, "login": "newadmin", "email": "new@example.test",
            "role": "administrator",
        }).json()

    assert data["ok"] is False
    password = data["results"]["user"]["password"]
    assert password.startswith("wpt-stub-pw-")
    # The live credential IS the payload's results (deliberate); the ERROR
    # channel, the log and both report faces must never carry it.
    assert password not in json.dumps(data["error"])
    assert password not in caplog.text
    assert "[redacted]" in data["error"]

    from wpt.actions.registry import write_failure_report
    from wpt.cli import Ctx
    from wpt.settings import load

    report = tmp_path / "user-create.md"
    ctx = Ctx(source="ftp://h", settings=load(), command="user-create",
              report_path=report)
    assert write_failure_report(
        ctx, "user-create", f"user-create failed: {data['error']}",
        title="wpt user-create") == 0
    assert password not in report.read_text(encoding="utf-8")
    assert password not in report.with_suffix(".json").read_text(
        encoding="utf-8")


def test_R15_user_create_scrubs_every_encoded_password_form(bridge):
    """R15-P1-4: a hook that throws ``htmlspecialchars``/``htmlentities``/
    ``urlencode``/``rawurlencode``/``json_encode`` of the just-generated
    password left a reversible live credential in the envelope.  Every form
    is scrubbed (or the diagnostic is withheld) before the client sees it."""
    (bridge.docroot / "wpt-stub-insert-throws-encoded-password").write_text("")
    (bridge.docroot / "wpt-stub-password-special").write_text("")
    data = bridge.call("user_create", {
        "apply": True, "login": "newadmin", "email": "new@example.test",
        "role": "administrator",
    }).json()

    assert data["ok"] is False
    password = data["results"]["user"]["password"]
    assert password == "Abc&Def!9"
    error = data["error"]
    forms = (
        password,
        "Abc&amp;Def!9",
        "Abc%26Def%219",
        json.dumps(password)[1:-1],
        json.dumps(password),
    )
    for form in forms:
        assert form not in error, (form, error)
    assert "Def!9" not in error and "Def%219" not in error


def test_R18_user_create_scrubs_esc_url_numeric_entity_password(bridge,
                                                               caplog):
    """R18-P1: ``esc_url($pass)`` renders ``&`` as ``&#038;`` — reversible,
    and invisible to the html/url/json variants.  The error, the warning log
    and BOTH report faces must carry no encoded live credential."""
    import logging

    from wpt.types import BridgeError

    (bridge.docroot / "wpt-stub-insert-throws-esc-url-password").write_text("")
    (bridge.docroot / "wpt-stub-password-special").write_text("")
    with caplog.at_level(logging.DEBUG, logger="wpt.wpbridge.client"):
        with live_client(bridge) as client:
            with pytest.raises(BridgeError) as excinfo:
                client.call("user_create", apply=True, login="newadmin",
                            email="new@example.test", role="administrator")
    error = str(excinfo.value)
    payload = excinfo.value.payload
    password = payload["results"]["user"]["password"]
    assert password == "Abc&Def!9"
    forms = (
        password,
        "Abc&#038;Def!9",
        "Abc&#38;Def!9",
        "Abc&#x26;Def!9",
        "Abc&amp;Def!9",
        "Abc%26Def%219",
        json.dumps(password)[1:-1],
    )
    for form in forms:
        assert form not in error, (form, error)
        assert form not in caplog.text, (form, caplog.text)
    # The RAW password is the one credential the failure envelope MUST carry
    # (the account is live); no ENCODED form may appear anywhere in it.
    payload_text = json.dumps(payload)
    for form in forms[1:-1]:
        assert form not in payload_text, (form, payload)

    from wpt.actions.registry import write_failure_report
    from wpt.cli import Ctx
    from wpt.settings import load

    report = Path(str(bridge.docroot.parent / "esc-url-report.md"))
    ctx = Ctx(source="ftp://h", settings=load(), command="user_create",
              report_path=report)
    assert write_failure_report(
        ctx, "user_create", f"user_create failed: {error}",
        title="wpt user_create") == 0
    for face in (report.read_text(encoding="utf-8"),
                 report.with_suffix(".json").read_text(encoding="utf-8")):
        for form in forms:
            assert form not in face, (form, face)


def test_R12_users_reset_keeps_a_password_written_before_a_hook_throw(
        bridge):
    """R12-P1-5: core's wp_set_password writes the hash and THEN fires its
    action, so a throwing hook reaches the catch with the new password
    already live.  The contained hash re-read must publish that row (and
    say a later step failed) instead of withholding the only live
    credential."""
    (bridge.docroot / "wpt-stub-password-fails-after-write").write_text("1")
    before = len(bridge.calls())
    data = bridge.call("users_reset", {
        "apply": True, "logins": ["admin"],
    }).json()

    assert data["ok"] is False
    assert data["failed"] == ["admin"]
    rows = {row["login"]: row for row in data["results"]["users"]}
    assert set(rows) == {"admin"}
    password = rows["admin"]["password"]
    assert password.startswith("wpt-stub-pw-")
    assert rows["admin"]["sessions_destroyed"] is False
    new_calls = bridge.calls()[before:]
    # The hash really landed before the throw.
    assert f"user_pass_set:1:{hashlib.md5(password.encode()).hexdigest()}" \
        in new_calls


def test_R13_users_reset_silent_setter_noop_is_not_published(bridge):
    """R13-P1-4: core's ``wp_set_password`` ignores the database update's
    return, so a no-op setter returns normally.  The op used to mark the
    password live immediately; it must prove the stored hash with
    ``wp_check_password`` before publishing anything.  A silent no-op is
    ``ok:false``, no password row, and the old hash stays intact."""
    (bridge.docroot / "wpt-stub-password-silent-noop").write_text("1")
    before = len(bridge.calls())
    data = bridge.call("users_reset", {
        "apply": True, "logins": ["admin"],
    }).json()

    assert data["ok"] is False
    assert data["failed"] == ["admin"]
    assert data["results"] == {"users": [], "count": 0}
    assert "password" not in json.dumps(data["results"])
    new_calls = bridge.calls()[before:]
    assert "wp_set_password:1" in new_calls
    # The write never landed ...
    assert not any(call.startswith("user_pass_set:1:")
                   for call in new_calls)
    # ... and the verifier saw the OLD hash (a miss), not the generated one.
    assert "user_pass_check:1:miss" in new_calls


def test_user_create_apply_creates_and_reads_back(bridge):
    before = len(bridge.calls())
    data = bridge.call("user_create", {
        "apply": True, "login": "newadmin", "email": "new@example.test",
        "role": "administrator",
    }).json()
    assert data["ok"] is True
    user = data["results"]["user"]
    assert data["results"]["apply"] is True
    assert user["login"] == "newadmin"
    assert user["email"] == "new@example.test"
    # roles come from the get_userdata() READ-BACK (the name => true map
    # WP_User::set_role leaves), not from the request.
    assert user["roles"] == ["administrator"]
    password = user["password"]
    assert password.startswith("wpt-stub-pw-")
    # The password returned is the one wp_insert_user received (compared
    # by digest, so the call log never holds a credential).
    new_calls = bridge.calls()[before:]
    assert [c for c in new_calls if c.startswith("wp_insert_user")] == [
        "wp_insert_user:8:newadmin",
    ]
    assert [c for c in new_calls if c.startswith("user_pass_set:")] == [
        f"user_pass_set:8:{hashlib.md5(password.encode()).hexdigest()}",
    ]


def test_user_create_sanitizes_the_login_before_everything(bridge):
    # The login is validated AFTER sanitize_user(strict) — the mode
    # wp_insert_user uses — so a tag-wrapped login is accepted under the
    # login WordPress will actually create, and the apply creates THAT.
    data = bridge.call("user_create", {
        "apply": True, "login": "<i>bob</i>", "email": "bob@example.test",
        "role": "editor",
    }).json()
    assert data["ok"] is True
    assert data["results"]["user"]["login"] == "bob"
    assert any(c == "wp_insert_user:8:bob" for c in bridge.calls())


def test_user_create_duplicate_login_refused(bridge):
    before = len(bridge.calls())
    data = bridge.call("user_create", {
        "apply": True, "login": "admin", "email": "fresh@example.test",
        "role": "administrator",
    }).json()
    assert data["ok"] is False
    assert "already exists: admin" in data["error"]
    assert not any(c.startswith("wp_insert_user") for c in bridge.calls()[before:])


def test_user_create_duplicate_email_refused(bridge):
    before = len(bridge.calls())
    data = bridge.call("user_create", {
        "apply": True, "login": "fresh", "email": "editor@example.test",
        "role": "administrator",
    }).json()
    assert data["ok"] is False
    assert "already exists: editor@example.test" in data["error"]
    assert not any(c.startswith("wp_insert_user") for c in bridge.calls()[before:])


@pytest.mark.parametrize("params,error", [
    ({"login": "new", "email": "not-an-email", "role": "administrator"},
     "not a valid email"),
    ({"login": "new", "email": "new@example.test", "role": "superuser"},
     "unknown role: superuser"),
    ({"login": "<b></b>", "email": "new@example.test", "role": "administrator"},
     "empty after WordPress sanitization"),
    ({"email": "new@example.test", "role": "administrator"},
     "param: login"),
    ({"login": "new", "role": "administrator"},
     "param: email"),
    ({"login": "new", "email": "new@example.test"},
     "param: role"),
])
def test_user_create_bad_request_refused(bridge, params, error):
    data = bridge.call("user_create", {"apply": True, **params}).json()
    assert data["ok"] is False
    assert error in data["error"]
    assert not any(c.startswith("wp_insert_user") for c in bridge.calls())


def test_user_create_login_longer_than_60_chars_refused(bridge):
    # Core's own bound (wp_insert_user: user_login_too_long). A read-only
    # plan must refuse it, never pass and then fail at insert after the
    # password was generated.
    before = len(bridge.calls())
    data = bridge.call("user_create", {
        "apply": True, "login": "a" * 61, "email": "new@example.test",
        "role": "administrator",
    }).json()
    assert data["ok"] is False
    assert "longer than 60 characters" in data["error"]
    assert not any(c.startswith("wp_insert_user") for c in bridge.calls()[before:])


@pytest.mark.parametrize("apply", [False, True])
def test_user_create_blocked_login_refused(bridge, apply):
    # The site's illegal_user_logins filter (a security plugin), mirrored
    # from core: refused read-only AND on apply, before the insert.
    (bridge.docroot / "wpt-stub-illegal-logins").write_text("")
    before = len(bridge.calls())
    data = bridge.call("user_create", {
        "apply": apply, "login": "forbidden", "email": "new@example.test",
        "role": "administrator",
    }).json()
    assert data["ok"] is False
    assert "not allowed on this site: forbidden" in data["error"]
    assert not any(c.startswith("wp_insert_user") for c in bridge.calls()[before:])


def test_user_create_insert_failure_surfaces(bridge):
    # wp_insert_user can still refuse at insert time (the plan/apply race,
    # a filter) — core's WP_Error message must reach the caller as the
    # operation's error, never a half-understood success.
    (bridge.docroot / "wpt-stub-insert-fails").write_text("")
    data = bridge.call("user_create", {
        "apply": True, "login": "newadmin", "email": "new@example.test",
        "role": "administrator",
    }).json()
    assert data["ok"] is False
    assert "wp_insert_user failed" in data["error"]


def test_purge_cache(bridge):
    before = len(bridge.calls())
    data = bridge.call("purge_cache").json()
    assert data == {"ok": True, "purged": True}
    new_calls = bridge.calls()[before:]
    # Every supported cache stack is purged, not just LiteSpeed: the
    # function_exists-guarded W3TC / WP Super Cache flush entry points fire
    # when those plugins are active, matching the documented post-apply purge.
    assert "do_action:litespeed_purge_all" in new_calls
    assert "w3tc_flush_all" in new_calls
    assert "wp_cache_clear_cache" in new_calls


def test_purge_cache_stock_wordpress_without_cache_plugins(bridge):
    # On a site with NO caching plugin active, neither flush function exists.
    # The function_exists guards must skip them and the purge must still
    # succeed on stock WordPress (core defines wp_cache_flush(), a different
    # name, so an unguarded call would fatal).
    before = len(bridge.calls())
    (bridge.docroot / "wpt-stub-no-cache-fns").write_text("")
    data = bridge.call("purge_cache").json()
    assert data == {"ok": True, "purged": True}
    new_calls = bridge.calls()[before:]
    assert "do_action:litespeed_purge_all" in new_calls
    assert "w3tc_flush_all" not in new_calls
    assert "wp_cache_clear_cache" not in new_calls


def test_fileperms(bridge):
    target = bridge.docroot / "wp-config.php"
    expected = format(os.stat(target).st_mode, "o")[-4:]
    data = bridge.call("fileperms", {"paths": [
        "wp-config.php",
        "wp-content/uploads/2023/10/pic.jpg",
        "missing.php",
    ]}).json()
    assert data["ok"] is True
    assert data["paths"]["wp-config.php"] == expected
    assert data["paths"]["wp-content/uploads/2023/10/pic.jpg"] is not None
    assert data["paths"]["missing.php"] is None
    assert data["context"]["abspath"] is not None
    assert data["context"]["uploads_basedir"] is not None


# ---------------------------------------------------------------------------
# core_md5 (bulk server-side digests)
# ---------------------------------------------------------------------------

def test_core_md5(bridge):
    paths = [
        "wp-config.php",              # good (harness fixture)
        "wp-includes/version.php",    # good (core_md5 fixture)
        "xmlrpc.php",                 # good (core_md5 fixture)
        "wp-includes",                # directory -> never hashed -> missing
        "wp-admin/setup-config.php",  # nothing there -> missing
    ]
    data = bridge.call("core_md5", {"paths": paths}).json()
    assert data["ok"] is True
    assert data["missing"] == ["wp-includes", "wp-admin/setup-config.php"]
    assert data["unreadable"] == []
    files = data["files"]
    assert (set(files) | set(data["missing"])) == set(paths)  # every path lands somewhere
    for rel in ("wp-config.php", "wp-includes/version.php", "xmlrpc.php"):
        assert files[rel] == hashlib.md5((bridge.docroot / rel).read_bytes()).hexdigest()


def test_core_md5_all_missing_keeps_files_an_object(bridge):
    data = bridge.call("core_md5", {"paths": ["gone.php", "gone.php"]}).json()
    assert data["ok"] is True
    assert data["files"] == {}  # wpt_map: always a JSON object, never []
    assert data["missing"] == ["gone.php"]  # repeated request paths deduplicated
    assert data["unreadable"] == []


def test_core_md5_traversal_refused(bridge):
    # "../x" that does not even exist: the LEXICAL ".." guard must refuse it
    # before realpath (realpath false alone would classify it as missing).
    r = bridge.call("core_md5", {"paths": ["wp-config.php", "../no-such-file"]})
    data = r.json()
    assert r.status_code == 200
    assert data["ok"] is False
    assert "refused" in data["error"]


def test_core_md5_symlink_outside_webroot_refused(bridge):
    # Lexically clean path whose realpath escapes ABSPATH — the containment
    # layer (not the ".." check) must refuse it.
    r = bridge.call("core_md5", {"paths": ["wp-includes/link-out.php"]})
    data = r.json()
    assert r.status_code == 200
    assert data["ok"] is False
    assert "refused" in data["error"]


def test_core_md5_refuses_over_5000_paths(bridge):
    data = bridge.call("core_md5", {"paths": ["wp-config.php"] * 5001}).json()
    assert data["ok"] is False
    assert "too many paths" in data["error"]


def test_core_md5_accepts_5000_paths(bridge):
    paths = [f"gone-{i}.php" for i in range(5000)]  # exactly at the cap
    data = bridge.call("core_md5", {"paths": paths}).json()
    assert data["ok"] is True
    assert data["files"] == {}
    assert len(data["missing"]) == 5000


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads mode-000 files")
def test_core_md5_unreadable_file(bridge):
    (bridge.docroot / "xmlrpc.php").chmod(0o000)
    data = bridge.call("core_md5", {"paths": ["xmlrpc.php"]}).json()
    assert data["ok"] is True
    assert data["files"] == {"xmlrpc.php": None}  # exists, but null digest
    assert data["unreadable"] == ["xmlrpc.php"]
    assert data["missing"] == []


def test_db_audit_autoload_set_mirrors_python_constant():
    # Cross-language mirror: the bridge's autoload SQL must count exactly the
    # AUTOLOAD_ON values from wpt.localmode.analyzer (WP 6.6 added 'on'/
    # 'auto-on'/'auto' alongside legacy 'yes').  Contract test against drift.
    from wpt.localmode.analyzer import AUTOLOAD_ON

    php = (Path(__file__).resolve().parent.parent
           / "wpt" / "wpbridge" / "bridge.php").read_text(encoding="utf-8")
    sql = next(line for line in php.splitlines() if "autoload_bytes" in line)
    for value in AUTOLOAD_ON:
        assert f"'{value}'" in sql, f"bridge autoload SQL missing '{value}'"
    for not_on in ("no", "off", "auto-off"):
        assert f"'{not_on}'" not in sql


# ---------------------------------------------------------------------------
# core_upgrade (WordPress's own database migration)
# ---------------------------------------------------------------------------

def test_core_upgrade_runs_the_migration_and_reports_the_readback(bridge):
    """The op is core's own wp_upgrade(): the schema version it reports is
    the value READ BACK from the database after the migration, and the
    target it migrated to is the $wp_db_version of the core this request
    loaded (the release the operator just swapped in)."""
    before = bridge.calls()
    data = bridge.call("core_upgrade", {"apply": True}).json()
    assert data["ok"] is True
    assert data["db_version"] == "60356"        # the stub's migration target
    assert data["target_db_version"] == "60356"
    assert data["wp_version"] == "6.4.2"        # get_bloginfo('version')
    assert data["output"] == "" and data["output_truncated"] is False
    # core's routine really ran (not a hand-written UPDATE of our own)
    assert "wp_upgrade" in bridge.calls()[len(before):]
    # and the value is the STORED one: a second, read-only info call
    # reports the same db_version
    assert bridge.call("info").json()["db_version"] == "60356"


def test_core_upgrade_requires_apply(bridge):
    """A migration is irreversible on its own, so the op refuses without
    the explicit flag — the gate every mutating op in this bridge has."""
    before = len(bridge.calls())
    data = bridge.call("core_upgrade", {}).json()
    assert data["ok"] is False
    assert "apply=true" in data["error"]
    # nothing ran
    assert "wp_upgrade" not in bridge.calls()[before:]


def test_core_upgrade_refuses_multisite(bridge):
    """wp_upgrade() takes the network path on multisite (upgrade_network()
    plus a per-site db_version in site meta); the op refuses there even if
    a future caller forgets to check."""
    (bridge.docroot / "wpt-stub-multisite").write_text("")
    before = len(bridge.calls())
    data = bridge.call("core_upgrade", {"apply": True}).json()
    assert data["ok"] is False
    assert "multisite" in data["error"]
    assert "wp_upgrade" not in bridge.calls()[before:]


def test_core_upgrade_keeps_the_migration_output_and_tells_the_caller(
        bridge):
    """A migration that PRINTS must not corrupt the JSON envelope — and
    its output must be KEPT, not discarded.

    It used to be ``ob_get_clean()``-ed into the void with a bare
    ``output_discarded`` boolean: the one piece of evidence of WHY a
    migration did not do what it was asked to (a notice from core, a
    warning from a hook) was thrown away, and the caller was told only
    that "something printed".  The op now returns it, bounded and
    UTF-8-clean, and the client logs it.
    """
    (bridge.docroot / "wpt-stub-upgrade-noise").write_text("")
    r = bridge.call("core_upgrade", {"apply": True})
    data = r.json()                      # a printed notice would raise here
    assert data["ok"] is True
    assert data["db_version"] == "60356"
    assert "a notice the migration printed" in data["output"]
    assert data["output_truncated"] is False
    # the envelope is still ONE json object, and the notice is inside it
    # rather than in front of it
    assert json.loads(r.text)["ok"] is True
    assert not r.text.lstrip().startswith("stub:")


def test_core_upgrade_bounds_and_cleans_its_output(bridge):
    """Output the op cannot put in a JSON envelope is bounded and cleaned,
    never passed through to raise.

    The success envelope is encoded with JSON_THROW_ON_ERROR, so a single
    invalid byte from a host whose notices are not UTF-8 would throw
    INSIDE the op and turn a successful migration into an error answer.
    """
    (bridge.docroot / "wpt-stub-upgrade-noise").write_text("")
    data = bridge.call("core_upgrade", {"apply": True}).json()
    # a 5 KiB notice is bounded, and the caller is told it was cut
    (bridge.docroot / "wpt-stub-upgrade-big-noise").write_text("")
    data = bridge.call("core_upgrade", {"apply": True}).json()
    assert data["ok"] is True
    assert len(data["output"]) <= 2000
    assert data["output_truncated"] is True
    (bridge.docroot / "wpt-stub-upgrade-big-noise").unlink()
    # and a non-UTF-8 notice is dropped rather than fatal
    (bridge.docroot / "wpt-stub-upgrade-binary").write_bytes(b"\xff\xfe\x00bad")
    data = bridge.call("core_upgrade", {"apply": True}).json()
    assert data["ok"] is True
    assert isinstance(data["output"], str)


def test_core_upgrade_writes_a_pre_migration_marker(bridge):
    """The op records what it is ABOUT to do, before it does it.

    That marker is the only account of the pre-migration state when the
    migration FATALS — a non-catchable PHP fatal destroys the response
    entirely, so the caller is left holding a half-moved database and no
    envelope.  It is autoload=off: a read-once diagnostic row must never
    be loaded on every page view.
    """
    data = bridge.call("core_upgrade", {"apply": True}).json()
    assert data["ok"] is True
    info = bridge.call("info").json()
    marker = info["upgrade_marker"]
    assert marker["from_db_version"] == "56657"     # where it began
    assert marker["target_db_version"] == "60356"   # where it was headed
    assert marker["wp_version"] == "6.4.2"
    assert marker["started"] > 0
    # and it is stamped finished on the way out
    assert marker["finished"] and marker["finished"] >= marker["started"]
    assert "update_option:wpt_core_upgrade" in bridge.calls()
    # the marker row is written autoload=off: a read-once diagnostic row
    # must never be loaded on every page view.  (The harness records the
    # argument count of every non-2-arg update_option call.)
    assert "update_option:argcount=3" in bridge.calls()


def test_info_reports_no_marker_on_a_site_that_never_migrated(bridge):
    """``upgrade_marker`` is null until a migration has run — an absent
    diagnostic is not a fabricated one."""
    assert bridge.call("info").json()["upgrade_marker"] is None


def test_a_fatal_inside_the_migration_leaves_the_marker_readable(tmp_path):
    """THE FAILURE THE MARKER EXISTS FOR, under a real memory limit.

    ``wp_upgrade()`` exhausts the interpreter: no Throwable, no envelope,
    no answer — the client sees non-JSON.  The database is left exactly
    where the fatal stopped, and the only thing that can say so is the
    marker the op wrote first, read back over a SECOND request.  Without
    it the operator has a half-migrated database and the words "bridge
    returned non-JSON".
    """
    env = _build(tmp_path, ini=["-d", "memory_limit=16M"])
    try:
        (env.docroot / "wpt-stub-upgrade-fat").write_text("")
        before = env.call("info").json()
        assert before["db_version"] == "56657"
        assert before["upgrade_marker"] is None
        client = live_client(env)
        with pytest.raises(BridgeError) as excinfo:
            client.upgrade_core()
        # the envelope is gone — and the client says so rather than
        # guessing at a schema version
        assert "non-JSON" in str(excinfo.value)
        # the database never moved
        assert env.call("info").json()["db_version"] == "56657"
        # and the state the migration BEGAN in is still readable
        marker = client.upgrade_marker()
        assert marker["from_db_version"] == 56657
        assert marker["target_db_version"] == 60356
        assert marker["finished"] is None      # it never finished
    finally:
        env.close()


def test_R19_esc_html_and_esc_js_quote_forms_never_reach_the_envelope(
        bridge, caplog):
    """R19-P1: ``esc_html`` (ENT_NOQUOTES) and ``esc_js`` (ENT_COMPAT)
    produce quote-policy variants no ENT_QUOTES form covers.  The owner now
    fails CLOSED: whenever a generated password exists, hook-derived text
    is replaced by one fixed diagnostic, so no raw/encoded spelling can
    reach the envelope, log or either report face."""
    import logging

    from wpt.types import BridgeError

    (bridge.docroot / "wpt-stub-insert-throws-noquotes-password").write_text("")
    (bridge.docroot / "wpt-stub-password-quotes").write_text("")
    with caplog.at_level(logging.DEBUG, logger="wpt.wpbridge.client"):
        with live_client(bridge) as client:
            with pytest.raises(BridgeError) as excinfo:
                client.call("user_create", apply=True, login="newadmin",
                            email="new@example.test", role="administrator")
    error = str(excinfo.value)
    payload = excinfo.value.payload
    password = payload["results"]["user"]["password"]
    assert password == "Abc'Def<9"
    forms = (
        password,
        "Abc'Def&lt;9",
        "Abc&#039;Def&lt;9",
        "Abc&#39;Def&lt;9",
        "Abc&#x27;Def&lt;9",
        "Abc%27Def%3C9",
    )
    for form in forms:
        assert form not in error, (form, error)
        assert form not in caplog.text, (form, caplog.text)
    # The RAW password is the one credential the failure envelope MUST carry
    # (the account is live); no ENCODED form may appear anywhere in it.
    for form in forms[1:]:
        assert form not in json.dumps(payload), (form, payload)
    assert "[redacted" in error


def test_R19_escaped_and_whitespace_password_spellings_are_withheld(
        bridge, caplog):
    """R19-P1: ``addslashes``, a literal ``\\x27`` escape and a
    backslash-space form are reversible spellings no exhaustive variant
    list covers.  The fail-closed diagnostic carries none of them."""
    import logging

    from wpt.types import BridgeError

    (bridge.docroot / "wpt-stub-insert-throws-escaped-password").write_text("")
    (bridge.docroot / "wpt-stub-password-quotes").write_text("")
    with caplog.at_level(logging.DEBUG, logger="wpt.wpbridge.client"):
        with live_client(bridge) as client:
            with pytest.raises(BridgeError) as excinfo:
                client.call("user_create", apply=True, login="newadmin",
                            email="new@example.test", role="administrator")
    error = str(excinfo.value)
    payload = excinfo.value.payload
    password = payload["results"]["user"]["password"]
    assert password == "Abc'Def<9"
    forms = (
        password,
        "Abc\\'Def<9",
        "Abc\\x27Def<9",
        "Abc\\x27Def\\x3C9",
        "Abc'Def&lt;9",
    )
    for form in forms:
        assert form not in error, (form, error)
        assert form not in caplog.text, (form, caplog.text)
    for form in forms[1:]:
        assert form not in json.dumps(payload), (form, payload)
    assert "[redacted]" in error


def test_the_client_logs_the_migration_output_redacted(tmp_path, caplog):
    """The output reaches the operator's log, through the client's own
    logger, with the shared free-text redaction applied on the way in."""
    env = _build(tmp_path)
    try:
        (env.docroot / "wpt-stub-upgrade-noise").write_text("")
        parent = logging.getLogger("wpt")
        parent.addHandler(caplog.handler)
        try:
            with caplog.at_level(logging.WARNING, logger="wpt.wpbridge"):
                client = live_client(env)
                result = client.upgrade_core()
        finally:
            parent.removeHandler(caplog.handler)
        assert "a notice the migration printed" in result["output"]
        assert "a notice the migration printed" in caplog.text
        assert "was discarded" not in caplog.text
    finally:
        env.close()


def test_info_reports_the_schema_version_and_multisite(bridge):
    """The two facts update-core needs from info: the WordPress SCHEMA
    version (the stored db_version option — NOT the engine version) and
    whether this is a network install."""
    data = bridge.call("info").json()
    assert data["db_version"] == "56657"
    assert data["mysql_version"] == "8.0.36"   # the engine, unchanged
    assert data["multisite"] is False
    (bridge.docroot / "wpt-stub-multisite").write_text("")
    assert bridge.call("info").json()["multisite"] is True


def test_info_db_version_unknown_is_null_not_zero(bridge):
    """A missing / non-scalar db_version option is UNKNOWN (null), never a
    0: a false zero would read as "needs migrating from scratch"."""
    (bridge.docroot / "wpt-stub-no-db-version").write_text("")
    data = bridge.call("info").json()
    assert data["ok"] is True
    assert data["db_version"] is None


def test_core_upgrade_through_the_real_client(bridge):
    """The client's own method: the wire call, the int normalization and
    the refusal shapes a hostile/malformed answer must produce."""
    client = live_client(bridge)
    result = client.upgrade_core()
    assert result == {"db_version": 60356, "target_db_version": 60356,
                      "wp_version": "6.4.2", "output": "",
                      "output_truncated": False}
    # an UNREADABLE schema version is refused: the caller must never be
    # handed a "migration finished, version 0"
    client.call = lambda *a, **k: {"db_version": None,
                                    "target_db_version": 1,
                                    "wp_version": "6.4.2",
                                    "output": "", "output_truncated": False}
    with pytest.raises(BridgeError, match="unusable db_version"):
        client.upgrade_core()
    # a 0 is not a schema version: refused, not reported as "at zero"
    client.call = lambda *a, **k: {"db_version": "0",
                                    "target_db_version": 1,
                                    "wp_version": "6.4.2",
                                    "output": "", "output_truncated": False}
    with pytest.raises(BridgeError, match="unusable db_version"):
        client.upgrade_core()
    # a missing version is unusable, not "empty is fine"
    client.call = lambda *a, **k: {"db_version": 1, "target_db_version": 1,
                                    "wp_version": "",
                                    "output": "", "output_truncated": False}
    with pytest.raises(BridgeError, match="unusable wp_version"):
        client.upgrade_core()
    # the migration's output is a contract, not a courtesy: a payload
    # without it (or with a non-bool truncation flag) is a wire anomaly
    client.call = lambda *a, **k: {"db_version": 1, "target_db_version": 1,
                                    "wp_version": "6.4.2",
                                    "output_truncated": False}
    with pytest.raises(BridgeError, match="output is"):
        client.upgrade_core()
    client.call = lambda *a, **k: {"db_version": 1, "target_db_version": 1,
                                    "wp_version": "6.4.2",
                                    "output": "x", "output_truncated": "yes"}
    with pytest.raises(BridgeError, match="output_truncated"):
        client.upgrade_core()


def test_the_clients_upgrade_marker_read(bridge):
    """``upgrade_marker`` is the client's own reader for the op's
    pre-migration marker, and it normalizes the two schema versions
    through the same coercion every other wire integer uses."""
    client = live_client(bridge)
    assert client.upgrade_marker() is None      # nothing has migrated
    bridge.call("core_upgrade", {"apply": True})
    marker = client.upgrade_marker()
    assert marker["from_db_version"] == 56657
    assert marker["target_db_version"] == 60356
    assert marker["finished"] is not None
    # a payload that is not a usable marker is None, never a half-read one
    client.call = lambda *a, **k: {"ok": True, "upgrade_marker": "nope"}
    assert client.upgrade_marker() is None


# ---------------------------------------------------------------------------
# End to end: the REAL client against the REAL bridge
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# core_upgrade_files (WordPress's OWN file half of a core update)
#
# The op drives core's own extractor and copy (harness stubs written to the
# docroot as wp-admin/includes/{file,class-wp-upgrader,class-wp-upgrader-skin,
# class-wp-automatic-upgrader,class-wp-filesystem-*,update-core}.php, with the
# extraction and the copy doing the REAL work), so what these tests pin is
# which core function the op calls, with what arguments, and what it reports.
#
#   requires_apply .... the mutating gate; nothing is touched without it
#   refuses_multisite . the core_upgrade refusal, same reason
#   drives_core_and_reports_every_phase ... unzip_file() into
#       wp-content/upgrade/, copy_dir() with core's skip list, version.php
#       LAST, the maintenance file written and removed, the bundled
#       re-add, wp-content/ NOT overlaid, and every phase MEASURED off the
#       disk afterwards
#   arms_attempt_rollback_the_admin_never_passes ... the argument the
#       bridge builds, and core's own critical-code rule applied to it
#   reports_a_core_failure_with_its_phases .... a mid-tree copy failure:
#       reported (not thrown), core's rollback class named, version.php
#       still the old one, .maintenance left behind, staging reported
#   refuses_a_filesystem_core_cannot_drive .... the PRECONDITION (direct)
#   refuses_to_wipe_an_earlier_staging ........ the recovery path is not
#       core's to delete
#   suppresses_the_fire_and_forget_db_step ..... core's own POST, blocked
#       through core's pre_http_request, and said so
#   refuses_a_package_outside_the_webroot ..... core_md5's anti-traversal
#   requires_a_target / refuses_an_install_with_no_update_body
#   info answers the driver facts ONLY when asked (get_filesystem_method
#       writes a probe file into the webroot) and reports an unreadable one
#       as unknown
#   the client .... the real client method: the account on success, the
#       op's refusal and the version check
# ---------------------------------------------------------------------------

#: The release the op is handed: the zip wpt would have proved against
#: wp.org's checksum map and uploaded.  One top-level ``wordpress/``
#: directory, the two sentinels core's own insane_distro check looks for,
#: a version.php declaring the target, a bundled theme the release
#: introduces (introduced in 6.7, above the harness site's 6.4.2, so core's
#: own re-add logic introduces it), and a wp-content/ tree core's copy must
#: NOT overlay.
def _release_zip_bytes(version: str = "7.1.2", *,
                       bundled: str = "twentytwentyfive") -> bytes:
    import io as _io
    import zipfile as _zipfile

    buf = _io.BytesIO()
    with _zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("wordpress/readme.html", "<h1>WordPress</h1>\n")
        zf.writestr("wordpress/index.php", b"<?php // new index\n")
        zf.writestr("wordpress/wp-admin/index.php", b"<?php // new admin\n")
        zf.writestr("wordpress/wp-includes/version.php",
                    f"<?php\n$wp_version = '{version}';\n"
                    f"$wp_db_version = 60356;\n?>\n".encode())
        zf.writestr("wordpress/wp-includes/functions.php", b"/* new */\n")
        zf.writestr(f"wordpress/wp-content/themes/{bundled}/style.css",
                    b"/* bundled */\n")
        zf.writestr("wordpress/wp-content/index.php", b"<?php // silence\n")
    return buf.getvalue()


def _upload_release(bridge, version: str = "7.1.2") -> str:
    """Put the release where wpt puts it: wp-content/wpt-update/, never
    inside wp-content/upgrade/ (core's unpack_package wipes that folder on
    its way in, so a package parked there would be deleted unread)."""
    path = bridge.docroot / "wp-content" / "wpt-update"
    path.mkdir(parents=True, exist_ok=True)
    rel = f"wp-content/wpt-update/wordpress-{version}.zip"
    (bridge.docroot / rel).write_bytes(_release_zip_bytes(version))
    return rel


def test_core_upgrade_files_requires_apply(bridge):
    """The gate is the same one every mutating op in this bridge carries.

    A call without it must touch nothing: no staging, no copy, no
    maintenance file.  The op overwrites the site's core files, so the
    flag is the difference between a dry run and an update.
    """
    package = _upload_release(bridge)
    before = list(bridge.calls())
    data = bridge.call("core_upgrade_files",
                       {"package": package, "target": "7.1.2"}).json()
    assert data["ok"] is False
    assert "requires apply=true" in data["error"]
    assert not any(c.startswith(("unzip_file:", "copy_dir:", "update_core"))
                   for c in bridge.calls()[len(before):])
    assert not (bridge.docroot / "wp-content" / "upgrade").exists()
    assert (bridge.docroot / "index.php").read_bytes() == \
        b"wpt-fixture:index.php\n"


def test_core_upgrade_files_refuses_multisite(bridge):
    """The same refusal core_upgrade makes, for the same reason: a network
    install's core update is a network operation and this action's
    snapshot is one site's."""
    package = _upload_release(bridge)
    (bridge.docroot / "wpt-stub-multisite").write_text("")
    data = bridge.call("core_upgrade_files",
                       {"apply": True, "package": package,
                        "target": "7.1.2"}).json()
    assert data["ok"] is False
    assert "multisite" in data["error"]
    assert not (bridge.docroot / "wp-content" / "upgrade").exists()
    (bridge.docroot / "wpt-stub-multisite").unlink()


def test_core_upgrade_files_drives_core_and_reports_every_phase(bridge):
    """THE OP: WordPress's own updater does the work, and the answer
    reports what it actually did.

    Every property asserted here is one a re-implementation of file
    placement would have to get right, and the reason wpt does not
    re-implement it: the extraction goes through core's own
    ``unzip_file()`` into core's own staging directory
    (``wp-content/upgrade/``), the copy goes through core's own
    ``copy_dir()`` with core's own skip list
    (``array('wp-content','wp-includes/version.php')``), the version file
    lands LAST, and the bundled theme/plugin re-add runs.  The phases are
    MEASURED from disk afterwards, not claimed.
    """
    package = _upload_release(bridge)
    before = len(bridge.calls())
    data = bridge.call("core_upgrade_files", {
        "apply": True, "package": package, "target": "7.1.2"}).json()
    assert data["ok"] is True, data
    assert data["error"] is None
    calls = bridge.calls()[before:]
    # core's own extraction, into core's own staging directory
    assert any(c.startswith("unzip_file:wp-content/wpt-update/wordpress-7.1.2.zip"
                            " -> wp-content/upgrade/wordpress-7.1.2")
               for c in calls), calls
    assert any(c.startswith("unpack_package:working=wp-content/upgrade/"
                            "wordpress-7.1.2") for c in calls), calls
    # core's own copy, with core's own skip list
    copy = [c for c in calls if c.startswith("copy_dir:")][0]
    assert "skip=wp-content,wp-includes/version.php" in copy, copy
    assert "copy_dir:skipped:wp-content" in calls
    assert "copy_dir:skipped:version.php" in calls
    # version.php copied LAST, after the tree
    assert "copy:version.php:last" in calls
    assert calls.index("copy:version.php:last") > calls.index(copy)
    # the maintenance file core writes and removes on ITS success route
    assert "maintenance:write" in calls and "maintenance:delete" in calls
    assert data["maintenance_left"] is False
    assert not (bridge.docroot / ".maintenance").exists()
    # the bundled re-add ran, and reported the unit it introduced
    assert "bundled:added:themes/twentytwentyfive/" in calls
    assert data["bundled_added"] == ["themes/twentytwentyfive/"]
    assert (bridge.docroot / "wp-content" / "themes" / "twentytwentyfive"
            / "style.css").read_bytes() == b"/* bundled */\n"
    # the bytes really landed on the webroot
    assert (bridge.docroot / "index.php").read_bytes() == b"<?php // new index\n"
    assert (bridge.docroot / "wp-includes" / "functions.php").read_bytes() == \
        b"/* new */\n"
    # wp-content/ was NOT overlaid: the release ships its own
    # wp-content/index.php, and the SITE's own must survive it — which is
    # what core's skip list exists for, and what re-implementing the copy
    # would have to reproduce exactly
    assert (bridge.docroot / "wp-content" / "index.php").read_bytes() == \
        b"wpt-fixture:wp-content-index.php\n"

    # ---- what it reports, per phase, measured off the disk
    assert data["wp_version"] == "7.1.2"       # read back, not returned
    assert data["from_wp_version"] == "6.4.2"  # get_bloginfo('version')
    assert data["staging"] == "wp-content/upgrade/wordpress-7.1.2"
    assert data["staging_exists"] is False     # core removed its own staging
    for phase in ("unzip", "copy", "bundled"):
        assert data["phases"][phase]["ok"] is True, (phase, data["phases"])
    assert "/wordpress/" in data["phases"]["unzip"]["detail"]
    assert "$wp_version = 7.1.2" in data["phases"]["copy"]["detail"]
    assert "1 of 1" in data["phases"]["bundled"]["detail"]
    # core's OWN ordered progress messages, read off update_feedback
    assert data["progress"][0] == "Verifying the unpacked files…"
    assert "Copying the required files" not in data["progress"]  # our stub's
    assert data["progress"][-1] == "Upgrading database…"
    assert data["filesystem_method"] == "direct"
    assert data["zip_library"] in ("ZipArchive", "PclZip")
    assert data["output"] == "" and data["output_truncated"] is False
    # the schema version is UNTOUCHED: this op does the file half only
    assert data["db_version"] == "56657"


def test_core_upgrade_files_arms_attempt_rollback_the_admin_never_passes(bridge):
    """``attempt_rollback => true`` is in the ARGUMENT the bridge builds.

    A manually clicked "Update Now" gets no rollback — only
    WP_Automatic_Updater arms it — and the arming is only useful if the
    answer says so AND core's own critical-failure rule is applied to the
    result, so the operator is told whether the failure that happened is
    the class core would have rolled back.  A package that fails a
    rollback-worthy way must therefore carry ``critical_code``; one that
    fails any other way must not.
    """
    package = _upload_release(bridge)
    data = bridge.call("core_upgrade_files", {
        "apply": True, "package": package, "target": "7.1.2"}).json()
    assert data["upgrade_args"]["attempt_rollback"] is True
    assert data["upgrade_args"]["do_rollback"] is False
    # the caller proved the bytes, and the package is the full release
    assert data["upgrade_args"]["pre_check_md5"] is False
    assert data["rollback"]["armed"] is True
    assert data["rollback"]["taken"] is False
    assert "pre-action snapshot" in data["rollback"]["reason"]
    assert "critical_code" not in data["rollback"]

    # a failure that is NOT core's rollback class carries no critical_code
    (bridge.docroot / "wp-admin" / "includes" / "update-core.php").unlink()
    package = _upload_release(bridge)
    plain = bridge.call("core_upgrade_files", {
        "apply": True, "package": package, "target": "7.1.2"}).json()
    assert plain["error"]["code"] == "no_update_core_body"
    assert "critical_code" not in plain["rollback"]


def test_core_upgrade_files_reports_a_core_failure_with_its_phases(bridge):
    """A mid-tree copy failure, on a site whose version file is intact.

    Three things this pins, each of which a naive driver would get wrong:
    the failure is REPORTED (``ok: true`` with ``error``) so the phases
    that got that far survive the answer; core's own critical-code rule
    fires, because ``copy_failed__copy_dir`` is exactly the class core
    would have rolled back on; and core's failure path leaves ITS
    ``.maintenance`` file behind (it is deleted only on the success
    route), which the op reports so the caller's own teardown can be
    trusted to have removed it.
    """
    (bridge.docroot / "wpt-stub-core-copy-fails").write_text("")
    package = _upload_release(bridge)
    data = bridge.call("core_upgrade_files", {
        "apply": True, "package": package, "target": "7.1.2"}).json()
    assert data["ok"] is True           # reported, not thrown
    assert data["error"]["code"] == "copy_failed__copy_dir"
    assert data["rollback"]["critical_code"] == "copy_failed__copy_dir"
    # the extraction finished; the copy did not
    assert data["phases"]["unzip"]["ok"] is True
    assert data["phases"]["copy"]["ok"] is False
    # core copies version.php LAST, precisely so a half-copied site still
    # reports its OLD version: the file on disk is not the target's
    assert (bridge.docroot / "wp-includes" / "version.php").read_bytes() == \
        b"wpt-core-fixture:wp-includes/version.php"
    assert data["wp_version"] is None
    assert data["maintenance_left"] is True
    # and the staging is still there — the recovery path, reported
    assert data["staging"] == "wp-content/upgrade/wordpress-7.1.2"
    assert data["staging_exists"] is True


def test_core_upgrade_files_refuses_a_filesystem_core_cannot_drive(bridge):
    """The PRECONDITION, not a retry.

    A host whose files are owned by the FTP user resolves to a non-direct
    method, and core's upgrader then blocks on an interactive credential
    prompt a bridge endpoint has nobody to answer.  The op refuses, names
    the method and points at the driver that needs no precondition.
    """
    package = _upload_release(bridge)
    (bridge.docroot / "wpt-stub-fs-method").write_text("ftpext")
    data = bridge.call("core_upgrade_files", {
        "apply": True, "package": package, "target": "7.1.2"}).json()
    assert data["ok"] is False
    assert "filesystem method is ftpext" in data["error"]
    assert "update.driver=swap" in data["error"]
    assert not (bridge.docroot / "wp-content" / "upgrade").exists()
    assert (bridge.docroot / "index.php").read_bytes() == \
        b"wpt-fixture:index.php\n"
    (bridge.docroot / "wpt-stub-fs-method").unlink()


def test_core_upgrade_files_refuses_to_wipe_an_earlier_staging(bridge):
    """core's unpack_package() WIPES wp-content/upgrade/ on its way in, so
    a non-empty one is an earlier core update that did not finish — and its
    staging is the recovery path.  The op refuses rather than deleting it,
    and NAMES it."""
    staging = bridge.docroot / "wp-content" / "upgrade" / "wordpress-7.0"
    staging.mkdir(parents=True)
    (staging / "version.php").write_bytes(b"<?php // 7.0\n")
    package = _upload_release(bridge)
    data = bridge.call("core_upgrade_files", {
        "apply": True, "package": package, "target": "7.1.2"}).json()
    assert data["ok"] is False
    assert "already holds 1 entr" in data["error"]
    assert "wordpress-7.0" in data["error"]
    assert (staging / "version.php").read_bytes() == b"<?php // 7.0\n"
    assert not any(c.startswith("unpack_package:wiped:") for c in bridge.calls())


def test_core_upgrade_files_suppresses_the_fire_and_forget_db_step(bridge):
    """core posts the database migration to itself with a 60s timeout and
    NEVER inspects the response.  From a bridge endpoint that is a second,
    unauthenticated migration racing the one wpt runs on purpose, and its
    outcome is unobservable — so the op blocks it through core's own
    ``pre_http_request`` filter and SAYS SO in the answer."""
    package = _upload_release(bridge)
    data = bridge.call("core_upgrade_files", {
        "apply": True, "package": package, "target": "7.1.2"}).json()
    assert data["ok"] is True
    assert "wp_remote_post:preempted" in bridge.calls()
    assert not any(c.startswith("wp_remote_post:https://example.test")
                   for c in bridge.calls())
    assert "fire-and-forget" in data["db_step"]
    assert "re-reads db_version" in data["db_step"]
    # and nothing migrated: the file half does not touch the schema
    assert bridge.call("info").json()["db_version"] == "56657"


def test_core_upgrade_files_refuses_a_package_outside_the_webroot(bridge):
    """The path reaches core's own extractor, so it gets core_md5's
    anti-traversal discipline: NUL stripped, no "..", realpath contained
    in ABSPATH, a regular file, a .zip."""
    outside = bridge.docroot.parent / "release.zip"
    outside.write_bytes(_release_zip_bytes())
    for package in ("../release.zip", "/etc/passwd", "",
                    "wp-content/wpt-update/not-there.zip"):
        data = bridge.call("core_upgrade_files", {
            "apply": True, "package": package, "target": "7.1.2"}).json()
        assert data["ok"] is False, package
    (bridge.docroot / "wp-content" / "wpt-update").mkdir(parents=True,
                                                         exist_ok=True)
    (bridge.docroot / "wp-content" / "wpt-update" / "notes.txt").write_text("x")
    data = bridge.call("core_upgrade_files", {
        "apply": True, "package": "wp-content/wpt-update/notes.txt",
        "target": "7.1.2"}).json()
    assert data["ok"] is False and "not a .zip" in data["error"]


def test_core_upgrade_files_requires_a_target(bridge):
    package = _upload_release(bridge)
    data = bridge.call("core_upgrade_files",
                       {"apply": True, "package": package}).json()
    assert data["ok"] is False and "missing target" in data["error"]


def test_core_upgrade_files_refuses_an_install_with_no_update_body(bridge):
    """A trimmed install that ships neither update-core.php nor update.php
    has no core update body to drive — the op says so instead of copying
    half a release."""
    (bridge.docroot / "wp-admin" / "includes" / "update-core.php").unlink()
    package = _upload_release(bridge)
    data = bridge.call("core_upgrade_files", {
        "apply": True, "package": package, "target": "7.1.2"}).json()
    assert data["ok"] is True          # the phases that got that far survive
    assert data["error"]["code"] == "no_update_core_body"
    assert data["phases"]["unzip"]["ok"] is True
    assert data["phases"]["copy"]["ok"] is False
    assert (bridge.docroot / "index.php").read_bytes() == \
        b"wpt-fixture:index.php\n"


def test_info_answers_the_driver_facts_only_when_asked(bridge):
    """``info`` is a cheap, side-effect-free read for the audit, and
    get_filesystem_method() WRITES a probe file into the webroot — so the
    two driver facts are asked for, never volunteered."""
    plain = bridge.call("info").json()
    assert "filesystem_method" not in plain
    facts = bridge.call("info", {"core_upgrade": True}).json()
    assert facts["filesystem_method"]["filesystem_method"] == "direct"
    assert facts["filesystem_method"]["zip_library"] in ("ZipArchive", "PclZip")


def test_info_reports_an_unreadable_filesystem_method_as_unknown(bridge):
    """A method that cannot be read is '', never a fabricated 'direct'."""
    (bridge.docroot / "wpt-stub-fs-method").write_text("ftpext")
    facts = bridge.call("info", {"core_upgrade": True}).json()
    assert facts["filesystem_method"]["filesystem_method"] == "ftpext"
    (bridge.docroot / "wp-admin" / "includes" / "file.php").unlink()
    facts = bridge.call("info", {"core_upgrade": True}).json()
    assert facts["filesystem_method"] == {
        "filesystem_method": "", "zip_library": ""}
    (bridge.docroot / "wpt-stub-fs-method").unlink()


def test_the_client_runs_the_op_and_refuses_a_mismatched_target(bridge):
    """Through the REAL client: a successful call returns the account, and
    a package that did not land the target is a BridgeError naming it —
    the driver whose result cannot be read cannot be called successful."""
    package = _upload_release(bridge)
    with live_client(bridge) as client:
        result = client.core_upgrade_files(package, "7.1.2")
        assert result["wp_version"] == "7.1.2"
        assert result["phases"]["copy"]["ok"] is True
        assert result["upgrade_args"]["attempt_rollback"] is True
        assert result["staging"] == "wp-content/upgrade/wordpress-7.1.2"
        # a target the package does not carry: the OP refuses it, because
        # core's own insane_distro check is two sentinel files and asserts
        # nothing about the version — so the op is the one that compares.
        with pytest.raises(BridgeError) as excinfo:
            client.core_upgrade_files(package, "9.9.9")
    assert "version_mismatch" in str(excinfo.value)
    assert excinfo.value.payload["phases"]["copy"]["ok"] is False


def test_the_client_checks_the_target_itself(bridge):
    """The client's own comparison is a second line, not the only one: an
    op that reported success for a package carrying a different version
    must still be refused, because the target is the CALLER's fact."""
    package = _upload_release(bridge)
    with live_client(bridge) as client:
        real = client.call

        def lie(action, **params):
            payload = real(action, **params)
            if action == "core_upgrade_files":
                payload["wp_version"] = "6.4.2"      # what the site ran before
            return payload

        client.call = lie
        with pytest.raises(BridgeError) as excinfo:
            client.core_upgrade_files(package, "7.1.2")
    assert "did not install the target" in str(excinfo.value)


def test_the_client_raises_the_core_error_and_keeps_the_phases(bridge):
    """A core failure is REPORTED by the op (ok:true, error:{...}) so the
    phases that got that far survive; the client turns it into the refusal
    the run fails on, with that account in the payload."""
    (bridge.docroot / "wpt-stub-core-copy-fails").write_text("")
    package = _upload_release(bridge)
    with live_client(bridge) as client:
        with pytest.raises(BridgeError) as excinfo:
            client.core_upgrade_files(package, "7.1.2")
    assert "copy_failed__copy_dir" in str(excinfo.value)
    payload = excinfo.value.payload
    assert payload["phases"]["unzip"]["ok"] is True
    assert payload["phases"]["copy"]["ok"] is False
    assert payload["rollback"]["critical_code"] == "copy_failed__copy_dir"
    assert payload["staging"] == "wp-content/upgrade/wordpress-7.1.2"


def test_the_client_refuses_an_answer_it_cannot_read(bridge):
    """A driver whose result cannot be read is not a successful driver."""
    package = _upload_release(bridge)
    with live_client(bridge) as client:
        real = client.call

        def no_phases(action, **params):
            payload = real(action, **params)
            payload.pop("phases", None)
            return payload

        client.call = no_phases
        with pytest.raises(BridgeError, match="no phases"):
            client.core_upgrade_files(package, "7.1.2")


def live_client(bridge) -> Bridge:
    """A real Bridge session over the harness docroot and php -S server."""
    return Bridge(DocrootSource(bridge.docroot), requests.Session(), "",
                  BridgeSettings(), bridge.base)


def test_end_to_end_one_stale_transient_does_not_kill_the_keep_set(bridge):
    # THE LIVE FAILURE, reproduced whole: the site's uploads carry the
    # stale _transient_dirsize_cache option (many absolute paths to the
    # PREVIOUS host, several of them bare year directories).  The client's
    # db_media_refs() used to refuse the whole answer, so media.unreferenced
    # fell back to walk-only and trim-media --apply refused — one junk row
    # disabled the union on the site.  Through the real client and the real
    # op, the union survives and the loss is REPORTED.
    before = {p.name for p in bridge.docroot.glob("bridge-*.php")}
    with live_client(bridge) as client:
        refs = client.db_media_refs()
    assert "2023/10/pic.jpg" in refs            # the migrated site's own file
    assert "2023/12/legacy.png" in refs
    assert not any(year in refs for year in ("2018", "2019", "2023"))
    assert not any(r.startswith("/") for r in refs)
    # the client deployed a token-guarded file and self-destructed it: no
    # new bridge-*.php is left in the docroot
    assert before == {p.name for p in bridge.docroot.glob("bridge-*.php")}


def test_end_to_end_media_rewrite_refs_through_the_real_client(bridge):
    # The op webp-media calls, driven exactly as the action drives it: the
    # read-only scan, then the apply with the mapping and one row per edit
    # — the whole reason `wpt webp-media` could not even PLAN before.
    client = live_client(bridge)
    mapping = {"2023/10/pic.jpg": "2023/10/pic.webp",
               "2023/10/pic-300x233.jpg": "2023/10/pic-300x233.webp"}
    with client:
        rows = list(client.iter_rewrite_refs())
        rewritable = [r for r in rows if "value" in r]
        gated = [r for r in rows if "gated" in r]
        assert {f"{r['table']}[{r['id']}]" for r in rewritable} == {
            "wp_posts[7]", "wp_postmeta[11]", "wp_postmeta[12]", "wp_options[4]"}
        assert {f"{r['table']}[{r['id']}]" for r in gated} == {
            "wp_posts[7]", "wp_comments[5]", "wp_usermeta[3]", "wp_termmeta[6]"}
        answer = client.rewrite_refs(
            mapping=mapping,
            rows=[{"table": r["table"], "key": r["key"], "id": r["id"]}
                  for r in rewritable])
    # the re-read values are the SERVER's proof, and every requested row is
    # accounted for
    assert [(r["table"], r["id"]) for r in answer] == [
        ("wp_options", 4), ("wp_postmeta", 11), ("wp_postmeta", 12),
        ("wp_posts", 7)]
    assert answer[0]["value"].endswith(
        's:36:"/wp-content/uploads/2023/10/pic.webp";}')
    assert "s:39:" in answer[1]["value"]        # the serialized rewrite
    assert "2023/10/pic.webp" in answer[3]["value"]
    store = json.loads((bridge.docroot / "wpt-stub-ref-rows.json").read_text())
    assert store["wp_posts"]["7"]["post_content"].endswith("pic.webp\" /></p>")
    assert "s:39:" in store["wp_postmeta"]["11"]["meta_value"]


def test_end_to_end_a_failing_rewrite_raises_rather_than_half_write(bridge):
    client = live_client(bridge)
    with client:
        with pytest.raises(BridgeError) as ei:
            client.rewrite_refs(
                mapping={"2023/10/pic.jpg": "2023/10/pic.webp"},
                rows=[{"table": "wp_posts", "key": "ID", "id": 7},
                      {"table": "wp_posts", "key": "ID", "id": 4242}])
    assert "were not rewritten" in str(ei.value)
    assert "wp_posts[4242]" in str(ei.value)


def test_end_to_end_a_mid_scan_failure_reaches_the_operator_as_the_servers_reason(
        bridge):
    # The whole point of D2, seen from the only side that matters: before
    # the fix the operator saw "malformed NDJSON line: Warning: Cannot
    # modify header information - headers already sent in …/docroot/
    # bridge-…php" — the client's guess at a broken server, with the
    # server's real reason and its absolute path both lost. Now the reason
    # is what the message says, and nothing about the deployment leaks.
    (bridge.docroot / "wpt-stub-ref-scan-fails").write_text("wp_postmeta")
    with live_client(bridge) as client:
        with pytest.raises(BridgeError) as ei:
            list(client.iter_rewrite_refs())
    message = str(ei.value)
    assert "reference scan failed for wp_postmeta" in message, message
    assert "malformed NDJSON line" not in message
    assert "headers already sent" not in message
    assert "docroot" not in message
    assert "Warning" not in message


def test_end_to_end_a_truncated_scan_refuses_rather_than_planning(
        bridge, tmp_path, monkeypatch):
    # The same lowered cap, but through the REAL client and the file it
    # uploads itself: a half-measured reference set raises instead of
    # reaching the plan, which is the whole point of the marker.
    # only the cap changes: the client still substitutes its own token and
    # expiry into the file it uploads.
    low = tmp_path / "bridge-lowcap.php"
    low.write_text(
        BRIDGE_SOURCE.read_text(encoding="utf-8").replace(
            "define( 'WPT_MEDIA_REWRITE_SCAN_CAP', 100000 );",
            "define( 'WPT_MEDIA_REWRITE_SCAN_CAP', 2 );"),
        encoding="utf-8")
    monkeypatch.setattr(client_module, "_BRIDGE_PHP", low)
    with live_client(bridge) as client:
        with pytest.raises(BridgeError, match="truncated"):
            list(client.iter_rewrite_refs())


def test_end_to_end_the_scan_cap_door_opens_from_the_client(bridge, tmp_path,
                                                           monkeypatch, caplog):
    # THE DOOR, WHOLE.  Through the REAL client and the file it uploads
    # itself, against a site whose image-bearing rows exceed the op's
    # DEFAULT cap: the default refuses (half-measured), and the same call
    # with ``scan_cap`` gets the whole set.  Before the client could send
    # one, a site over 100k rows had exactly one way past it — editing the
    # deployed PHP by hand — so the parameter existed and nothing could
    # reach it.
    low = tmp_path / "bridge-lowcap.php"
    low.write_text(
        BRIDGE_SOURCE.read_text(encoding="utf-8").replace(
            "define( 'WPT_MEDIA_REWRITE_SCAN_CAP', 100000 );",
            "define( 'WPT_MEDIA_REWRITE_SCAN_CAP', 2 );"),
        encoding="utf-8")
    monkeypatch.setattr(client_module, "_BRIDGE_PHP", low)
    with live_client(bridge) as client:
        with pytest.raises(BridgeError, match="truncated"):
            list(client.iter_rewrite_refs())
        rows = list(client.iter_rewrite_refs(
            scan_cap=client_module.REWRITE_REF_SCAN_CAP_MAX))
    assert rows == SCAN_ROWS


def test_end_to_end_a_clamped_scan_cap_is_reported_not_swallowed(bridge, tmp_path,
                                                                monkeypatch, caplog):
    # ... and asking for MORE than the op will honour is answered at the
    # ceiling and says so, and the client says so TOO: a caller that asked
    # to measure a million rows and was handed ten must not read the plan
    # that follows as a complete measurement of the site.  The ceiling here
    # is lowered to 10 so the scan still COMPLETES — a clamped request that
    # also truncates is refused outright (the existing truncation contract,
    # pinned above), which is a louder answer than this one.
    low = tmp_path / "bridge-lowceiling.php"
    low.write_text(
        BRIDGE_SOURCE.read_text(encoding="utf-8").replace(
            "define( 'WPT_MEDIA_REWRITE_SCAN_CAP_MAX', 1000000 );",
            "define( 'WPT_MEDIA_REWRITE_SCAN_CAP_MAX', 10 );"),
        encoding="utf-8")
    monkeypatch.setattr(client_module, "_BRIDGE_PHP", low)
    wpt_logger = logging.getLogger("wpt")
    wpt_logger.addHandler(caplog.handler)
    caplog.set_level(logging.WARNING, logger="wpt")
    try:
        with live_client(bridge) as client:
            rows = list(client.iter_rewrite_refs(
                scan_cap=client_module.REWRITE_REF_SCAN_CAP_MAX))
    finally:
        wpt_logger.removeHandler(caplog.handler)
    assert rows == SCAN_ROWS
    clamped = [r for r in caplog.records if "CLAMPED" in r.getMessage()]
    assert len(clamped) == 1, [r.getMessage() for r in caplog.records]
    assert "10" in clamped[0].getMessage()


def test_end_to_end_webp_media_plans_and_applies_against_the_real_op(bridge):
    """`wpt webp-media` in ftp mode, driven against the REAL bridge.

    THE D1 DEFECT, whole: the action called an op the whitelist did not
    have, so every ftp-mode run died with "unknown action" — it could not
    even PLAN.  This drives the action itself (plan + apply) over the real
    docroot, the real php -S bridge and the real client, so the wire shapes
    are proven by the one consumer that depends on them.
    """
    import io
    import random

    from PIL import Image

    from wpt.actions.images_webp import ImagesWebpAction
    from wpt.cli import Ctx
    from wpt.settings import load

    # A real, decodable JPEG where the stub's post 7 references it, and
    # big enough to clear webp.skip_below_bytes.
    rnd = random.Random(7)
    image = Image.new("RGB", (400, 400))
    image.putdata([(rnd.randrange(256), rnd.randrange(256), rnd.randrange(256))
                   for _ in range(400 * 400)])
    photo = bridge.uploads / "2023" / "10" / "pic.jpg"
    buffer = io.BytesIO()
    image.save(buffer, format="JPEG", quality=95)
    photo.write_bytes(buffer.getvalue())
    # db_audit must see the WordPress tables: the action snapshots every
    # table it will rewrite, and refuses when the list cannot cover them.
    (bridge.docroot / "wpt-stub-tables.json").write_text(json.dumps(
        ["wp_posts", "wp_postmeta", "wp_options", "wp_comments",
         "wp_users", "wp_usermeta", "wp_termmeta"]))

    ctx = Ctx(source="ftp://example.test",
              settings=load(str(REPO / "wpt/data/profiles/default.json")),
              command="webp-media", apply=True, yes=True,
              backup_dir=bridge.docroot.parent / "backup",
              sql=None, zip=None, wp_url=None)
    client = live_client(bridge)
    action = ImagesWebpAction()
    with client:
        plan = action.plan(ctx, (DocrootSource(bridge.docroot), None, client))
        targets = {item.target for item in plan.items}
        assert "wp-content/uploads/2023/10/pic.webp" in targets, \
            [i.target for i in plan.items]
        # the read-only surfaces are REPORTED as holding images back
        gated = [i for i in plan.items if i.category == "media.webp_gated"]
        assert gated and "gated-table" in gated[0].target
        applied = action.apply(ctx, (DocrootSource(bridge.docroot), None,
                                     client), plan)
        done = [i for i in applied.items if i.requires_apply and i.done]
        assert done, "nothing the plan promised actually landed"

    # the twin is on disk and the ORIGINAL is kept (no --purge-originals)
    assert (bridge.uploads / "2023" / "10" / "pic.webp").exists()
    assert photo.exists()
    # the rows carry the SERVER's re-read: the serialized one had its
    # "s:38:" length prefix recomputed to "s:39:" in PHP
    store = json.loads((bridge.docroot / "wpt-stub-ref-rows.json").read_text())
    assert store["wp_posts"]["7"]["post_content"].endswith("pic.webp\" /></p>")
    assert "s:39:" in store["wp_postmeta"]["11"]["meta_value"]
    assert store["wp_options"]["4"]["option_value"].endswith(
        's:36:"/wp-content/uploads/2023/10/pic.webp";}')
    # ... and no row still points at a converted original
    for table, rows in store.items():
        for row in rows.values():
            for value in row.values():
                if isinstance(value, str):
                    assert "2023/10/pic.jpg" not in value, (table, value)




def test_end_to_end_a_value_the_proof_cannot_spend_answers_and_leaves_nothing(
        tmp_path):
    """[C] THE WHOLE OP, under a memory limit that a runaway must hit.

    Everything else in this file measures the deployed function in
    isolation.  This one runs what an operator runs: the REAL client, which
    DEPLOYS a bridge file, drives the op, and destroys the bridge again —
    with the server started under a 32 MB limit, so a value the proof
    cannot bound within it produces the uncatchable FATAL the harness
    exists to survive rather than a graceful refusal.

    A stored row carrying a value just past the deployed work budget (1025
    levels) is that value: the smallest shape the proof must refuse.  The
    4096-level boundary is owned by
    test_a_value_at_php_s_own_nesting_limit_is_refused_not_spent, so this
    end-to-end case does not pay the extreme cost twice.  The answer must
    be:

    * a BridgeError carrying the SERVER's reason (the work budget), never
      "bridge returned non-JSON" and never a truncated stream;
    * no write: the row is left byte-for-byte as it was;
    * no residue: the count of deployed ``bridge-*.php`` files is back to
      what it was, so the failure did not leave a token-guarded PHP file
      sitting in the webroot.
    """
    env = _build(tmp_path, ini=["-d", "memory_limit=32M"])
    try:
        scan(env)                       # the rows fixture the apply reads
        rows_file = env.docroot / "wpt-stub-ref-rows.json"
        store = json.loads(rows_file.read_text())
        deep = nested_arrays(1025)      # just over the deployed 1024 budget
        store["wp_options"]["30"] = {
            "option_id": "30", "option_name": "deep", "autoload": "no",
            "option_value": deep,
        }
        rows_file.write_text(json.dumps(store))
        before = {p.name for p in env.docroot.glob("bridge-*.php")}
        assert before                       # the fixture's own deployments
        client = live_client(env)
        with client:
            with pytest.raises(BridgeError) as ei:
                client.rewrite_refs(
                    mapping={"2023/10/pic.jpg": "2023/10/pic.webp"},
                    rows=[{"table": "wp_options", "key": "option_id",
                           "id": 30}],
                )
        message = str(ei.value)
        # the SERVER's reason, with the bound in it
        assert "work budget" in message
        assert "1024" in message
        assert "non-JSON" not in message
        assert "Fatal error" not in message
        # nothing was written
        after = json.loads(rows_file.read_text())
        assert after["wp_options"]["30"]["option_value"] == deep
        # ... and no bridge file was left behind: the client deployed one
        # and destroyed it on the way out
        assert before == {p.name for p in env.docroot.glob("bridge-*.php")}
    finally:
        env.close()


def test_end_to_end_a_refused_row_does_not_abort_its_batch(tmp_path):
    """[C, residual] A BUDGET REFUSAL IS A PER-ROW ANSWER, not a batch error.

    The proven shape: a batch whose SECOND row is nested past the shape
    walk's work budget.  The throw had nowhere to land — the per-row loop
    had no catch — so it escaped the op, the first row was already UPDATEd,
    and the client was handed an op-level error naming no row: it could not
    tell a partial write from a whole one, which is the one thing a
    mutating answer must never make its caller guess.

    So the refusal travels on ``failed[]``, the channel that already means
    "this row must not be written", and the answer states exactly which
    rows WERE written.  Driven through the REAL client (it deploys the
    bridge, drives the op and destroys the bridge again), so the whole
    path is exercised and not a function in isolation:

    * the first row is written and REPORTED as written;
    * the second is refused BY NAME with the server's reason in the label;
    * the answer is complete and parseable, and the client refuses the
      whole call rather than reporting a partial success.
    """
    env = _build(tmp_path, ini=["-d", "memory_limit=32M"])
    try:
        scan(env)
        rows_file = env.docroot / "wpt-stub-ref-rows.json"
        store = json.loads(rows_file.read_text())
        # the offending row, one level past what the budget can read
        store["wp_options"]["30"] = {
            "option_id": "30", "option_name": "deep", "autoload": "no",
            "option_value": nested_arrays(_shape_work_budget() + 1),
        }
        rows_file.write_text(json.dumps(store))
        before = {p.name for p in env.docroot.glob("bridge-*.php")}
        client = live_client(env)
        with client:
            with pytest.raises(BridgeError) as ei:
                client.rewrite_refs(
                    mapping={"2023/10/pic.jpg": "2023/10/pic.webp"},
                    rows=[{"table": "wp_options", "key": "option_id", "id": 4},
                          {"table": "wp_options", "key": "option_id", "id": 30}],
                )
        # the refusal names the row and carries the server's reason
        message = str(ei.value)
        assert "wp_options[30]" in message, message
        assert "work budget" in message, message
        # ... and the client is still refusing the CALL, not reporting a
        # partial success: one row was not rewritten
        assert "were not rewritten" in message, message
        # the first row WAS written (the batch completed) and the offending
        # row was not touched at all
        after = json.loads(rows_file.read_text())
        assert "2023/10/pic.webp" in after["wp_options"]["4"]["option_value"]
        assert after["wp_options"]["30"]["option_value"] == \
            nested_arrays(_shape_work_budget() + 1)
        # ... and no bridge file was left behind
        assert before == {p.name for p in env.docroot.glob("bridge-*.php")}
    finally:
        env.close()


def test_end_to_end_the_bridge_self_bounds_its_own_work_without_a_client(
        tmp_path):
    """The same op answered STRUCTURALLY, with no client in the way.

    The NDJSON answer is the contract the action reads, so the refusal has
    to arrive IN it: a COMPLETE ``{ok:true, rows, failed}`` answer whose
    ``failed`` entry names the row and the bound, with the stream closed
    properly.  A truncated stream is the L4 defect in a new place, and this
    asserts the difference between that answer and this one.

    The fixture is the SMALLEST value that exercises the refusal — the
    budget plus one level.  It used to plant ``nested_arrays(4000)``, PHP's
    own nesting limit, which measured 2.64 s against the client's 10 s
    timeout: a 3.8x margin that still flaked once under load, for a value
    4x larger than the refusal needs.
    """
    env = _build(tmp_path, ini=["-d", "memory_limit=32M"])
    try:
        scan(env)
        rows_file = env.docroot / "wpt-stub-ref-rows.json"
        store = json.loads(rows_file.read_text())
        deep = nested_arrays(_shape_work_budget() + 1)
        store["wp_options"]["30"] = {
            "option_id": "30", "option_name": "deep", "autoload": "no",
            "option_value": deep,
        }
        rows_file.write_text(json.dumps(store))
        r = env.call("media_rewrite_refs", {
            "apply": True,
            "mapping": {"2023/10/pic.jpg": "2023/10/pic.webp"},
            "rows": [{"table": "wp_options", "key": "option_id", "id": 30}],
        })
        assert r.status_code == 200
        data = r.json()                       # parses: not a truncated stream
        # the answer is WHOLE: ok:true with the per-row refusal in it, never
        # an op-level error (which is what the escaping throw produced)
        assert data["ok"] is True
        assert data["rows"] == []
        assert len(data["failed"]) == 1
        assert data["failed"][0].startswith("wp_options[30] (refused: ")
        assert "work budget" in data["failed"][0]
        # the process is still ALIVE and serving (a fatal would have taken
        # the server with it, and this is the whole point)
        assert env.call("media_rewrite_refs", {"apply": False}).status_code \
            == 200
    finally:
        env.close()


def test_the_row_refusal_reaches_the_wire_with_its_marker_written_once(
        tmp_path):
    """THE MARKER HAS ONE PRODUCER, measured on the wire.

    ``media_rewrite_apply``'s per-row catch used to prefix ``(refused: …)``
    to the exception text, and every reason that catch carries ALREADY opens
    with the marker — the shape proofs word their refusals that way on
    purpose, so a caller reading a refusal string always finds it.  So the
    deployed bridge answered ``(refused: refused: this value is nested too
    deeply …)`` and the CLIENT had to collapse the duplicate to keep the
    operator from reading one refusal twice.

    The bridge now sends the BARE reason and the client writes the marker
    (wpt/wpbridge/client.py::_refusal_label), so the label on the wire
    carries it exactly once — the same operator-facing text as before, from
    one producer instead of two.  The fixture is the work-budget throw the
    test above builds: the smallest value that reaches the catch."""
    env = _build(tmp_path)
    try:
        scan(env)
        rows_file = env.docroot / "wpt-stub-ref-rows.json"
        store = json.loads(rows_file.read_text())
        store["wp_options"]["30"] = {
            "option_id": "30", "option_name": "deep", "autoload": "no",
            "option_value": nested_arrays(_shape_work_budget() + 1),
        }
        rows_file.write_text(json.dumps(store))
        data = env.call("media_rewrite_refs", {
            "apply": True,
            "mapping": {"2023/10/pic.jpg": "2023/10/pic.webp"},
            "rows": [{"table": "wp_options", "key": "option_id", "id": 30}],
        }).json()
        assert data["ok"] is True and len(data["failed"]) == 1, data
        label = data["failed"][0]
        assert label.count("refused:") == 1, (
            f"the wire label carries the marker more than once: {label!r}")
        # the reason is the throw's OWN text, unmarked-but-for-its-vocabulary
        assert label.startswith("wp_options[30] (refused: this value is "
                                "nested too deeply"), label
        # ... and the client renders exactly what it renders, once
        from wpt.wpbridge.client import _refusal_label

        assert _refusal_label(label) == label
    finally:
        env.close()


def test_the_client_depth_bound_and_the_server_proof_budget_agree():
    """[C, residual 2] ONE number, one owner: the two depth bounds are told
    apart, and the disagreement is pinned.

    Two numbers exist and they are NOT the same fact, which is why they
    used to look like one disagreeing mirror:

    * ``wpt.media_refs._MAX_DEPTH`` is PHP's OWN nesting limit, the bound
      under which this decoder still reads a stored value.  It is a
      KEEP-SET bound: a value deeper than it is a map the live half reads
      and this half refuses, so every registered size of that attachment is
      lost offline and becomes a deletion candidate.  Lowering it to the
      server's number would trade a false refusal for real data loss, and
      it would not even stop the row from being sent (the SHAPE PROOF
      refuses it, not the transport).
    * ``WPT_MEDIA_SHAPE_WORK_BUDGET`` is the deployed proof's WORK budget
      in levels opened, and a value past it is refused BY NAME on the
      per-row ``failed[]`` channel.

    So the client does send a value 1025..4096 deep and the server refuses
    that row; both halves are correct and neither mirror is a lie, provided
    the two facts are not confused.  This test is the pin: the PHP number
    is read from bridge.php itself (its one owner) and the Python one from
    the module, the band between them is asserted to exist, and both are
    checked against the two facts they must be (PHP's own limit, and a
    quarter of it).
    """
    from wpt.media_refs import _MAX_DEPTH

    budget = _shape_work_budget()
    assert budget < _MAX_DEPTH, (
        "the proof's work budget must stay under the depth this decoder "
        "reads, or the client would refuse rows the server accepts")
    # the band exists, and a value in it is READ here and REFUSED there
    assert _MAX_DEPTH - budget > 0
    # each is the fact it claims to be: PHP's own limit is 4096 (measured
    # on the PHP 8.4 CLI — see wpt/media_refs.py), and the budget is a
    # quarter of it
    assert _MAX_DEPTH == 4096
    assert budget * 4 == _MAX_DEPTH


def test_R15_users_reset_skips_an_invalid_utf8_login_before_any_write(bridge):
    """R15-P1-3: one latin-1 login byte must never be published as a
    SUBSTITUTED login while its old password is revoked.  The invalid row is
    skipped before the first setter, named by ID in ``skipped``, and the
    valid users still reset (with their live credential returned)."""
    (bridge.docroot / "wpt-stub-user-invalid-utf8").write_text("")
    before = len(bridge.calls())
    data = bridge.call("users_reset", {"apply": True}).json()

    assert data["ok"] is True
    results = data["results"]
    assert results["skipped"] == [
        {"id": 1, "reason": "user_login is not valid UTF-8"}]
    rows = results["users"]
    assert [row["login"] for row in rows] == ["editor", "author"]
    assert results["count"] == 2
    assert "admin" not in json.dumps(rows)
    calls = bridge.calls()[before:]
    # The invalid user's old password was NEVER touched; the valid users'
    # passwords were set and proven live.
    assert "wp_set_password:1" not in calls
    assert "user_pass_check:1:match" not in calls
    assert "wp_set_password:2" in calls
    assert "wp_set_password:7" in calls
    assert "user_pass_check:2:match" in calls
    assert "user_pass_check:7:match" in calls
    assert all(row["password"].startswith("wpt-stub-pw-") for row in rows)


def test_R15_users_reset_targeting_an_invalid_utf8_login_refuses_before_write(
        bridge):
    """The targeted path is fail-closed: a login that only exists on an
    invalid-UTF-8 row is refused whole (nothing reset), never matched and
    published under a substituted spelling."""
    (bridge.docroot / "wpt-stub-user-invalid-utf8").write_text("")
    before = len(bridge.calls())
    data = bridge.call("users_reset", {
        "apply": True, "logins": ["admin\udcff"],
    }).json()

    assert data["ok"] is False
    # The wire cannot even carry the invalid login (PHP rejects the
    # surrogate escape), so the handler never runs and nothing is reset.
    calls = bridge.calls()[before:]
    assert not [call for call in calls if call.startswith("wp_set_password:")]


def test_R14_user_create_invalid_utf8_keeps_the_live_credential(bridge):
    """The same envelope owner: a created account whose read-back carries
    an invalid byte still returns the generated password."""
    (bridge.docroot / "wpt-stub-user-invalid-utf8").write_text("")
    data = bridge.call("user_create", {
        "apply": True, "login": "newadmin", "email": "new@example.test",
        "role": "administrator",
    }).json()

    assert data["ok"] is True
    user = data["results"]["user"]
    assert user["login"] == "newadmin"
    assert user["email"].startswith("new@example.test")
    password = user["password"]
    assert password.startswith("wpt-stub-pw-")
    assert any(
        call.startswith("user_pass_set:")
        and call.endswith(hashlib.md5(password.encode()).hexdigest())
        for call in bridge.calls())


def test_R21_info_merges_a_loaded_active_plugin_missing_from_get_plugins(
        bridge):
    """R21-P1: WordPress loads an active_plugins file that EXISTS even when
    get_plugins() cannot read its header; the inventory omitted it, so
    clean-files saw the loaded unit as inactive.  info now merges every
    raw active entry as ACTIVE with empty name/version."""
    _seed_active_plugins(
        bridge,
        "akismet/akismet.php",
        "headerless/headerless.php",
    )
    data = bridge.call("info").json()
    assert data["ok"] is True
    assert data["plugins"]["headerless/headerless.php"] == {
        "name": "", "version": "", "active": True,
    }
    # A header-bearing entry keeps its real inventory and active flag.
    assert data["plugins"]["akismet/akismet.php"]["active"] is True


def test_R21_user_create_returns_the_live_credential_when_readback_is_false(
        bridge):
    """R21-P1: after wp_insert_user wrote the row and a user_register hook
    threw, a captured id whose get_userdata() returned FALSE was silently
    discarded (only a THROWING read set recovery_error), so the op rethrew
    into the global envelope and lost the live generated password."""
    (bridge.docroot / "wpt-stub-insert-throws-after").write_text("")
    (bridge.docroot / "wpt-stub-user-readback-fails").write_text("")
    data = bridge.call("user_create", {
        "apply": True, "login": "newadmin", "email": "new@example.test",
        "role": "administrator",
    }).json()

    assert data["ok"] is False
    assert data["created"] is True
    assert "recovery read failed" in data["error"]
    user = data["results"]["user"]
    assert user["login"] == "newadmin"
    assert user["password"].startswith("wpt-stub-pw-")
    assert any(c.startswith("wp_insert_user:")
               for c in bridge.calls())
