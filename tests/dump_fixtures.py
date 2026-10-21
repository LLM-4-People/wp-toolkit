"""The ``--sql`` DUMP fixture every cross-mode witness test needs — one
builder, shared by the two media actions that gate on it.

The witness (:mod:`wpt.actions.dump_witness`) asks a dump FIVE structural
questions, and three of them are about the dump's relation to the LIVE
schema: it must declare every table the site has, and it must not be
materially behind the live row counts of the tables the reference set is
read from.  A fixture that declared only the two tables a test happens to
read would therefore be refused for declaring none of the live
``wp_commentmeta`` — correct behaviour, useless fixture — so the builder
here writes a dump shaped like a real ``mysqldump`` of a small WordPress
site: the whole core table set, with a realistic number of rows in each and
none of the filler naming a media file.

:func:`make_dump` is the ONE place that knows the shape.  ``rows=`` models
a dump taken before the site's content was written (the "behind" case),
``tables=`` models one that predates a table, dropping ``trailer`` models a
transfer that was cut short, and the ``*_SCHEMA`` tuples model the tables a
REAL plugin adds beside the core ones — ``wp_aioseo_posts`` and
``wp_edd_postmeta`` (whose names end in a core role) and ``aioseo_options``
/ ``aioseo_termmeta`` / ``wp_aioseo_options`` / ``wp_edd_termmeta`` (whose
columns make them CONTEST a core role).  Both families end in a real defect
and neither may be resolved by name order.
"""

from __future__ import annotations

from pathlib import Path

__all__ = ["AIOSEO_OPTIONS_SCHEMA", "AIOSEO_POSTS_SCHEMA",
           "AIOSEO_TERMMETA_SCHEMA", "CORE_SCHEMA", "DECOY_POSTMETA_SCHEMA",
           "EDD_TERMMETA_SCHEMA", "LIVE_ROWS", "DUMP_TRAILER",
           "PLUGIN_ROWS", "WP_AIOSEO_OPTIONS_SCHEMA", "make_dump"]

#: mysqldump's completion trailer — the structural signal a whole dump
#: carries and a cut-off transfer does not.
DUMP_TRAILER = "\n-- Dump completed on 2024-01-01 21:04:11\n"

#: The core table set a real ``mysqldump`` of this site declares: the table
#: name, its CREATE columns, and a FILLER row template (every value a
#: non-media row of that table really holds).
CORE_SCHEMA = (
    ("wp_commentmeta",
     "`meta_id` text, `comment_ID` text, `meta_key` text, "
     "`meta_value` text", "%d,10,'_edit_comment','10'"),
    ("wp_options",
     "`option_id` text, `option_name` text, `option_value` text, "
     "`autoload` text", "%d,'row-%d','x','yes'"),
    ("wp_postmeta",
     "`meta_id` text, `post_id` text, `meta_key` text, "
     "`meta_value` text", "%d,10,'_edit_lock','10'"),
    ("wp_posts",
     "`ID` text, `post_type` text, `post_status` text, `post_content` text,"
     " `post_excerpt` text, `post_guid` text",
     "%d,'page','publish','an ordinary page','','https://example.com/?p=%d'"),
    ("wp_term_relationships",
     "`object_id` text, `term_taxonomy_id` text, `term_order` text",
     "%d,1,'0'"),
    ("wp_termmeta",
     "`meta_id` text, `term_id` text, `meta_key` text, `meta_value` text",
     "%d,1,'_edit_term','1'"),
)

#: The live row counts the ``db_audit`` fixtures report — the other half of
#: the witness' currency comparison, so they are REALISTIC: a WordPress site
#: has hundreds of options and thousands of meta rows, and a fixture
#: reporting "10 rows in wp_options" would let a dump holding ONE option row
#: pass a check it must fail.  :func:`make_dump` writes exactly this many
#: rows per table by default (a dump taken before the run carries at least
#: what the live tables do).
LIVE_ROWS = {
    "wp_commentmeta": 4,
    "wp_options": 12,
    "wp_postmeta": 60,
    "wp_posts": 24,
    "wp_term_relationships": 18,
    "wp_termmeta": 6,
}

#: A PLUGIN's own table whose name merely ENDS in the core role's suffix, in
#: the ``CORE_SCHEMA`` tuple shape so a test can pass
#: ``tables=CORE_SCHEMA + (AIOSEO_POSTS_SCHEMA,)``.
#:
#: ``wp_aioseo_posts`` is a REAL table — All in One SEO 4.x owns it (SPEC
#: L31 is about exactly that table) — and its name ends in ``posts``.  It is
#: the decoy that made the witness' currency check validate a table the
#: reference set was never read from: resolved by bare suffix (the first
#: name in ``sorted()``) it is chosen over ``wp_posts`` itself, so a dump
#: carrying 40 AIOSEO rows satisfied the check while the core posts table
#: held 2 of the live 80, and the apply proceeded.
AIOSEO_POSTS_SCHEMA = (
    "wp_aioseo_posts",
    "`id` text, `post_id` text, `post_type` text, `post_status` text,"
    " `post_content` text, `post_excerpt` text, `post_guid` text",
    "%d,10,'aioseo_post','publish','a keyword record','excerpt',"
    "'https://example.com/?p=%d'",
)

#: The same shape one role over: a plugin's ``<prefix>postmeta``-suffixed
#: table.  Sorted, ``wp_edd_postmeta`` comes before ``wp_postmeta``, so a
#: suffix-resolved check validated THIS one — and an empty one, which the
#: ``live_rows == 0 -> continue`` branch then skipped entirely, so the real
#: postmeta table was never compared at all.
DECOY_POSTMETA_SCHEMA = (
    "wp_edd_postmeta",
    "`meta_id` text, `post_id` text, `meta_key` text, `meta_value` text",
    "%d,10,'_edd_downloads','0'",
)

#: A PLUGIN's own table that carries the CORE options column pair, in the
#: ``CORE_SCHEMA`` tuple shape: ``aioseo_options`` is a REAL table (All in
#: One SEO 4.x creates it, and it is not even prefixed with the site's).
#:
#: This is the shape that produced a POSITIVE keep-set of ZERO.  Resolved
#: by bare suffix over ``sorted()`` it beat ``wp_options`` (``a`` < ``w``),
#: so the measurement read the plugin's table, found no uploads path in it,
#: and answered "this database references no uploads file" on a dump whose
#: ``wp_postmeta`` named a full set — while the analyzer, resolving the same
#: question in dump order, read ``wp_options`` and warned about
#: ``aioseo_options``.  Two rules, two tables, ONE run.
AIOSEO_OPTIONS_SCHEMA = (
    "aioseo_options",
    "`id` text, `option_name` text, `option_value` text, `added` text",
    "%d,'aioseo_options','a:0:{}','%d'",
)

#: The same contested role with the SITE's prefix on the plugin's table
#: (``wp_aioseo_options``, what a prefixed AIOSEO install creates).  Sorted,
#: it still beats ``wp_options`` — the decoy does not have to be
#: unprefixed to win a ``sorted()`` rule.
WP_AIOSEO_OPTIONS_SCHEMA = (
    "wp_aioseo_options",
    "`id` text, `option_name` text, `option_value` text, `added` text",
    "%d,'aioseo_options','a:0:{}','%d'",
)

#: ``aioseo_termmeta``: AIOSEO 4.x's own term-meta table, carrying the core
#: termmeta column pair.  The residual of the same defect one role over —
#: sorted, it displaced ``wp_termmeta`` and every category image stored
#: there left the keep-set.
AIOSEO_TERMMETA_SCHEMA = (
    "aioseo_termmeta",
    "`meta_id` text, `term_id` text, `meta_key` text, `meta_value` text",
    "%d,1,'_aioseo_term','0'",
)

#: The same, EDD's way: ``wp_edd_termmeta`` (Easy Digital Downloads really
#: ships one, and its name ends in ``termmeta``).
EDD_TERMMETA_SCHEMA = (
    "wp_edd_termmeta",
    "`meta_id` text, `term_id` text, `meta_key` text, `meta_value` text",
    "%d,1,'_edd_downloads','0'",
)


#: The row count a table gets when the caller declares none: a plugin's
#: decoy table is a REAL table with real rows, and a decoy declared with
#: zero rows would be a shape no live site has.  ``rows={table: 0}`` still
#: declares none, for the tests that need exactly that.
PLUGIN_ROWS = 3


def schema_tables(rows=None, tables=CORE_SCHEMA) -> list[str]:
    """The CREATE statements plus one INSERT of ``rows`` filler rows each."""
    counts = dict(LIVE_ROWS)
    counts.update(rows or {})
    out = []
    for table, columns, template in tables:
        out.append(f"CREATE TABLE `{table}` ({columns});\n")
        count = counts.get(table, PLUGIN_ROWS)
        if count <= 0:
            continue
        values = []
        for index in range(count):
            try:
                values.append("(%s)" % (template % (index + 1, index + 1)))
            except TypeError:      # a template with one slot
                values.append("(%s)" % (template % (index + 1)))
        out.append(f"INSERT INTO `{table}` VALUES " + ",".join(values) + ";\n")
    return out


def make_dump(tmp_path, refs=(), name="site.sql", site="https://example.com",
              trailer=True, rows=None, tables=CORE_SCHEMA) -> Path:
    """Write a dump of THIS site's database whose media half is ``refs``.

    ``site`` is what the dump STATES it is (``siteurl``) — another site's,
    for the foreign-witness case.  ``trailer=False`` builds the dump a
    cut-off transfer leaves behind, ``rows={table: n}`` one that PREDATES
    the live schema, and ``tables=`` one that does not declare a table the
    live schema has.
    """
    body = schema_tables(rows, tables)
    body.append("INSERT INTO `wp_options` VALUES "
                f"({LIVE_ROWS['wp_options'] + 1},'siteurl','{site}','yes');\n")
    attachments = [
        f"({LIVE_ROWS['wp_postmeta'] + index + 1},10,'_wp_attached_file',"
        f"'{ref}')"
        for index, ref in enumerate(sorted(refs))
    ]
    if attachments:
        body.append("INSERT INTO `wp_postmeta` VALUES "
                    + ",".join(attachments) + ";\n")
    text = "".join(body)
    if trailer:
        text += DUMP_TRAILER
    path = Path(tmp_path) / name
    path.write_bytes(text.encode())
    return path
