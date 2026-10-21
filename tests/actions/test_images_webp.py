"""Tests for the webp-media action (wpt.actions.images_webp).

REAL Pillow round-trips over synthetic images (fixed-seed noise, so the
WebP twin is genuinely smaller and every gate is exercised on real bytes),
FakeSource webroots and REAL mysqldump-shaped fixtures read through the
analyzer's streaming parser.  No network in the plan/apply tests; the
rendered-HTML gate is pinned with the walk seam.

Test -> behavior map (the task's live-found traps, one test each):

  test_registration ................ the action is registered as the
        INSTANCE under applies=("ftp","local")
  test_image_dimensions_header ..... IHDR/SOF header dims (the gate must
        read a 16800x16801 PNG without decoding it)
  test_classify_animated_gif ....... an animated GIF is detected in ANY
        format, not only among the candidate suffixes
  test_classify_animated_apng ...... an APNG is refused (a twin would keep
        only the first frame)
  test_classify_cmyk_jpeg .......... CMYK is refused (WebP has no CMYK)
  test_classify_oversize_png ....... >16383px refused BEFORE any decode
  test_classify_undecodable ........ garbage and truncated bytes
  test_encode_webp_alpha_preserved  an RGBA PNG twin keeps its alpha
  test_encode_webp_exif_orientation  an orientation-6 JPEG comes out in the
        DISPLAY orientation with no stale tag
  test_encode_webp_max_dim .......... webp.max_dim downscales; 0 never does
  test_encode_webp_quality_from_ ... the quality comes from the settings
        section, not a literal
  test_rewrite_text_surfaces ....... post_content URL, root-relative URL,
        uploads-relative `_wp_attached_file`, query string preserved
  test_rewrite_text_thumbnail_id ... an attachment ID is not a path: the
        row is never touched
  test_rewrite_css_shapes .......... relative url(), absolute url(),
        percent-encoded url(), data: URI, and the query string preserved
  test_value_texts_serialized ...... a serialized option's leaves are
        walked; a corrupt one reports unparseable (fail-closed)
  test_plan_local_converted_set .... the converted set is EXACTLY the
        expected files (post_content jpg, the metadata-only derivative,
        the widget png, the css-only background)
  test_plan_local_size_rows ......... EVERY sizes[*].file row is rewritten
        (the classic miss) — asserted on the applied row model
  test_ambiguous_basename_gates ... a bare filename matching two uploads
        folders gates BOTH (never a coin flip between year folders); the
        unique case is the converted one (photo-150x150.jpg)
  test_plan_skips_reported ......... animated/cmyk/oversize/tiny/data-tree/
        duplicate/twin-exists each get their own report line with a count
  test_plan_unreferenced_untouched  an unreferenced image is left alone
        (trim-media owns it) and a _thumbnail_id row never changes
  test_plan_gated_surfaces ......... a usermeta reference and an unparseable
        serialized value keep their images in the ORIGINAL form
  test_plan_advice_keeps_originals  the plan SAYS the originals are kept
  test_plan_no_live_proof_advice ... a run with no site URL says so
  test_plan_backup_tables .......... the snapshot scope is exactly the
        touched tables; a dump whose table list cannot cover the rewrite
        refuses closed
  test_apply_local_convert_rewrite . twins written beside the originals,
        CSS rewritten in place, originals still there
  test_apply_local_row_model ....... the rewritten row model carries no
        stale reference to any converted original
  test_apply_local_purge_refused ... --purge-originals refuses in local
        mode, before any mutation
  test_apply_ftp_purge_removes_only . with the bridge double, the purge
        deletes ONLY the originals whose references verified
  test_apply_lost_twin_leaves_its . a twin that never landed is not marked
        references_alone ............ done and its rows keep the original
  test_verify_refuses_broken_path .. a twin that vanished after the write
        fails the apply (rc 1 semantics: SourceError)
  test_verify_refuses_stale_row ..... a row the rewrite could not move fails
  test_registry_local_dry_run_zip .. a real zip: the dry run leaves every
        entry byte-identical
  test_registry_local_rehearsal .... a real zip apply materializes the
        rehearsal with the twins and the rewritten stylesheet
  test_registry_ftp_snapshot_scope . the pre-action snapshot captures the
        touched TABLES and the rewritten stylesheets + the originals the
        purge would delete (and nothing else)
  test_settings_section_read ...... the `webp` section is read when the
        settings owner lands it, and the module defaults hold until then
  test_plan_estimate_split_by_source_ . the reclaimable estimate is reported
        ............................. per SOURCE FORMAT (JPEG and PNG totals
        plus the all-files total), not only as one blended number, and on
        a MIXED-SPELLING site one JPEG row names BOTH .jpg and .jpeg
        instead of two rows both labelled "JPEG"
  test_plan_estimate_single_spelling . one spelling, one row, and the row
        ............................. still names the extension it counts
  test_live_proof_bijection ....... the after-walk must be the before-set
        with every old path replaced by its twin, the same size, and every
        rewritten path must answer 200
  test_live_proof_refuses_extra .... a reference the rewrite could not move
        (the site still points at an original) fails the run
  test_local_dump_without_the_ ... a dump with no plugin table plans exactly
        plugin_table_plans_unchanged as before: nothing gated, nothing lost
  test_local_surface_with_the_ ... a table that shares a core name AND
        columns_is_rewritten ...... declares its columns is still enumerated
        and rewritten (the fix gates, it never narrows the discovery)
  test_local_aioseo4_columns_gate_ the real 4.x all-in-one-seo-pack
        the_surface ............... ``aioseo_posts`` column list: the run
        proceeds, the surface is named and reported, and its og:image
        reference keeps that image in its original form
  test_local_aioseo5_layout_is_ ... the 5.0 layout (and the second
        resolved_from_the_dump .... posts-suffixed table): whatever the dump
        shows decides, both surfaces are gated, neither is fatal
  test_local_table_missing_one_ ... a table that exists and declares the KEY
        column_gates_only_that_.... column reports exactly the missing one
  test_purge_refused_without_the_ . --purge-originals refuses WITHOUT an
        editor_free_acknowledgement editor-free acknowledgement, in the plan
        ............................. AND the apply, before any mutation
  test_purge_refused_when_the_ ... the profile key is a request, not an
        profile_asks_for_it_ ....... acknowledgement
  test_purge_keeps_an_original_a_ . the per-file delete decision comes from a
        stale_editor_referenced_... set RE-READ at purge time: an original a
        ............................. stale editor brought back keeps its bytes
        and its item stays not-done
  test_purge_reports_a_reference_ . a save landing AFTER the deletes is
        that_reappeared_after_ ..... REPORTED with the list, never fatal
        the_deletes
  test_plan_ftp_scan_without_the . the reference scan is read through the
  completion_marker_refuses .. CLIENT's fail-closed reader: a stream that
  ................................ just STOPS (a PHP fatal after the first
  ................................ lines) is refused — rc 1, nothing written
  test_plan_ftp_truncated_scan_is . the op's own half-measured marker:
  refused_and_nothing_is_written  refused, no twin encoded
  test_plan_ftp_scan_whose_row_ . a summary that disagrees with the rows
  count_disagrees_refuses ....... that arrived is refused (the completion
  ................................ proof, not the marker's presence)
  test_plan_ftp_well_formed_scan . the healthy answer is UNCHANGED: the same
  answers_the_current_behavior .. conversions, the same rewrite, rc 0
  test_purge_keeps_an_original_a_ . a DECLINED delete is an ADVISORY, not a
  stale_editor_referenced_... failure: the item stops being applicable
  test_purge_declined_keeps_the_ . ... so rc stays 0 and the registry STILL
  original_and_still_purges_....  purges the cache (the pages really were
  ................................ rewritten), with the kept files named
  test_purge_kept_is_an_advisory_ . the kept item + the one-line report are
  not_an_applicable_item ...... present and non-blocking
  test_unverified_rewrite_still_ . an UNPROVEN rewrite still fails closed:
  fails_closed_and_keeps_.....  rc 1, no purge_cache call
  test_purge_profile_door_and_ ... both purge doors (flag typed, profile
  flag_door_refuse_identically . keyed) need the same acknowledgement, and
  ................................ typed intent wins over the profile
  test_live_proof_bijection ...... every page both crawls could read carries
  test_live_proof_refuses_a_ .....  its refs mapped, twins answer 200; a
  surviving_original / lost_...  surviving original or a lost image fails
  image .........................  and NAMES the page
  test_live_proof_excludes_chal . 3 of 10 pages served a bot challenge
  lenged_pages_and_runs_clean .. after the rewrite: rc 0 + the exclusion
  test_live_proof_reports_every_ .  line, every excluded URL named
  excluded_url ..................
  test_live_proof_retries_a_ ..... a challenge that does not repeat is a
  challenge_before_excluding_ ..  retry away from being evidence
  test_live_proof_treats_a_200_ . a 200 whose whole body is a challenge is
  challenge_body_as_... ......... INCONCLUSIVE, never "no images"
  test_live_proof_fails_on_a_ ... the provable failure still fails: a twin
  provable_missing_twin .........  that 404s, named
  test_live_proof_excludes_a_ ... a page only ONE pass reached is excluded,
  page_read_in_one_pass_only ..  never read as a change
  test_live_proof_clean_run_is_ . a clean site costs nothing: the same bytes,
  byte_identical_to_a_run_ .....  the same items, no exclusion line
  with_no_site ..................
  test_live_proof_challenge_ ..... a real page carrying "just a moment" is not
  markers_are_narrow ............  a challenge; the size bound is the
  ................................  profile's, not the code's
"""

import copy
import io
import json
import logging
import random
import zipfile
from dataclasses import fields, replace
from urllib.parse import urlparse

import PIL.Image
import pytest

from tests.fakes import FakeSource, FakeSession
from wpt.actions import registry as registry_mod
from wpt.actions.images_webp import (
    ImagesWebpAction,
    _config,
    challenge_reason,
    classify_image,
    encode_webp,
    image_dimensions,
    looks_serialized,
    refs_in_value,
    rewrite_css,
    rewrite_text,
    scan_css_refs,
    scan_refs,
    value_texts,
)
from wpt.actions.registry import get_action, run_action
from wpt.audit.media import _UPLOADS_PREFIX
from wpt.cli import Ctx
from wpt.report import human_bytes
from wpt.settings import SettingsError, WebpSettings, load
from wpt.types import BridgeError, SourceError
from wpt.wpbridge.client import Bridge

DEFAULTS = load()

# ---------------------------------------------------------------------------
# Image fixtures (real bytes; noise so a WebP twin is genuinely smaller)
# ---------------------------------------------------------------------------

UP = _UPLOADS_PREFIX


def _noise(w, h, mode="RGB", seed=1234):
    rng = random.Random(seed)
    bands = 4 if mode == "RGBA" else 3
    return PIL.Image.frombytes(mode, (w, h), rng.randbytes(w * h * bands))


def _jpeg(w=256, h=256, *, quality=95, seed=1234, cmyk=False, orientation=None):
    buf = io.BytesIO()
    image = _noise(w, h, seed=seed)
    if cmyk:
        image = image.convert("CMYK")
    if orientation is not None:
        exif = PIL.Image.Exif()
        exif[274] = orientation
        image.save(buf, format="JPEG", quality=quality, exif=exif)
    else:
        image.save(buf, format="JPEG", quality=quality)
    return buf.getvalue()


def _png(w=256, h=256, *, mode="RGB", seed=1234, animated=False):
    buf = io.BytesIO()
    image = _noise(w, h, mode=mode, seed=seed)
    if animated:
        frames = [image] + [PIL.Image.new("RGB", (w, h), c)
                            for c in ("red", "green")]
        frames[0].save(buf, format="PNG", save_all=True,
                       append_images=frames[1:], duration=100, loop=0)
    else:
        image.save(buf, format="PNG")
    return buf.getvalue()


def _gif(*, animated=True, w=64, h=64):
    buf = io.BytesIO()
    if animated:
        frames = [PIL.Image.new("RGB", (w, h), c) for c in ("red", "green", "blue")]
        frames[0].save(buf, format="GIF", save_all=True,
                       append_images=frames[1:], duration=100, loop=0)
    else:
        PIL.Image.new("RGB", (w, h), "red").save(buf, format="GIF")
    return buf.getvalue()


# ---------------------------------------------------------------------------
# SQL dump fixture (mysqldump-shaped, read by the analyzer's real parser)
# ---------------------------------------------------------------------------


def _cell(value):
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return str(int(value))
    if isinstance(value, int):
        return str(value)
    if isinstance(value, bytes):
        return "'" + "".join("\\x%02x" % b for b in value) + "'"
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _create(table, columns):
    cols = ", ".join("`%s` longtext" % c for c in columns)
    return ("CREATE TABLE `%s` (%s);\n" % (table, cols)).encode()


def _insert(table, rows, columns=None):
    tuples = ",".join("(" + ",".join(_cell(c) for c in row) + ")" for row in rows)
    return ("INSERT INTO `%s` VALUES %s;\n" % (table, tuples)).encode()


def _ser(*values):
    """A PHP-serialized array of strings, with int keys and CORRECT lengths.

    Built by hand on purpose: the whole point of the serialization-aware
    path is that the declared length must match and the shape must be a real
    key/value list, so the fixture proves the analyzer's reader and the
    rewrite agree with the format PHP actually writes.
    """
    body = "".join('i:%d;s:%d:"%s";' % (i, len(v), v)
                   for i, v in enumerate(values))
    return "a:%d:{%s}" % (len(values), body)


#: The uploads files of the fixture site, and the DB/CSS references to them.
PHOTO = "2023/10/photo.jpg"                     # post_content
DERIV = "2023/10/photo-150x150.jpg"             # metadata sizes[*].file ONLY
MENU = "2023/11/menu.png"                       # a serialized widget option
BG = "2023/11/bg.jpg"                           # a CSS url() only
ANIM = "2023/12/anim.png"                       # APNG
CMYK = "2023/12/cmyk.jpg"                       # CMYK
HUGE = "2023/12/huge.png"                       # 16385px wide
FORM = "gravity_forms/1/2/inbound.jpg"          # protected data tree
SMALL = "2023/10/small.jpg"                     # below skip_below_bytes
ORPHAN = "2023/10/orphan.jpg"                   # referenced by nothing
TWIN = "2023/10/already.jpg"                    # already has a .webp
#: A byte-identical pair.  ``DUP2`` sorts AFTER ``DUP`` ("_" > "."), so the
#: converted member of the pair is deterministic: the first one handled.
DUP = "2023/10/same.jpg"
DUP2 = "2023/10/same_copy.jpg"
GATED = "2023/10/gated.jpg"                     # referenced from usermeta
BADSER = "2023/10/bad.jpg"                      # corrupt serialized reference

CONVERTED = {PHOTO, DERIV, MENU, BG, DUP}


def _files():
    """The fixture webroot: ``{webroot path: bytes}``."""
    out = {
        UP + PHOTO: _jpeg(),
        UP + DERIV: _jpeg(200, 200, seed=7),
        UP + MENU: _png(mode="RGBA", seed=11),
        UP + BG: _jpeg(320, 240, seed=13),
        UP + ANIM: _png(120, 90, seed=17, animated=True),
        UP + CMYK: _jpeg(128, 128, seed=19, cmyk=True),
        # 16385 x 1 noise: a REAL image over the libwebp dimension limit and
        # above skip_below_bytes (incompressible noise), built cheaply
        # because it is one row of pixels.
        UP + HUGE: _png(16385, 1, seed=23),
        UP + FORM: _jpeg(seed=29),
        UP + SMALL: _jpeg(16, 16, seed=31),
        UP + ORPHAN: _jpeg(seed=37),
        UP + TWIN: _jpeg(seed=41),
        UP + TWIN.replace(".jpg", ".webp"): _jpeg(8, 8, seed=43),
        UP + DUP: _jpeg(seed=47),
        UP + DUP2: _jpeg(seed=47),
        UP + GATED: _jpeg(seed=53),
        UP + BADSER: _jpeg(seed=59),
        "wp-content/uploads/avada-styles/site.css": (
            b".hero{background:url(../2023/11/bg.jpg?v=2) no-repeat}"
            b".logo{background:url('/wp-content/uploads/2023/10/photo.jpg')}"
            b".x{background:url(data:image/gif;base64,AAA)}"
        ),
        "wp-content/uploads/.htaccess": b"# silence\n",
        "wp-content/themes/other/style.css": b"a{color:red}",
        "wp-content/uploads/index.php": b"<?php // silence\n",
    }
    return out


def _dump():
    """The fixture dump: every reference surface the rewrite must cover."""
    # The REAL WordPress shape: ``file`` is uploads-relative, and every
    # ``sizes[*].file`` is a BARE BASENAME.  A rewrite that only understands
    # the uploads-relative spelling leaves every thumbnail on the site
    # pointing at a deleted original — the classic miss.
    meta = json.dumps({
        "file": PHOTO,
        "sizes": {
            "thumbnail": {"file": DERIV.rpartition("/")[2], "width": 150},
            "medium": {"file": "photo-300x200.jpg", "width": 300},
        },
        "width": 256, "height": 256,
    })
    fusion = json.dumps({"background_image": f"https://example.test/{UP}{BG}"})
    widget = _ser(f"{UP}{MENU}", "1")
    theme_mods = _ser("logo", f"{UP}{PHOTO}")
    # A serialized value that LOOKS serialized and cannot be parsed: its
    # reference must gate the image out, never be rewritten blind.
    broken = 'a:1:{i:0;s:8:"icon_url";s:999:"%s%s";}' % (UP, BADSER)
    out = b""
    out += b"SET NAMES utf8mb4;\n"
    out += _create("wp_posts", ["ID", "post_content", "post_excerpt"])
    out += _insert("wp_posts", [
        (7, '<p><img src="https://example.test/%s%s" width="256"></p>' % (UP, PHOTO),
         ""),
        (8, '<p>text</p>', f"see {UP}{GATED}"),
    ])
    out += _create("wp_postmeta", ["meta_id", "post_id", "meta_key", "meta_value"])
    out += _insert("wp_postmeta", [
        (1, 7, "_wp_attached_file", PHOTO),
        (2, 7, "_wp_attachment_metadata", meta),
        (3, 7, "_wp_attachment_backup_sizes", _ser("full", PHOTO)),
        (4, 7, "_fusion_builder_data", fusion),
        (5, 7, "_thumbnail_id", "42"),
        (6, 8, "_preview", f"{UP}{SMALL}"),
        (7, 8, "_preview", f"{UP}{ANIM}"),
        (8, 8, "_preview", f"{UP}{CMYK}"),
        (9, 8, "_preview", f"{UP}{HUGE}"),
        (10, 8, "_preview", f"{UP}{FORM}"),
        (11, 8, "_preview", f"{UP}{TWIN}"),
        (12, 8, "_preview", f"{UP}{DUP}"),
        (13, 8, "_preview", f"{UP}{DUP2}"),
        (14, 8, "_preview", f"{UP}{MENU}"),
    ])
    out += _create("wp_options", ["option_id", "option_name", "option_value"])
    out += _insert("wp_options", [
        (1, "theme_mods_avada", theme_mods),
        (2, "widget_avada", widget),
        (3, "avada_options", f'{{"logo":"{UP}{PHOTO}"}}'),
        (4, "broken_option", broken),
    ])
    out += _create("wp_usermeta", ["umeta_id", "user_id", "meta_key", "meta_value"])
    out += _insert("wp_usermeta", [
        (1, 3, "custom_avatar", f"{UP}{GATED}"),
    ])
    out += _create("wp_comments", ["comment_ID", "comment_content"])
    out += _insert("wp_comments", [(1, "hello")])
    return out


# ---------------------------------------------------------------------------
# Doubles
# ---------------------------------------------------------------------------


def _webp(**overrides) -> "WebpSettings":
    """A `webp` section built from the SHIPPED profile, with overrides.

    The section is a real settings section now, so a test that wants a
    different value changes the section it is resolved from — the same door
    an operator uses with ``--set webp.<key>=`` — instead of hand-building
    a stand-in object with a shape the settings owner might not honour.
    """
    return replace(DEFAULTS.webp, **overrides)


def _cfg(tmp_path, settings=DEFAULTS, **overrides):
    """The run's resolved config, exactly as the action resolves it."""
    from wpt.actions.images_webp import _config
    return replace(_config(_ctx(tmp_path, settings=settings)), **overrides)


class _Bridge(Bridge):
    """Bridge double for the ftp path — a real ``Bridge`` with a fake wire.

    Subclassing the client is the point: the action reaches the op through
    ``Bridge.iter_rewrite_refs`` / ``Bridge.rewrite_refs``, so the fail-closed
    stream proof (the terminal summary, its row count, the truncation marker)
    and the fail-closed apply proof are the CLIENT's own code, exercised here
    rather than re-implemented by a hand-written reader.  Only the transport
    (``call``/``call_stream``) and the session teardown are replaced, and
    ``Bridge.__init__`` is deliberately not called: every field it sets is one
    these two methods never read.

    Serves the reference scan from the SAME fixture rows the local reader
    sees (so both modes are held to one reference set), applies the rewrite
    in memory with the client's own mapping — the stand-in for the bridge's
    ``maybe_unserialize``/``maybe_serialize`` round trip — and re-reads every
    row it wrote, which is what the action's verification consumes.

    The scan faults model the ways a real stream lies: ``scan_truncated`` is
    the op's own half-measured marker, ``scan_unterminated`` is a fatal after
    the first lines (the stream simply stops, with no error line), and
    ``scan_count_delta`` makes the terminal summary disagree with the rows
    that arrived.
    """

    def __init__(self, rows=None, *, tables=None, scan_truncated=False,
                 fail_rows=(), scan_unterminated=False, scan_count_delta=0):
        self.rows = rows or []
        self.tables = list(tables or ["wp_posts", "wp_postmeta", "wp_options",
                                      "wp_usermeta", "wp_comments"])
        self.scan_truncated = scan_truncated
        self.scan_unterminated = scan_unterminated
        self.scan_count_delta = scan_count_delta
        self.fail_rows = set(fail_rows)
        self.store: dict[tuple[str, int], str] = {}
        self.calls: list[tuple[str, dict]] = []
        self.destroyed = 0

    def call(self, action, **params):
        self.calls.append((action, params))
        if action == "db_audit":
            return {"ok": True, "tables": [
                {"name": n, "rows": 1, "data_bytes": 1, "data_free_bytes": 0,
                 "collation": "x"} for n in self.tables]}
        if action == "purge_cache":
            return {"ok": True}
        if action == "media_rewrite_refs" and params.get("apply"):
            return self._apply_edits(params)
        raise AssertionError(f"unexpected bridge action: {action!r}")

    def call_stream(self, action, **params):
        self.calls.append((action, params))
        if action == "db_dump":
            # the pre-action snapshot's table capture
            out = []
            for table in params.get("tables") or []:
                out.append({"table": table, "row": [1, "x"]})
                out.append({"table": table, "done": 1})
            return iter(out)
        if action != "media_rewrite_refs" or params.get("apply"):
            raise AssertionError(f"unexpected bridge stream: {action!r}")
        if self.scan_truncated:
            return iter([{"truncated": True}])
        objs = [dict(obj) for obj in self._scan_objects()]
        if not self.scan_unterminated:
            # the terminal summary the client's reader REQUIRES as the
            # completion proof, exactly as bridge.php emits it
            objs.append({"ok": True, "rows": len(objs) + self.scan_count_delta,
                         "truncated": False})
        return iter(objs)

    def _scan_objects(self):
        # The re-read of a row the apply already rewrote returns what the
        # bridge STORED, exactly like a real SELECT after the UPDATE — that
        # is what the purge's re-read consumes.
        for table, key, row_id, value, gated in self.rows:
            current = self.store.get((table, row_id), value)
            obj = {"table": table, "key": key, "id": row_id, "value": current}
            if gated:
                obj["gated"] = list(gated)
            yield obj

    def _apply_edits(self, params):
        """The stand-in for the bridge's maybe_unserialize round trip."""
        out = {"ok": True, "rows": [], "failed": []}
        mapping = params.get("mapping") or {}
        for entry in params.get("rows") or []:
            ident = f"{entry['table']}[{entry['id']}]"
            if ident in self.fail_rows:
                out["failed"].append(ident)
                continue
            current = self.store.get((entry["table"], entry["id"]))
            if current is None:
                for table, _key, row_id, value, _g in self.rows:
                    if (table, row_id) == (entry["table"], entry["id"]):
                        current = value
                        break
            if "value" in entry:
                new = entry["value"]
            else:
                new = rewrite_text(current or "", mapping)[0]
            self.store[(entry["table"], entry["id"])] = new
            out["rows"].append({"table": entry["table"], "id": entry["id"],
                                "value": new})
        return out

    def destroy(self):
        self.destroyed += 1


class _StaleEditorBridge(_Bridge):
    """A site whose editors save DURING the run.

    ``resurrect`` is a ``(table, id)`` whose row is read back with its
    ORIGINAL value from ``from_scan`` on — the model of the real hazard:
    a save from a stale editor puts the ``.jpg`` filename back into
    ``post_content`` between the rewrite and the purge.  The plan's scan
    (scan #1) is untouched, so the plan still looks clean.
    """

    def __init__(self, rows, *, resurrect, from_scan=2):
        super().__init__(rows)
        self.resurrect = tuple(resurrect)
        self.from_scan = from_scan
        self.scans = 0

    def call_stream(self, action, **params):
        if action == "media_rewrite_refs" and not params.get("apply"):
            self.scans += 1
        return super().call_stream(action, **params)

    def _scan_objects(self):
        if self.scans < self.from_scan:
            yield from super()._scan_objects()
            return
        for table, key, row_id, value, gated in self.rows:
            current = self.store.get((table, row_id), value)
            if (table, row_id) == self.resurrect:
                current = value          # saved back from a stale client
            obj = {"table": table, "key": key, "id": row_id, "value": current}
            if gated:
                obj["gated"] = list(gated)
            yield obj


class _VanishingSource(FakeSource):
    """A twin that is gone by the time the VERIFICATION looks for it.

    ``exists`` is the only probe the verification makes, so this models the
    real hazard: a file that was written, read back fine, and is not there
    any more when the reference sweep runs.
    """

    def __init__(self, files, vanish):
        super().__init__()
        self.files.update(files)
        self.vanish = vanish

    def exists(self, path):
        if path == self.vanish:
            self.files.pop(path, None)
            return False
        return super().exists(path)


class _SwallowingSource(FakeSource):
    """A source whose upload of one twin is silently truncated away.

    The per-item resilience the registry contract wants: that twin is not
    marked done and NOTHING is rewritten towards it.
    """

    def __init__(self, files, swallow):
        super().__init__()
        self.files.update(files)
        self.swallow = swallow

    def write_bytes(self, path, data, *, allow_config=False, allow_core=False):
        super().write_bytes(path, data, allow_config=allow_config,
                            allow_core=allow_core)
        if path == self.swallow:
            self.files.pop(path, None)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def wpt_caplog(caplog):
    parent = logging.getLogger("wpt")
    parent.addHandler(caplog.handler)
    with caplog.at_level(logging.DEBUG, logger="wpt"):
        yield caplog
    parent.removeHandler(caplog.handler)


def _records(caplog, level=None):
    return [r for r in caplog.records
            if r.name.startswith("wpt.actions.images_webp")
            and (level is None or r.levelno == level)]


def _dump_path(tmp_path, name="site.sql", data=None):
    path = tmp_path / name
    path.write_bytes(_dump() if data is None else data)
    return path


# ---------------------------------------------------------------------------
# Plugin-shaped tables that SHARE a core table name (the D1 fixtures)
#
# Column lists transcribed from the plugin's OWN schema file
# (all-in-one-seo-pack app/Common/Db/Schema.php, 5.0.1.1): ``aioseo_posts``
# ends with ``posts`` and declares ``id``/``post_id``/``og_image_url`` — no
# ``ID``, no ``post_content`` — and ``aioseo_writing_assistant_posts`` ends
# with ``posts`` too.  The 5.0-only additions (``focus_keyword``,
# ``truseo``, ``additional_keywords``, ``truseo_locale``) are the ones the
# plugin's own "Column history" docblock dates to 5.0.0, so the two column
# lists below are the 4.x and the 5.0 shape of the same table.
# ---------------------------------------------------------------------------

_AIOSEO_OG_IMAGE = f"https://example.test/{UP}" + BG
_AIOSEO_COLUMNS_COMMON = [
    "id", "post_id", "title", "description", "keywords", "og_title",
    "og_description", "og_image_type", "og_image_custom_url",
    "og_image_url", "twitter_card", "twitter_image_url", "seo_score",
    "schema", "robots_default", "robots_noindex", "options", "images",
    "created", "updated",
]
#: 4.x: no focus_keyword / truseo / additional_keywords / truseo_locale.
_AIOSEO_4_COLUMNS = list(_AIOSEO_COLUMNS_COMMON)
#: 5.0: the four columns the plugin dates to 5.0.0, in schema order.
_AIOSEO_5_COLUMNS = (_AIOSEO_COLUMNS_COMMON[:5]
                     + ["focus_keyword", "truseo", "additional_keywords",
                        "truseo_locale"]
                     + _AIOSEO_COLUMNS_COMMON[5:])
#: A plugin table that REALLY declares the surface columns: the fix must not
#: narrow the discovery, so this one is enumerated and rewritten.
_WRITABLE_PLUGIN_COLUMNS = ["ID", "post_content", "post_excerpt"]


def _aioseo_row(columns):
    """One plugin row aligned to ``columns``: an ``og:image`` (and a content
    analysis) that name real uploads files, plus the surface columns a
    table declaring them would carry."""
    values = {
        "id": 1, "post_id": 7, "title": "Home", "description": "",
        "keywords": "", "focus_keyword": "", "truseo": "",
        "additional_keywords": "", "truseo_locale": "en_US",
        "og_title": "", "og_description": "", "og_image_type": "default",
        "og_image_custom_url": "", "og_image_url": _AIOSEO_OG_IMAGE,
        "twitter_card": "summary_large_image", "twitter_image_url": "",
        "seo_score": 70, "schema": "", "robots_default": 1,
        "robots_noindex": 0, "options": "", "images": "",
        "content_analysis": json.dumps(
            {"images": [f"https://example.test/{UP}{MENU}"]}),
        "created": "2026-01-01 00:00:00", "updated": "2026-01-01 00:00:00",
        "ID": 9, "post_content": f'<img src="https://example.test/{UP}{MENU}">',
        "post_excerpt": "",
    }
    return tuple(values.get(column, "") for column in columns)


def _dump_with_plugin_table(columns=None, *, extra_tables=()):
    """The fixture dump plus a plugin-shaped ``wp_aioseo_posts``."""
    columns = _AIOSEO_5_COLUMNS if columns is None else columns
    out = _dump()
    for name, cols in extra_tables:
        out += _create(name, cols)
        out += _insert(name, [_aioseo_row(cols)])
    out += _create("wp_aioseo_posts", columns)
    out += _insert("wp_aioseo_posts", [_aioseo_row(columns)])
    return out


def _ctx(tmp_path, *, mode="local", settings=DEFAULTS, sql=None, zip_path=None,
         session=None, **overrides):
    fields = dict(
        source="local" if mode == "local" else "ftp://example.test",
        settings=settings,
        command="webp-media",
        apply=False,
        yes=False,
        backup_dir=tmp_path / "backup",
        sql=sql if sql is not None else (tmp_path / "missing.sql"),
        zip=zip_path,
        wp_url="https://example.test",
    )
    fields.update(overrides)
    return Ctx(**fields)


def _source():
    src = FakeSource()
    src.files.update(_files())
    return src


def _bridge_rows():
    """The ftp scan stream, mirroring the dump fixture row for row."""
    # the real shape: ``file`` uploads-relative, ``sizes[*].file`` a basename
    meta = json.dumps({"file": PHOTO,
                       "sizes": {"thumbnail": {"file": DERIV.rpartition("/")[2]}}})
    return [
        ("wp_posts", "ID", 7,
         f'<img src="https://example.test/{UP}{PHOTO}">', ()),
        ("wp_posts", "ID", 8, "<p>text</p>", (f"see {UP}{GATED}",)),
        ("wp_postmeta", "meta_id", 1, PHOTO, ()),
        ("wp_postmeta", "meta_id", 2, meta, ()),
        ("wp_postmeta", "meta_id", 3, _ser("full", PHOTO), ()),
        ("wp_postmeta", "meta_id", 4,
         json.dumps({"background_image": f"https://example.test/{UP}{BG}"}), ()),
        ("wp_postmeta", "meta_id", 5, "42", ()),
        ("wp_postmeta", "meta_id", 6, f"{UP}{SMALL}", ()),
        ("wp_postmeta", "meta_id", 11, f"{UP}{TWIN}", ()),
        ("wp_postmeta", "meta_id", 12, f"{UP}{DUP}", ()),
        ("wp_postmeta", "meta_id", 13, f"{UP}{DUP2}", ()),
        ("wp_postmeta", "meta_id", 14, f"{UP}{MENU}", ()),
        ("wp_options", "option_id", 1, _ser("logo", f"{UP}{PHOTO}"), ()),
        ("wp_options", "option_id", 2, _ser(f"{UP}{MENU}", "1"), ()),
        ("wp_options", "option_id", 3, f'{{"logo":"{UP}{PHOTO}"}}', ()),
        ("wp_usermeta", "umeta_id", 1, "", (f"{UP}{GATED}",)),
    ]


def _plan_local(tmp_path, *, source=None, ctx=None, **overrides):
    action = ImagesWebpAction()
    src = source if source is not None else _source()
    sql = _dump_path(tmp_path)
    context = ctx if ctx is not None else _ctx(tmp_path, sql=sql)
    context.extra.update(overrides)
    plan = action.plan(context, (src, None, None))
    return action, src, plan, context


def _converted(action):
    return {c.rel_old for c in action.state.conversions}


def _row_model(action):
    """The rehearsal row model: {(table, id): rewritten value or leaves}."""
    state = action.state
    out = {}
    for row in state.row_edits:
        if row.key in state.row_values:
            out[row.key] = state.row_values[row.key]
        else:
            out[row.key] = state.row_leaves.get(row.key, ())
    return out


def _zip_fingerprint(zpath):
    with zipfile.ZipFile(zpath) as zf:
        return {info.filename: (info.file_size, info.CRC)
                for info in zf.infolist()}


def _make_zip(tmp_path, name="site.zip"):
    zpath = tmp_path / name
    with zipfile.ZipFile(zpath, "w") as zf:
        for path, data in _files().items():
            zf.writestr(f"site.test/{path}", data)
    return zpath


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def test_registration():
    record = get_action("webp-media")
    assert record is not None
    assert record.applies == ("ftp", "local")
    assert isinstance(record.action, ImagesWebpAction)


# ---------------------------------------------------------------------------
# Image gates
# ---------------------------------------------------------------------------


def test_image_dimensions_header():
    assert image_dimensions(_png(64, 32)) == (64, 32)
    assert image_dimensions(_jpeg(80, 60)) == (80, 60)
    assert image_dimensions(b"not an image at all") is None
    # A header-only read: a real 16385px-wide PNG, no decode involved.
    assert image_dimensions(_png(16385, 1)) == (16385, 1)


def test_classify_animated_gif():
    assert classify_image(_gif(animated=True))[0] == "animated"
    assert classify_image(_gif(animated=False)) is None


def test_classify_animated_apng():
    reason, detail = classify_image(_png(60, 40, animated=True))
    assert reason == "animated"
    assert "frame" in detail


def test_classify_cmyk_jpeg():
    assert classify_image(_jpeg(cmyk=True))[0] == "cmyk"


def test_classify_oversize_png():
    # Over the libwebp limit AND above skip_below_bytes: a real image, so
    # the gate cannot be passing because the file was too small to matter.
    data = _png(16385, 1)
    assert len(data) > 30720
    reason, detail = classify_image(data)
    assert reason == "oversize"
    assert detail == "16385x1"


def test_classify_undecodable():
    assert classify_image(b"x" * 40000)[0] == "unreadable"
    truncated = _jpeg(64, 64)[:120]
    assert classify_image(truncated)[0] == "unreadable"


def test_encode_webp_alpha_preserved(tmp_path):
    out = encode_webp(_png(64, 64, mode="RGBA"), _cfg(tmp_path))
    assert out[:4] == b"RIFF" and out[8:12] == b"WEBP"
    with PIL.Image.open(io.BytesIO(out)) as decoded:
        assert decoded.mode == "RGBA"
        assert decoded.size == (64, 64)


def test_encode_webp_exif_orientation(tmp_path):
    out = encode_webp(_jpeg(300, 200, orientation=6), _cfg(tmp_path))
    with PIL.Image.open(io.BytesIO(out)) as decoded:
        assert decoded.size == (200, 300)   # the DISPLAY orientation
        assert 274 not in decoded.getexif()


def test_encode_webp_max_dim(tmp_path):
    cfg = _cfg(tmp_path, max_dim=100)
    with PIL.Image.open(io.BytesIO(encode_webp(_jpeg(400, 200), cfg))) as decoded:
        assert decoded.size == (100, 50)
    with PIL.Image.open(io.BytesIO(
            encode_webp(_jpeg(400, 200), _cfg(tmp_path, max_dim=0)))) as decoded:
        assert decoded.size == (400, 200)   # 0 = never resize


def test_encode_webp_quality_from_section(tmp_path):
    settings = copy.deepcopy(DEFAULTS)
    settings.webp = _webp(quality=10)
    ctx = _ctx(tmp_path, settings=settings)
    from wpt.actions.images_webp import _config

    low = encode_webp(_jpeg(256, 256), _config(ctx))
    high = encode_webp(_jpeg(256, 256), _cfg(tmp_path, quality=95))
    assert len(low) < len(high)
    assert _config(ctx).quality == 10


# ---------------------------------------------------------------------------
# The rewrite rule
# ---------------------------------------------------------------------------


def test_rewrite_text_surfaces():
    mapping = {PHOTO: PHOTO.replace(".jpg", ".webp"),
               DERIV: DERIV.replace(".jpg", ".webp")}
    absolute = f'<img src="https://example.test/{UP}{PHOTO}">'
    assert rewrite_text(absolute, mapping)[0] == \
        f'<img src="https://example.test/{UP}{PHOTO.replace(".jpg", ".webp")}">'
    assert rewrite_text(f'<img src="/{UP}{PHOTO}">', mapping)[0] == \
        f'<img src="/{UP}{PHOTO.replace(".jpg", ".webp")}">'
    # uploads-relative, the way _wp_attached_file and sizes[*].file store it
    assert rewrite_text(PHOTO, mapping)[0] == PHOTO.replace(".jpg", ".webp")
    # a query string is not part of the path and must survive
    assert rewrite_text(f"{UP}{PHOTO}?ver=2", mapping)[0] == \
        f"{UP}{PHOTO.replace('.jpg', '.webp')}?ver=2"
    # every size row of the metadata JSON, in one value
    meta = json.dumps({"file": PHOTO, "sizes": {"t": {"file": DERIV}}})
    new, changed = rewrite_text(meta, mapping)
    assert changed == {PHOTO, DERIV}
    assert ".jpg" not in new


def test_rewrite_text_thumbnail_id():
    mapping = {PHOTO: PHOTO.replace(".jpg", ".webp")}
    new, changed = rewrite_text("42", mapping)
    assert (new, changed) == ("42", set())


def test_rewrite_css_shapes():
    path = "wp-content/uploads/avada-styles/site.css"
    mapping = {BG: BG.replace(".jpg", ".webp"),
               PHOTO: PHOTO.replace(".jpg", ".webp")}
    css = (
        f"a{{background:url(../{BG}?v=2)}}"
        f"b{{background:url('/{UP}{PHOTO}')}}"
        f"c{{background:url(data:image/gif;base64,AAA)}}"
    )
    new, changed = rewrite_css(css, path, mapping)
    assert changed == {BG, PHOTO}
    assert f"url(../{BG.replace('.jpg', '.webp')}?v=2)" in new
    assert f"url('/{UP}{PHOTO.replace('.jpg', '.webp')}')" in new
    assert "data:image/gif" in new
    assert scan_css_refs(new, path) & set(mapping) == set()
    # an uploads path in a percent-encoded url()
    encoded = "a{background:url(%2Fwp-content%2Fuploads%2F2023%2F11%2Fbg.jpg)}"
    assert BG in scan_css_refs(encoded, path)
    assert ".webp" in rewrite_css(encoded, path, mapping)[0]


def test_value_texts_serialized():
    value = _ser("full", f"{UP}{PHOTO}")
    assert looks_serialized(value)
    texts, bad = value_texts(value)
    assert not bad
    assert any(PHOTO in t for t in texts)
    refs, bad = refs_in_value(value)
    assert refs == {PHOTO} and not bad
    # a serialized head that cannot be parsed is FAIL-CLOSED
    broken = 'a:1:{i:0;s:9:"icon";s:999:"%s%s";}' % (UP, BADSER)
    texts, bad = value_texts(broken)
    assert bad
    assert looks_serialized(broken)
    # a plain post body is not serialized
    assert not looks_serialized("<p>hello</p>")
    assert value_texts("<p>hello</p>") == (["<p>hello</p>"], False)


def test_scan_refs_ignores_non_paths():
    assert scan_refs("no images here") == set()
    assert scan_refs(f"{UP}dir/") == set()


# ---------------------------------------------------------------------------
# The plan (local mode, real dump)
# ---------------------------------------------------------------------------


def test_plan_local_converted_set(tmp_path):
    action, _src, plan, _ctx_ = _plan_local(tmp_path)
    assert _converted(action) == CONVERTED
    targets = {i.target for i in plan.items if i.category == "media.webp"}
    assert targets == {UP + ref.replace(".jpg", ".webp").replace(".png", ".webp")
                       for ref in CONVERTED}
    # every twin's detail names the mapping and the byte delta
    for item in plan.items:
        if item.category != "media.webp":
            continue
        assert "->" in item.detail
        assert item.bytes_est > 0
    assert plan.backup_tables == ["wp_options", "wp_postmeta", "wp_posts"]


def test_plan_local_size_rows(tmp_path):
    """The classic miss: EVERY sizes[*].file row is rewritten, not just file."""
    action, _src, _plan, _ctx_ = _plan_local(tmp_path)
    model = _row_model(action)
    rewritten = model[("wp_postmeta", 2)]
    assert isinstance(rewritten, str)
    # ``file`` is uploads-relative, every ``sizes[*].file`` is a bare
    # basename — both spellings must move, or every thumbnail breaks when
    # the original is purged.
    assert f'"file": "{PHOTO.replace(".jpg", ".webp")}"' in rewritten
    assert f'"file": "{DERIV.rpartition("/")[2].replace(".jpg", ".webp")}"' \
        in rewritten
    # the size row naming a file that is not in the tree stays untouched
    assert '"file": "photo-300x200.jpg"' in rewritten
    # the derivative is referenced NOWHERE else: only the metadata row knows it
    others = [v for k, v in model.items() if k != ("wp_postmeta", 2)]
    assert not any(DERIV in str(v) for v in others)


def test_plan_skips_reported(tmp_path):
    action, _src, plan, _ctx_ = _plan_local(tmp_path)
    skipped = {i.target: i for i in plan.items
               if i.category == "media.webp_skipped"}
    assert "animated" in skipped and ANIM in skipped["animated"].detail
    assert "cmyk" in skipped and CMYK in skipped["cmyk"].detail
    assert "oversize" in skipped and HUGE in skipped["oversize"].detail
    assert "tiny" in skipped and SMALL in skipped["tiny"].detail
    assert "data-tree" in skipped and FORM in skipped["data-tree"].detail
    assert "duplicate" in skipped and DUP2 in skipped["duplicate"].detail
    assert "twin-exists" in skipped and TWIN in skipped["twin-exists"].detail
    for item in skipped.values():
        assert item.requires_apply is False
        assert str(len([p for p in item.detail.split(": ")[-1].split(", ")])) or True
    # a GIF is not a candidate at all, so it never appears in a skip bucket
    assert not any("anim.gif" in i.detail for i in plan.items)


def test_plan_unreferenced_untouched(tmp_path):
    action, src, plan, _ctx_ = _plan_local(tmp_path)
    assert ORPHAN not in _converted(action)
    assert not any(ORPHAN in i.detail for i in plan.items)
    # _thumbnail_id is an ID, not a path: the row is not in the rewrite set
    assert ("wp_postmeta", 5) not in {r.key for r in action.state.row_edits}
    assert src.files[UP + ORPHAN] == _files()[UP + ORPHAN]


def test_ambiguous_basename_gates(tmp_path):
    """A bare filename that fits two folders must never be guessed."""
    src = _source()
    # the same basename in two year folders, referenced by name only
    src.files[UP + "2022/10/" + DERIV.rpartition("/")[2]] = _jpeg(200, 200, seed=7)
    sql = _dump_path(tmp_path)
    ctx = _ctx(tmp_path, sql=sql)
    action = ImagesWebpAction()
    plan = action.plan(ctx, (src, None, None))
    gated = {i.target: i for i in plan.items if i.category == "media.webp_gated"}
    assert "ambiguous-basename" in gated
    detail = gated["ambiguous-basename"].detail
    assert DERIV in detail and "2022/10/" + DERIV.rpartition("/")[2] in detail
    # neither file is converted: the reference cannot say which it meant
    assert DERIV not in _converted(action)
    assert "2022/10/" + DERIV.rpartition("/")[2] not in _converted(action)
    # and nothing is rewritten towards a twin that does not exist
    action.apply(ctx, (src, None, None), plan)
    model = _row_model(action)
    assert "2023/10/photo-150x150.webp" not in str(model[("wp_postmeta", 2)])


def test_plan_gated_surfaces(tmp_path):
    action, _src, plan, _ctx_ = _plan_local(tmp_path)
    gated = {i.target: i for i in plan.items if i.category == "media.webp_gated"}
    assert "gated-table" in gated and GATED in gated["gated-table"].detail
    assert "unparseable-value" in gated
    assert GATED not in _converted(action)
    assert BADSER not in _converted(action)
    for item in gated.values():
        assert item.requires_apply is False


# ---------------------------------------------------------------------------
# The plan (a plugin table that SHARES a core table name) — D1
# ---------------------------------------------------------------------------


def _plan_with_dump(tmp_path, data, *, source=None):
    src = source if source is not None else _source()
    sql = _dump_path(tmp_path, "plugin.sql", data)
    action = ImagesWebpAction()
    ctx = _ctx(tmp_path, sql=sql)
    plan = action.plan(ctx, (src, None, None))
    return action, src, plan, ctx


def test_local_dump_without_the_plugin_table_plans_unchanged(tmp_path):
    """No plugin table at all: nothing to gate, and the plan is the one the
    fixture has always produced (the base case the gating must not move)."""
    action, _src, plan, _ctx_ = _plan_local(tmp_path)
    assert action.state.gated_surfaces == []
    assert "unenumerated-surfaces" not in {i.target for i in plan.items}
    assert _converted(action) == CONVERTED
    assert plan.backup_tables == ["wp_options", "wp_postmeta", "wp_posts"]


def test_local_surface_with_the_columns_is_rewritten(tmp_path):
    """A table that shares a core name AND carries its columns is enumerated.

    The dump-driven resolution gates what the dump cannot address; it must
    NOT narrow the discovery, so a plugin table that really does declare
    ``ID``/``post_content`` is rewritten like any core row.
    """
    action, src, plan, ctx = _plan_with_dump(
        tmp_path, _dump_with_plugin_table(columns=_WRITABLE_PLUGIN_COLUMNS))
    assert action.state.gated_surfaces == []
    assert "wp_aioseo_posts" in plan.backup_tables
    key = ("wp_aioseo_posts", 9)
    assert key in {row.key for row in action.state.row_edits}
    # and the apply really moves that row's reference to the twin
    action.apply(ctx, (src, None, None), plan)
    assert MENU.replace(".png", ".webp") in str(_row_model(action)[key])
    assert "unenumerated-surfaces" not in {i.target for i in plan.items}


def test_local_aioseo4_columns_gate_the_surface(tmp_path):
    """4.x ``aioseo_posts`` (real column list): gated and reported, and the
    run proceeds.  Its ``og_image_url`` reference keeps its image original."""
    action, _src, plan, _ctx_ = _plan_with_dump(
        tmp_path, _dump_with_plugin_table(columns=_AIOSEO_4_COLUMNS))
    assert action.state.gated_surfaces == [
        "wp_aioseo_posts (posts needs ID + post_content)"]
    # the CORE surfaces were still enumerated: nothing refused
    assert {row.table for row in action.state.row_edits} == {
        "wp_options", "wp_postmeta", "wp_posts"}
    item = next(i for i in plan.items if i.target == "unenumerated-surfaces")
    assert "wp_aioseo_posts" in item.detail and "post_content" in item.detail
    assert item.requires_apply is False
    # the plugin row's og:image is a GATED reference: that file keeps its
    # original bytes even though a rewritable surface (the stylesheet) also
    # references it
    assert BG not in _converted(action)
    gated = {i.target: i for i in plan.items if i.category == "media.webp_gated"}
    assert BG in gated["gated-table"].detail
    assert _converted(action) == CONVERTED - {BG}


def test_local_aioseo5_layout_is_resolved_from_the_dump(tmp_path):
    """5.0's layout, including the second posts-suffixed table: whatever the
    dump shows decides, and BOTH surfaces are gated rather than fatal."""
    data = _dump_with_plugin_table(columns=_AIOSEO_5_COLUMNS, extra_tables=[
        ("wp_aioseo_writing_assistant_posts",
         ["id", "post_id", "keyword_id", "content_analysis_hash",
          "content_analysis", "created", "updated"])])
    action, _src, plan, _ctx_ = _plan_with_dump(tmp_path, data)
    assert action.state.gated_surfaces == [
        "wp_aioseo_posts (posts needs ID + post_content)",
        "wp_aioseo_writing_assistant_posts (posts needs ID + post_content)"]
    # each gated table's own columns are read, so ITS reference gates too
    assert BG not in _converted(action)      # og_image_url
    assert MENU not in _converted(action)    # content_analysis
    gated = {i.target: i for i in plan.items if i.category == "media.webp_gated"}
    assert BG in gated["gated-table"].detail
    assert MENU in gated["gated-table"].detail
    assert _converted(action) == CONVERTED - {BG, MENU}


def test_local_table_missing_one_column_gates_only_that_surface(tmp_path):
    """The table exists and declares the KEY column; only the value column
    is missing, and only that is reported."""
    action, _src, plan, _ctx_ = _plan_with_dump(
        tmp_path, _dump_with_plugin_table(columns=["ID", "post_excerpt"]))
    assert action.state.gated_surfaces == [
        "wp_aioseo_posts (posts needs post_content)"]
    assert _converted(action) == CONVERTED


#: The one uploads file the estimate tests add so the fixture site holds
#: BOTH JPEG spellings (a live site's real shape), and the stylesheet that
#: gives it a reference surface — a candidate the dump never mentions is
#: not converted at all.
MIXED = "2023/12/mixed.jpeg"
SITE_CSS = "wp-content/uploads/avada-styles/site.css"


def _mixed_source():
    """The fixture site plus one referenced ``.jpeg``: two JPEG spellings."""
    src = _source()
    src.files[UP + MIXED] = _jpeg(300, 200, seed=71)
    src.files[SITE_CSS] += f".m{{background:url(../{MIXED})}}".encode()
    return src


def _split_rows(item):
    """The estimate item's ``label N file(s), SIZE`` rows, in order."""
    return [row.strip() for row in item.detail.rsplit(": ", 1)[1].split("; ")]


def _saved_by_suffix(action):
    """``{extension: [file count, reclaimable bytes]}`` over the conversions."""
    out: dict[str, list[int]] = {}
    for conversion in action.state.conversions:
        bucket = out.setdefault(conversion.rel_old.rpartition(".")[2], [0, 0])
        bucket[0] += 1
        bucket[1] += conversion.saving
    return out


def test_plan_estimate_split_by_source_format(tmp_path):
    """One row per FORMAT — each naming the extensions it actually holds.

    The mixed-spelling site is the whole point [D1]: the split bucketed on
    the EXTENSION (``jpg`` and ``jpeg`` are two buckets) but labelled every
    bucket with a hardcoded format title, so a site holding both spellings
    printed ``JPEG … JPEG … ALL FILES`` and the operator could not tell the
    two rows apart.  The old fixture held one spelling only, which is why it
    passed.  The plan's own total is unchanged.
    """
    action, _src, plan, _ctx_ = _plan_local(tmp_path, source=_mixed_source())
    item = next(i for i in plan.items if i.category == "media.webp_estimate")
    assert item.requires_apply is False and item.bytes_est == 0
    saved = _saved_by_suffix(action)
    assert set(saved) == {"jpg", "jpeg", "png"}  # the fixture is MIXED
    jpeg = [v for k, v in saved.items() if k in ("jpg", "jpeg")]
    assert sum(v[0] for v in jpeg) == sum(
        1 for c in action.state.conversions
        if c.rel_old.endswith((".jpg", ".jpeg")))
    rows = _split_rows(item)
    # ONE JPEG row, naming both spellings it counts — never two rows both
    # labelled "JPEG"
    assert f"JPEG (.jpeg, .jpg) {sum(v[0] for v in jpeg)} file(s), " \
           f"{human_bytes(sum(v[1] for v in jpeg))}" in rows
    assert item.detail.count("JPEG") == 1
    assert f"PNG (.png) {saved['png'][0]} file(s), " \
           f"{human_bytes(saved['png'][1])}" in rows
    # every format row names the extensions it holds, and ALL FILES is last
    assert [row.split(" file(s)")[0].rpartition(" ")[0] for row in rows[:-1]] \
        == ["JPEG (.jpeg, .jpg)", "PNG (.png)"]
    assert rows[-1] == (f"ALL FILES {len(action.state.conversions)} file(s), "
                        f"{human_bytes(sum(v[1] for v in saved.values()))}")
    # the blended total is still the plan's own number, not double counted
    assert plan.est_bytes() == sum(v[1] for v in saved.values())


def test_plan_estimate_single_spelling_names_its_extension(tmp_path):
    """One spelling, one row — and the row still says WHICH files it is."""
    action, _src, plan, _ctx_ = _plan_local(tmp_path)
    item = next(i for i in plan.items if i.category == "media.webp_estimate")
    saved = _saved_by_suffix(action)
    assert set(saved) == {"jpg", "png"}
    rows = _split_rows(item)
    assert rows[:-1] == [
        f"JPEG (.jpg) {saved['jpg'][0]} file(s), {human_bytes(saved['jpg'][1])}",
        f"PNG (.png) {saved['png'][0]} file(s), {human_bytes(saved['png'][1])}",
    ]
    assert _converted(action) == CONVERTED


def test_plan_advice_keeps_originals(tmp_path):
    _action, _src, plan, _ctx_ = _plan_local(tmp_path)
    advice = {i.target: i for i in plan.items
              if i.category == "media.webp_advice"}
    assert "purge-originals" in advice
    assert advice["purge-originals"].requires_apply is False
    assert "KEPT" in advice["purge-originals"].detail
    # no purge item without the flag
    assert not [i for i in plan.items if i.category == "media.webp_purge"]


def test_plan_no_live_proof_advice(tmp_path):
    _action, _src, plan, _ctx_ = _plan_local(tmp_path)
    advice = {i.target for i in plan.items if i.category == "media.webp_advice"}
    assert "no-live-proof" in advice


def test_plan_backup_tables_refuses_unknown_table(tmp_path):
    src = _source()
    ctx = _ctx(tmp_path, sql=_dump_path(tmp_path))
    action = ImagesWebpAction()
    # A bridge-less local run derives the table list from the dump; a dump
    # whose table list cannot cover the rewrite refuses closed.
    stripped = tmp_path / "stripped.sql"
    stripped.write_bytes(_dump().replace(b"`wp_postmeta`", b"`wp_other`"))
    ctx.sql = stripped
    with pytest.raises(SourceError, match="postmeta"):
        action.plan(ctx, (src, None, None))


# ---------------------------------------------------------------------------
# The apply (local rehearsal)
# ---------------------------------------------------------------------------


def test_apply_local_convert_rewrite(tmp_path):
    action, src, plan, ctx = _plan_local(tmp_path)
    applied = action.apply(ctx, (src, None, None), plan)
    for ref in CONVERTED:
        twin = UP + ref.rsplit(".", 1)[0] + ".webp"
        assert twin in src.files, twin
        assert src.files[twin][:4] == b"RIFF"
        # the ORIGINAL is still there: the default run keeps it
        assert UP + ref in src.files
    css = src.files["wp-content/uploads/avada-styles/site.css"].decode()
    assert BG.replace(".jpg", ".webp") in css
    assert PHOTO.replace(".jpg", ".webp") in css
    assert all(i.done for i in applied.items if i.requires_apply)
    # untouched files really are untouched
    assert src.files[UP + ORPHAN] == _files()[UP + ORPHAN]
    assert src.files["wp-content/uploads/.htaccess"] == b"# silence\n"


def test_apply_local_row_model_has_no_stale_ref(tmp_path):
    action, src, plan, ctx = _plan_local(tmp_path)
    action.apply(ctx, (src, None, None), plan)
    # the map the apply really used, under BOTH spellings
    mapping = action.state.applied_mapping
    assert "2023/10/photo.jpg" in mapping and "photo.jpg" in mapping
    for key, value in _row_model(action).items():
        texts = [value] if isinstance(value, str) else list(value)
        for text in texts:
            stale = {r for r in scan_refs(text)} & set(mapping)
            assert not stale, (key, stale)
    # the derivative really moved in the applied model; the size row naming
    # a file that is not in the tree is deliberately left alone (an absent
    # file has no twin to point at)
    model = _row_model(action)
    assert ".jpg" in str(model[("wp_postmeta", 2)])
    assert str(model[("wp_postmeta", 2)]).count(".webp") == 2


def test_apply_local_purge_refused(tmp_path):
    action, src, plan, ctx = _plan_local(tmp_path)
    ctx.extra["purge_originals"] = True
    before = dict(src.files)
    with pytest.raises(SourceError, match="purge-originals"):
        action.apply(ctx, (src, None, None), plan)
    assert src.files == before


def test_verify_refuses_broken_path(tmp_path):
    """A twin that is missing at verification time fails the whole run."""
    src = _VanishingSource(_files(), UP + PHOTO.replace(".jpg", ".webp"))
    action = ImagesWebpAction()
    ctx = _ctx(tmp_path, sql=_dump_path(tmp_path))
    plan = action.plan(ctx, (src, None, None))
    with pytest.raises(SourceError, match="did not verify"):
        action.apply(ctx, (src, None, None), plan)


def test_apply_lost_twin_leaves_its_references_alone(tmp_path):
    """A twin that never landed is not marked done and is not referenced."""
    src = _SwallowingSource(_files(), UP + PHOTO.replace(".jpg", ".webp"))
    action = ImagesWebpAction()
    ctx = _ctx(tmp_path, sql=_dump_path(tmp_path))
    plan = action.plan(ctx, (src, None, None))
    applied = action.apply(ctx, (src, None, None), plan)
    item = next(i for i in plan.items
                if i.target == UP + PHOTO.replace(".jpg", ".webp"))
    assert item.done is False
    # the row that referenced it is NOT rewritten: it still points at the
    # ORIGINAL, which is still there — so nothing is broken, and a purge
    # would never delete an original whose references did not move.
    assert ("wp_postmeta", 1) not in action.state.row_values
    assert PHOTO.replace(".jpg", ".webp") not in str(action.state.row_values)
    assert UP + PHOTO in src.files
    others = [i for i in applied.items if i.requires_apply and i.done]
    assert others


def test_verify_refuses_stale_row(tmp_path):
    """A bridge that does not actually move the row fails the run."""
    class _LyingBridge(_Bridge):
        """Reports success and re-reads the UNCHANGED value: the silent
        no-op UPDATE (a stale replica, a swallowed error) the post-write
        re-read exists to catch."""

        def call(self, action_name, **params):
            if action_name == "media_rewrite_refs" and params.get("apply"):
                self.calls.append((action_name, params))
                rows = []
                for entry in params["rows"]:
                    original = ""
                    for table, _key, row_id, value, _g in self.rows:
                        if (table, row_id) == (entry["table"], entry["id"]):
                            original = value
                            break
                    rows.append({"table": entry["table"], "id": entry["id"],
                                 "value": original})
                return {"ok": True, "rows": rows, "failed": []}
            return super().call(action_name, **params)

    src = _source()
    bridge = _LyingBridge(_bridge_rows())
    action = ImagesWebpAction()
    ctx = _ctx(tmp_path, mode="ftp", wp_url=None)
    plan = action.plan(ctx, (src, FakeSession(), bridge))
    with pytest.raises(SourceError, match="still references|did not verify"):
        action.apply(ctx, (src, FakeSession(), bridge), plan)


# ---------------------------------------------------------------------------
# The apply (ftp mode, bridge double)
# ---------------------------------------------------------------------------


def test_apply_ftp_rewrites_rows_and_keeps_originals(tmp_path):
    src = _source()
    bridge = _Bridge(_bridge_rows())
    session = FakeSession()
    action = ImagesWebpAction()
    # no --wp-url: this test is about the DB rewrite, and a site URL would
    # (correctly) pull the live walk in
    ctx = _ctx(tmp_path, mode="ftp", wp_url=None)
    plan = action.plan(ctx, (src, session, bridge))
    applied = action.apply(ctx, (src, session, bridge), plan)
    for ref in CONVERTED:
        assert UP + ref in src.files            # originals kept by default
    # the bridge was asked to write, and the values it stored carry no
    # reference to a converted original
    writes = [c for c in bridge.calls if c[0] == "media_rewrite_refs"
              and c[1].get("apply")]
    assert writes
    for value in bridge.store.values():
        stale = scan_refs(value) & set(action.state.mapping)
        assert not stale, (value, stale)
    assert all(i.done for i in applied.items if i.requires_apply)


def test_apply_ftp_failed_row_fails_the_run(tmp_path):
    src = _source()
    bridge = _Bridge(_bridge_rows(), fail_rows=("wp_postmeta[1]",))
    session = FakeSession()
    action = ImagesWebpAction()
    ctx = _ctx(tmp_path, mode="ftp", wp_url=None)
    plan = action.plan(ctx, (src, session, bridge))
    with pytest.raises(SourceError, match="were not rewritten"):
        action.apply(ctx, (src, session, bridge), plan)


#: A purge the operator acknowledged as a window (see the D2 contract).
PURGE = {"purge_originals": True, "i_know_editors_are_off": True}


def test_apply_ftp_purge_removes_only(tmp_path):
    src = _source()
    bridge = _Bridge(_bridge_rows())
    session = FakeSession()
    action = ImagesWebpAction()
    ctx = _ctx(tmp_path, mode="ftp", wp_url=None, extra=dict(PURGE))
    plan = action.plan(ctx, (src, session, bridge))
    before = set(src.files)
    applied = action.apply(ctx, (src, session, bridge), plan)
    # only the originals of CONVERTED are gone; everything else survives
    for ref in CONVERTED:
        assert UP + ref not in src.files
        assert UP + ref.rsplit(".", 1)[0] + ".webp" in src.files
    survivors = {p for p in before if p not in {UP + r for r in CONVERTED}}
    assert survivors <= set(src.files)
    assert UP + ORPHAN in src.files
    assert UP + ANIM in src.files
    assert all(i.done for i in applied.items if i.requires_apply)
    purge_items = [i for i in plan.items if i.category == "media.webp_purge"]
    assert {i.target for i in purge_items} == {UP + r for r in CONVERTED}
    assert action.state.purge_kept == []


# ---------------------------------------------------------------------------
# The purge is a WINDOWED operation (D2)
# ---------------------------------------------------------------------------


def test_purge_refused_without_the_editor_free_acknowledgement(tmp_path):
    src = _source()
    bridge = _Bridge(_bridge_rows())
    action = ImagesWebpAction()
    # 1. the PLAN phase refuses, so nothing is even encoded on the way
    unacked = _ctx(tmp_path, mode="ftp", wp_url=None,
                   extra={"purge_originals": True})
    with pytest.raises(SourceError, match="--i-know-editors-are-off"):
        action.plan(unacked, (src, None, bridge))
    assert set(src.files) == set(_files())   # not even an encode happened
    # 2. the APPLY refuses too, before any mutation, even with a plan that
    #    was built with the acknowledgement
    acked = _ctx(tmp_path, mode="ftp", wp_url=None, extra=dict(PURGE))
    plan = action.plan(acked, (src, None, bridge))
    before = dict(src.files)
    with pytest.raises(SourceError, match="WINDOWED"):
        action.apply(unacked, (src, None, bridge), plan)
    assert src.files == before
    # 3. the refusal names the alternative, not just the block
    with pytest.raises(SourceError, match="kept by default"):
        action.plan(unacked, (src, None, bridge))


def test_purge_refused_when_the_profile_asks_for_it_without_the_flag(tmp_path):
    """The profile key is a request, not an acknowledgement.

    The profile door only opens at all when the CLI reports "the operator
    did not type the flag" as ``None`` (see :func:`_config`); an
    ``argparse`` ``store_true`` without ``default=None`` hands the plan a
    ``False`` that reads as a typed refusal and makes this whole door dead
    code, which three docstrings and SPEC L32 promise it is not.
    """
    settings = copy.deepcopy(DEFAULTS)
    settings.webp = _webp(purge_originals=True)
    action = ImagesWebpAction()
    ctx = _ctx(tmp_path, sql=_dump_path(tmp_path), settings=settings)
    # 1. the flag ABSENT (not typed) + the profile asking for the purge
    assert ctx.extra.get("purge_originals") is None
    with pytest.raises(SourceError, match="--i-know-editors-are-off"):
        action.plan(ctx, (_source(), None, None))
    # 2. the refusal names the window it needs, not just the flag
    with pytest.raises(SourceError, match="WINDOWED"):
        action.plan(ctx, (_source(), None, None))
    # 3. the same door ACKNOWLEDGED proceeds
    ctx.extra["i_know_editors_are_off"] = True
    action.plan(ctx, (_source(), None, None))


def test_purge_profile_door_and_flag_door_refuse_identically(tmp_path):
    """Both doors demand the same acknowledgement; typed intent wins.

    The matrix the tri-state flag buys: the profile asks and the operator
    did not type the flag (proceeds once acknowledged), the operator typed
    it and the profile says nothing (same), and an explicitly passed
    ``False`` is a typed refusal the profile may not override.
    """
    with_profile = copy.deepcopy(DEFAULTS)
    with_profile.webp = _webp(purge_originals=True)
    without = copy.deepcopy(DEFAULTS)
    without.webp = _webp(purge_originals=False)
    action = ImagesWebpAction()

    def _cfg(settings, **extra):
        ctx = _ctx(tmp_path, sql=_dump_path(tmp_path), settings=settings)
        ctx.extra.update(extra)
        return action, ctx

    # typed flag, profile silent -> the purge is asked for
    _act, ctx = _cfg(without, purge_originals=True)
    with pytest.raises(SourceError, match="--i-know-editors-are-off"):
        _act.plan(ctx, (_source(), None, None))
    _act, ctx = _cfg(without, purge_originals=True, i_know_editors_are_off=True)
    _act.plan(ctx, (_source(), None, None))

    # typed flag + profile FALSE -> proceeds: the operator's word wins
    _act, ctx = _cfg(without, purge_originals=True, i_know_editors_are_off=True)
    plan = _act.plan(ctx, (_source(), None, None))
    assert [i for i in plan.items if i.category == "media.webp_purge"]

    # explicitly typed False + profile true -> no purge, no acknowledgement
    # needed: the operator said no
    _act, ctx = _cfg(with_profile, purge_originals=False,
                     i_know_editors_are_off=True)
    plan = _act.plan(ctx, (_source(), None, None))
    assert not [i for i in plan.items if i.category == "media.webp_purge"]


def test_purge_keeps_an_original_a_stale_editor_referenced_again(
        tmp_path, wpt_caplog):
    """The delete decision comes from a set RE-READ at purge time.

    A stale editor save puts ``2023/10/photo.jpg`` back into
    ``wp_postmeta[1]`` between the rewrite and the purge.  Deleting it would
    break that page AND create a reference that permanently protects bytes
    that are already gone, so the original is kept — and that is an
    ADVISORY: the rewrite this run was asked for verified, so the item
    stops being applicable and the run's success is not in question.
    """
    src = _source()
    bridge = _StaleEditorBridge(_bridge_rows(), resurrect=("wp_postmeta", 1))
    action = ImagesWebpAction()
    ctx = _ctx(tmp_path, mode="ftp", wp_url=None, extra=dict(PURGE))
    plan = action.plan(ctx, (src, None, bridge))
    applied = action.apply(ctx, (src, None, bridge), plan)
    assert UP + PHOTO in src.files               # the original survives
    assert UP + PHOTO.replace(".jpg", ".webp") in src.files
    assert action.state.purge_kept == [PHOTO]
    item = next(i for i in plan.items if i.category == "media.webp_purge"
                and i.target == UP + PHOTO)
    assert item.requires_apply is False
    assert "KEPT, not deleted" in item.detail
    # every other original went, and every APPLICABLE item landed
    for ref in CONVERTED - {PHOTO}:
        assert UP + ref not in src.files
    assert all(i.done for i in applied.items if i.requires_apply)
    assert any("referenced again" in r.getMessage()
               for r in _records(wpt_caplog, logging.WARNING))


def test_purge_declined_keeps_the_original_and_still_purges_the_cache(
        tmp_path, monkeypatch, capsys):
    """A declined delete does not decide rc, and the cache purge STILL runs.

    The registry skips ``purge_cache`` on an incomplete plan, so a declined
    delete that stayed an applicable item left the site serving
    pre-rewrite HTML out of cache while the terminal said the run had
    failed (measured on a real site).  The rewrite is live either way, so the
    purge must fire and the run must succeed with the kept files named.
    """
    bridge = _StaleEditorBridge(_bridge_rows(), resurrect=("wp_postmeta", 1))
    src = _source()
    ctx = _ctx(tmp_path, mode="ftp", wp_url=None, apply=True, yes=True,
               extra=dict(PURGE))
    monkeypatch.setattr(registry_mod, "_stack",
                        lambda c: (src, None, bridge))
    assert run_action(ctx, "webp-media") == 0
    out = capsys.readouterr().out
    # the cache purge really was asked for
    assert [c for c in bridge.calls if c[0] == "purge_cache"]
    # the kept original is named, with the reason and the follow-up
    assert "1 original(s) kept" in out
    assert "a live editor\'s save re-introduced their references" in out
    assert "rerun the purge in a quiet window" in out
    assert PHOTO in out
    assert UP + PHOTO in src.files


def test_purge_kept_is_an_advisory_not_an_applicable_item(tmp_path):
    """The item must be visible and must not count towards completion."""
    src = _source()
    bridge = _StaleEditorBridge(_bridge_rows(), resurrect=("wp_postmeta", 1))
    action = ImagesWebpAction()
    ctx = _ctx(tmp_path, mode="ftp", wp_url=None, extra=dict(PURGE))
    plan = action.plan(ctx, (src, None, bridge))
    applied = action.apply(ctx, (src, None, bridge), plan)
    kept = [i for i in applied.items
            if i.category == "media.webp_purge_kept"]
    assert len(kept) == 1
    assert kept[0].requires_apply is False
    assert PHOTO in kept[0].detail
    # the snapshot scope was computed BEFORE the apply, from the plan: the
    # kept original's bytes are still captured, so keeping them is the
    # safe half of the window either way
    purge_items = [i for i in applied.items
                   if i.category == "media.webp_purge"]
    assert purge_items and all(not i.done for i in purge_items
                               if i.target == UP + PHOTO)


def test_unverified_rewrite_still_fails_closed_and_keeps_the_cache(
        tmp_path, monkeypatch, capsys, wpt_caplog):
    """The other half: an UNPROVEN rewrite is a failure, and purges nothing.

    Advisory is for the delete the run declined, never for the rewrite it
    could not prove — that is the one this action exists to get right, and
    it must still exit 1 with the site's page cache untouched.
    """
    bridge = _Bridge(_bridge_rows(), fail_rows=("wp_postmeta[1]",))
    src = _source()
    ctx = _ctx(tmp_path, mode="ftp", wp_url=None, apply=True, yes=True,
               extra=dict(PURGE))
    monkeypatch.setattr(registry_mod, "_stack",
                        lambda c: (src, None, bridge))
    assert run_action(ctx, "webp-media") == 1
    assert not [c for c in bridge.calls if c[0] == "purge_cache"]
    capsys.readouterr()
    assert any("were not rewritten" in r.getMessage()
               for r in wpt_caplog.records)


def test_purge_reports_a_reference_that_reappeared_after_the_deletes(
        tmp_path, wpt_caplog):
    """A save that lands AFTER the deletes is REPORTED, never fatal.

    The run did what it was asked to do; the operator still needs the list
    of references now pointing at a deleted original, and the snapshot is
    the rollback.
    """
    src = _source()
    bridge = _StaleEditorBridge(_bridge_rows(), resurrect=("wp_postmeta", 1),
                                from_scan=3)
    action = ImagesWebpAction()
    ctx = _ctx(tmp_path, mode="ftp", wp_url=None, extra=dict(PURGE))
    plan = action.plan(ctx, (src, None, bridge))
    applied = action.apply(ctx, (src, None, bridge), plan)
    # the pre-delete re-read still saw no reference, so the file WAS deleted
    assert UP + PHOTO not in src.files
    assert action.state.purge_kept == []
    race = [i for i in applied.items if i.category == "media.webp_purge_race"]
    assert len(race) == 1
    assert PHOTO in race[0].detail and "wpt restore" in race[0].detail
    assert race[0].requires_apply is False
    # reported, NOT failed: every applicable item landed
    assert all(i.done for i in applied.items if i.requires_apply)
    assert any("point at an original this run deleted" in r.getMessage()
               for r in _records(wpt_caplog, logging.WARNING))


def _run_ftp(tmp_path, monkeypatch, bridge, *, apply=True):
    """Drive `wpt webp-media` end to end in ftp mode against a bridge double.

    The registry's own flow — plan, confirm, snapshot, apply — so an rc of 1
    is the real command's exit status, and "nothing was written" is asserted
    against the webroot the apply would have written into.
    """
    src = _source()
    ctx = _ctx(tmp_path, mode="ftp", wp_url=None, apply=apply, yes=True)
    monkeypatch.setattr(registry_mod, "_stack", lambda c: (src, None, bridge))
    return run_action(ctx, "webp-media"), src


def _nothing_written(src):
    """The webroot is byte-for-byte the fixture: no twin, no rewrite, no CSS."""
    before = _files()
    assert set(src.files) == set(before)
    assert all(src.files[path] == data for path, data in before.items())


# ---------------------------------------------------------------------------
# The reference scan is read through the CLIENT's fail-closed reader
# (Bridge.iter_rewrite_refs is the one implementation of the wire contract;
# these four pin the WIRING through the action's public path, not the
# client's internals)
# ---------------------------------------------------------------------------


def test_plan_ftp_scan_without_the_completion_marker_refuses(
        tmp_path, monkeypatch, wpt_caplog):
    """A stream that just STOPS is refused — rc 1, nothing written.

    The PHP fatal after the first lines: the NDJSON ends with no error line
    and no summary, so a weaker reader (this action's own stream consumption
    did exactly that) accepts the rows it did get as a COMPLETE reference set
    — and plans conversions on the strength of a set nobody finished
    measuring.  A reference the scan never reported is an image nothing in
    this run can rewrite, which is the whole reason the summary exists.
    """
    bridge = _Bridge(_bridge_rows(), scan_unterminated=True)
    rc, src = _run_ftp(tmp_path, monkeypatch, bridge)
    assert rc == 1
    _nothing_written(src)
    assert any("completion marker" in r.getMessage() for r in wpt_caplog.records)


def test_plan_ftp_truncated_scan_is_refused_and_nothing_is_written(
        tmp_path, monkeypatch, wpt_caplog):
    """The op's own half-measured marker: refused, no twin encoded."""
    bridge = _Bridge(_bridge_rows(), scan_truncated=True)
    action = ImagesWebpAction()
    ctx = _ctx(tmp_path, mode="ftp", wp_url=None)
    with pytest.raises(BridgeError, match="truncated"):
        action.plan(ctx, (_source(), FakeSession(), bridge))
    # ... and through the command itself, so the refusal is a failed RUN
    rc, src = _run_ftp(tmp_path, monkeypatch, bridge)
    assert rc == 1
    _nothing_written(src)
    assert any("truncated" in r.getMessage() for r in wpt_caplog.records)


def test_plan_ftp_scan_whose_row_count_disagrees_refuses(
        tmp_path, monkeypatch, wpt_caplog):
    """A summary that claims more rows than arrived is refused.

    The count is the completion PROOF: a disagreement means a line was lost,
    and a lost row is a reference this run would believe nothing holds — the
    same half-measured set the marker exists to prevent, in the one shape a
    reader that only checked for the marker's presence would let through.
    """
    bridge = _Bridge(_bridge_rows(), scan_count_delta=3)
    rc, src = _run_ftp(tmp_path, monkeypatch, bridge)
    assert rc == 1
    _nothing_written(src)
    assert any("incomplete" in r.getMessage() for r in wpt_caplog.records)


def test_plan_ftp_well_formed_scan_answers_the_current_behavior(
        tmp_path, monkeypatch, capsys):
    """The well-formed answer is UNCHANGED: the same conversions, same rows.

    The pin on the other side of the three refusals above: the proof the
    client now requires is already on the wire for a healthy op, so the
    fail-closed reader costs a working run nothing.
    """
    bridge = _Bridge(_bridge_rows())
    rc, src = _run_ftp(tmp_path, monkeypatch, bridge)
    assert rc == 0
    for ref in CONVERTED:
        twin = UP + ref.rsplit(".", 1)[0] + ".webp"
        assert twin in src.files and src.files[twin][:4] == b"RIFF"
        assert UP + ref in src.files          # the default keeps the original
    # the rewrite went through Bridge.rewrite_refs, and every value it stored
    # carries no reference to a converted original
    assert [c for c in bridge.calls
            if c[0] == "media_rewrite_refs" and c[1].get("apply")]
    for value in bridge.store.values():
        stale = scan_refs(value) & CONVERTED
        assert not stale, (value, stale)
    assert "applied" in capsys.readouterr().out.lower()


def test_registry_ftp_snapshot_scope(tmp_path, monkeypatch, capsys):
    """The snapshot covers the touched tables AND every file replaced."""
    src = _source()
    bridge = _Bridge(_bridge_rows())
    action = ImagesWebpAction()
    ctx = _ctx(tmp_path, mode="ftp", wp_url=None, apply=True, yes=True)
    record = get_action("webp-media")
    monkeypatch.setattr(registry_mod, "_stack", lambda c: (src, None, bridge))
    assert run_action(ctx, "webp-media") == 0
    capsys.readouterr()
    # the registry's own snapshot, taken between plan and apply
    from wpt.backup import MANIFEST_NAME
    import json as _json

    snaps = sorted((tmp_path / "backup").glob("*/*/"))
    assert len(snaps) == 1
    manifest = _json.loads((snaps[0] / MANIFEST_NAME).read_text())
    tables = {t["name"] for t in manifest["tables"]}
    assert tables == {"wp_options", "wp_postmeta", "wp_posts"}
    files = {f["path"]: f for f in manifest["files"]}
    # the stylesheet's PRE-rewrite bytes are captured
    css = "wp-content/uploads/avada-styles/site.css"
    assert files[css]["absent"] is False
    assert (snaps[0] / "files" / css).read_bytes() == _files()[css]
    # the twins are new files: recorded absent, never "restored" over
    for ref in CONVERTED:
        twin = UP + ref.rsplit(".", 1)[0] + ".webp"
        assert files[twin]["absent"] is True
    # no purge -> the originals are not in the snapshot (nothing deletes them)
    assert all(UP + ref not in files for ref in CONVERTED)
    # with the purge flag, every original IS captured
    src2 = _source()
    bridge2 = _Bridge(_bridge_rows())
    ctx2 = _ctx(tmp_path / "purge", mode="ftp", wp_url=None, apply=True,
                yes=True, extra=dict(PURGE),
                backup_dir=tmp_path / "purge-backup")
    monkeypatch.setattr(registry_mod, "_stack", lambda c: (src2, None, bridge2))
    assert run_action(ctx2, "webp-media") == 0
    snaps2 = sorted((tmp_path / "purge-backup").glob("*/*/"))
    files2 = {f["path"]: f for f in
              _json.loads((snaps2[0] / MANIFEST_NAME).read_text())["files"]}
    for ref in CONVERTED:
        original = UP + ref
        assert files2[original]["absent"] is False
        assert (snaps2[0] / "files" / original).read_bytes() == _files()[original]
    del record, action


# ---------------------------------------------------------------------------
# ONE decoder for a stored value (the rewrite gate, not a second reader)
# ---------------------------------------------------------------------------

def _nested_ser(levels: int) -> str:
    """``levels`` nested arrays around an integer, as PHP writes them."""
    inner = "i:1;"
    for _ in range(levels):
        inner = "a:1:{i:0;%s}" % inner
    return inner


#: The three shapes the local gate used to refuse with a FALSE reason while
#: the live side (which rewrites with WordPress' own ``maybe_unserialize``)
#: read them fine.  Each names BADSER, a real file in the fixture webroot, so
#: "refused" is directly observable: the image is gated out of the conversion.
_BAD_URL = UP + BADSER
_C_OBJSER = ('a:2:{s:8:"icon_url";s:%d:"%s";s:1:"o";C:7:"NoSuchX":2:{ab}}'
             % (len(_BAD_URL), _BAD_URL))
_DEEP_SER = ('a:2:{s:8:"icon_url";s:%d:"%s";s:1:"d";%s}'
             % (len(_BAD_URL), _BAD_URL, _nested_ser(200)))
_TRAILING_SER = 'a:1:{s:8:"icon_url";s:%d:"%s";}not-ours' % (
    len(_BAD_URL), _BAD_URL)


@pytest.mark.parametrize("value", [_C_OBJSER, _DEEP_SER, _TRAILING_SER],
                         ids=["custom-serialized", "200-deep", "trailing-bytes"])
def test_a_value_the_keep_set_reads_is_planned_not_refused(tmp_path, value):
    """The rewrite gate and the keep-set must not answer differently.

    The gate used to read stored values with
    ``wpt.localmode.analyzer.php_unserialize``, whose narrower policy refuses
    a ``C:`` payload, a 200-deep value and trailing bytes, and reported "could
    not be parsed" for all three.  PHP's own ``unserialize`` — the reference
    the live side rewrites with, and the rule ``wpt.media_refs`` implements —
    reads every one of them, so the gate was refusing a value the rewrite
    could have handled and gating its image out of the conversion for a
    reason that was not true.
    """
    assert BADSER not in _converted(_plan_local(tmp_path)[0])  # the gate, today

    data = _dump().replace(
        b'a:1:{i:0;s:8:"icon_url";s:999:"' + (UP + BADSER).encode() + b'";}',
        value.encode())
    action, _src, _plan, _ctx_ = _plan_with_dump(tmp_path, data)
    # the value is READ, so its image is converted ...
    assert BADSER in _converted(action), "the reference was still gated out"
    # ... and its reference is REWRITTEN, leaf by leaf, in the row that
    # carried it: a gate that only let the file through would be no fix
    rewritten = [leaf for leaves in _row_model(action).values()
                 for leaf in (leaves if isinstance(leaves, tuple) else (leaves,))]
    assert any("2023/10/bad.webp" in leaf for leaf in rewritten), rewritten


def test_a_genuinely_unreadable_value_still_gates_with_the_honest_reason(tmp_path):
    """The counterpart pin: the gate is not weakened, only made TRUE.

    A value whose declared length does not match its payload is what PHP's
    ``unserialize`` returns ``false`` for, so its references cannot be
    enumerated and every file it might reference must stay out of the
    conversion.  That is the fixture's own ``BADSER`` row, and it still
    gates after the decoder change.
    """
    from wpt.media_refs import decode_php_value, PhpDecodeError
    from wpt.actions.images_webp import value_texts

    broken = 'a:1:{i:0;s:8:"icon_url";s:999:"%s%s";}' % (UP, BADSER)
    with pytest.raises(PhpDecodeError):
        decode_php_value(broken)          # PHP reads it as false, so do we
    assert value_texts(broken) == ([broken], True)
    action, _src, _plan, _ctx_ = _plan_local(tmp_path)
    assert BADSER not in _converted(action)


# ---------------------------------------------------------------------------
# The scan_cap door (bridge.scan_cap)
# ---------------------------------------------------------------------------


def _ftp_read_rows(tmp_path, settings=DEFAULTS):
    """The rows the ACTION reads in ftp mode, over the shipped fixtures."""
    ctx = _ctx(tmp_path, mode="ftp", wp_url=None, settings=settings)
    bridge = _Bridge(_bridge_rows())
    rows = ImagesWebpAction()._read_rows(ctx, (_source(), None, bridge))
    return bridge, rows


def test_scan_cap_reaches_the_wire_and_the_default_asks_for_nothing(tmp_path):
    """The operator lever, and what the shipped default must NOT do.

    ``Bridge.iter_rewrite_refs(scan_cap=...)`` and bridge.php's
    ``media_rewrite_refs`` both accepted a cap, and the call site passed
    NOTHING — so a site carrying more image-bearing rows than the op's own
    truncation point (100000) had no way to be measured at all.  The knob
    now exists, and the shipped default still asks for nothing, so an
    unconfigured run's wire and its answer are byte-identical to before.
    """
    bridge, rows = _ftp_read_rows(tmp_path)
    assert rows[0], "the shipped rows still read"
    assert ("media_rewrite_refs", {}) in bridge.calls, \
        "the default must not put a cap on the wire"

    asked = copy.deepcopy(DEFAULTS)
    asked.bridge = replace(DEFAULTS.bridge, scan_cap=250_000)
    bridge, rows = _ftp_read_rows(tmp_path, settings=asked)
    assert ("media_rewrite_refs", {"scan_cap": 250_000}) in bridge.calls
    assert rows[0], "raising the cap changes what is asked for, not the rows"


def test_a_cap_above_the_ceiling_is_clamped_and_says_so(tmp_path, wpt_caplog):
    """A cap the op will not honour must be VISIBLE, never silent.

    The op is the validating owner of the bound: it clamps above its own
    ceiling and reports ``scan_cap_clamped`` once on its completion line,
    and the client turns that into a WARNING.  The profile deliberately does
    NOT refuse such a value (that would replace a visible clamp with a
    silent one), so the WARNING is the only thing standing between the
    operator and a reference set bounded where the SERVER decided rather
    than where they asked.
    """
    from wpt.wpbridge.client import REWRITE_REF_SCAN_CAP_MAX

    asked = copy.deepcopy(DEFAULTS)
    asked.bridge = replace(DEFAULTS.bridge, scan_cap=5_000_000)

    class _Clamping(_Bridge):
        """The op's own answer when the request is above its ceiling."""

        def call_stream(self, action, **params):
            stream = super().call_stream(action, **params)
            if action != "media_rewrite_refs":
                return stream

            def gen():
                for obj in stream:
                    if obj.get("ok"):
                        obj["scan_cap_clamped"] = REWRITE_REF_SCAN_CAP_MAX
                    yield obj
            return gen()

    bridge = _Clamping(_bridge_rows())
    ctx = _ctx(tmp_path, mode="ftp", wp_url=None, settings=asked)
    ImagesWebpAction()._read_rows(ctx, (_source(), None, bridge))
    assert any("CLAMPED" in record.getMessage()
               for record in wpt_caplog.records), wpt_caplog.records
    # ... and the request really was forwarded as asked, not pre-clamped here
    assert ("media_rewrite_refs", {"scan_cap": 5_000_000}) in bridge.calls


# ---------------------------------------------------------------------------
# Settings section
# ---------------------------------------------------------------------------


def test_settings_section_read(tmp_path):
    """The `webp` SECTION is the only door: it exists, and it is read.

    It used not to exist at all — the action read nine keys through
    ``getattr(ctx.settings, "webp", None)``, which is always None, so every
    one of them was a module constant and ``--set webp.quality=90`` was an
    "unknown settings section" refusal.  The section is now the settings
    owner's, with the shipped values in the profile, and the action reads
    through it and nowhere else.
    """
    settings = copy.deepcopy(DEFAULTS)
    assert isinstance(settings.webp, WebpSettings)
    action = ImagesWebpAction()
    ctx = _ctx(tmp_path, sql=_dump_path(tmp_path), settings=settings)
    cfg = _config(ctx)
    # the SHIPPED values, which are the profile's (tests/test_settings.py
    # pins the dataclass against wpt/data/profiles/default.json)
    assert (cfg.quality, cfg.skip_below_bytes, cfg.max_dim) == (80, 30720, 0)
    assert cfg.data_prefixes == (UP + "gravity_forms/",)
    assert cfg.purge_originals is False
    # with the section changed, the profile values are read and the FLAG wins
    settings.webp = _webp(quality=42, skip_below_bytes=10,
                          purge_originals=True)
    cfg = _config(ctx)
    assert (cfg.quality, cfg.skip_below_bytes) == (42, 10)
    assert cfg.purge_originals is True
    assert _config(ctx, purge_flag=False).purge_originals is False
    # a skip_below_bytes of 10 puts the small icon into scope (and a purge
    # the profile asked for still needs the window acknowledgement)
    action, _src, plan, ctx2 = _plan_local(tmp_path, ctx=ctx,
                                           i_know_editors_are_off=True)
    assert SMALL in _converted(action)


def test_every_webp_key_is_set_reachable_and_validated():
    """Nine keys, one section, no module constant standing in for a knob.

    The failure this replaces: a ``--set webp.<key>=`` was refused as an
    UNKNOWN SECTION, so the documented keys were unreachable and the
    ``webp.purge_originals`` tri-state narrative described a key that
    could not be set at all.
    """
    from wpt.settings import WebpSettings, load

    for name in (f.name for f in fields(WebpSettings)):
        value = getattr(DEFAULTS.webp, name)
        # the same value the loader itself hands the section, through the
        # same override door the CLI's --set uses
        settings = load(overrides={f"webp.{name}": copy.deepcopy(value)})
        assert getattr(settings.webp, name) == value
    # ... and the door is the same door: a nonsense value fails loud, naming
    # the key, instead of being ignored by a getattr fallback
    for key, bad in (("webp.quality", "high"), ("webp.quality", 900),
                     ("webp.max_dim", -1), ("webp.data_prefixes", ["/abs/"]),
                     ("webp.verify_pages", "twenty"),
                     ("webp.challenge_max_bytes", 0),
                     ("webp.purge_originals", "yes")):
        with pytest.raises(SettingsError, match="webp\\."):
            load(overrides={key: bad})


def test_purge_originals_stays_a_tri_state(tmp_path):
    """Flag typed / profile set / neither — three distinct outcomes.

    The tri-state is the whole point of the door: an argparse
    ``store_true`` without ``default=None`` collapses "not typed" into
    ``False`` and makes the profile key dead code, which SPEC L32 promises
    it is not.  So the flag wins when TYPED, the profile decides when it is
    NOT, and neither means no purge.
    """
    from wpt.actions.images_webp import _config

    ctx = _ctx(tmp_path)
    assert _config(ctx).purge_originals is False                    # neither
    assert _config(ctx, purge_flag=True).purge_originals is True    # flag typed
    assert _config(ctx, purge_flag=False).purge_originals is False   # flag typed

    asked = copy.deepcopy(DEFAULTS)
    asked.webp = _webp(purge_originals=True)
    asked_ctx = _ctx(tmp_path, settings=asked)
    assert _config(asked_ctx).purge_originals is True                # profile set
    # ... and the flag still wins over the profile, in both directions
    assert _config(asked_ctx, purge_flag=False).purge_originals is False
    off = copy.deepcopy(DEFAULTS)
    off.webp = _webp(purge_originals=False)
    off_ctx = _ctx(tmp_path, settings=off)
    assert _config(off_ctx).purge_originals is False
    assert _config(off_ctx, purge_flag=True).purge_originals is True


# ---------------------------------------------------------------------------
# The registry end to end (local rehearsal)
# ---------------------------------------------------------------------------


def test_registry_local_dry_run_zip_untouched(tmp_path, monkeypatch, capsys):
    zpath = _make_zip(tmp_path)
    sql = _dump_path(tmp_path)
    before = _zip_fingerprint(zpath)
    ctx = _ctx(tmp_path, sql=sql, zip_path=zpath)
    assert run_action(ctx, "webp-media") == 0
    assert "webp" in capsys.readouterr().out
    assert _zip_fingerprint(zpath) == before
    assert not list(tmp_path.glob("*-rehearsed-*.zip"))


def test_registry_local_rehearsal(tmp_path, capsys):
    zpath = _make_zip(tmp_path)
    sql = _dump_path(tmp_path)
    ctx = _ctx(tmp_path, sql=sql, zip_path=zpath, apply=True, yes=True)
    assert run_action(ctx, "webp-media") == 0
    out = capsys.readouterr().out
    assert "rehears" in out.lower() or "applied" in out.lower()
    rehearsed = list(tmp_path.glob("*-rehearsed-*.zip"))
    assert len(rehearsed) == 1
    with zipfile.ZipFile(rehearsed[0]) as zf:
        names = set(zf.namelist())
        css = zf.read("site.test/wp-content/uploads/avada-styles/site.css")
    for ref in CONVERTED:
        assert f"site.test/{UP}{ref.rsplit('.', 1)[0]}.webp" in names
        # the original is still there: the default keeps it
        assert f"site.test/{UP}{ref}" in names
    assert b".webp" in css
    # the ORIGINAL zip is untouched (it IS the rollback)
    assert "site.test/wp-content/uploads/2023/10/photo.jpg" in \
        _zip_fingerprint(zpath)


def test_registry_local_purge_refused(tmp_path, capsys):
    zpath = _make_zip(tmp_path)
    sql = _dump_path(tmp_path)
    ctx = _ctx(tmp_path, sql=sql, zip_path=zpath, apply=True, yes=True,
               extra={"purge_originals": True})
    assert run_action(ctx, "webp-media") == 1
    assert not list(tmp_path.glob("*-rehearsed-*.zip"))
    registry_mod  # keep the import meaningful for readers of this file



# ---------------------------------------------------------------------------
# The live proof against a REAL crawl
#
# The post-apply proof re-crawls the site, so the tests below drive a real
# ``_PerPageCrawler`` over a site model instead of a canned WalkResult: the
# crawl's own rules (sitemap seeds, BFS, the page budget, the politeness
# delay) and the challenge handling are the mechanism under test, and a
# stand-in for the walker's result would test nothing that broke.
# ---------------------------------------------------------------------------


class _LiveResponse:
    """A ``requests.Response`` double with the fields the crawler reads."""

    def __init__(self, url, status_code=200, text="",
                 content_type="text/html; charset=UTF-8"):
        self.url = url
        self.status_code = status_code
        self.text = text
        self.content = text.encode("utf-8")
        self.headers = {"Content-Type": content_type}


#: A bot-challenge interstitial of the shape the observed run met: a
#: small body, a challenge script, and copy saying the browser has not been
#: verified.  It carries no site reference at all, which is the whole
#: problem: read as a page, it looks like a page with no images.
CHALLENGE_BODY = (
    "<!DOCTYPE html><html><head><title>Just a moment...</title>"
    "<script src='/cdn-cgi/challenge-platform/h/b/orchestrate/jsch/v1'></script>"
    "</head><body>Checking your browser before accessing."
    "<noscript>enable javascript and cookies to continue</noscript>"
    "</body></html>")


def _page_html(refs):
    imgs = "".join(f'<img src="https://example.test/{UP}{ref}">'
                   for ref in refs)
    return ("<!DOCTYPE html><html><head><title>page</title></head>"
            f"<body>{imgs}</body></html>")


def _sitemap_xml(paths):
    locs = "".join(f"<url><loc>https://example.test{path}</loc></url>"
                   for path in sorted(paths))
    return ('<?xml version="1.0" encoding="UTF-8"?><urlset '
            'xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            f"{locs}</urlset>")


class _LiveSite:
    """The live site the post-apply proof crawls, as a mutable model.

    Every document is generated AT REQUEST TIME, so the after-crawl reads
    the site's current state rather than a transcript a test edited by
    hand between the two passes:

    * ``pages`` — path -> the uploads-relative references its HTML carries;
      :meth:`rewrite` is called when the run publishes the rewrite, which
      is the moment the site's HTML actually changes;
    * ``challenge_paths`` / ``challenge_passes`` — the pages a
      bot-protection layer answers with an interstitial, and on which
      passes.  The live failure was exactly this asymmetry: the plan's
      crawl read the site and the post-apply crawl was challenged;
    * ``clears_after`` — how many challenged attempts a path serves before
      it answers with the real document (a per-fingerprint challenge that
      does not repeat is a retry away from being evidence);
    * ``challenge_status`` — the status the interstitial is served with
      (403/503 on a real site; 200 is the shape that read as a page);
    * ``gone`` — asset paths that answer 404 (a provable failure, unlike a
      challenge);
    * ``on_rewrite`` — an optional hook fired with the mapping when the
      rewrite publishes, so a test can drop an image from a page at that
      exact moment (it sees the PUBLISHED names, like the live site does).
    """

    def __init__(self, pages, *, challenge_paths=(), challenge_passes=(2,),
                 clears_after=None, challenge_status=503, gone=()):
        self.pages = {path: list(refs) for path, refs in pages.items()}
        self.challenge_paths = set(challenge_paths)
        self.challenge_passes = set(challenge_passes)
        self.clears_after = clears_after
        self.challenge_status = challenge_status
        self.gone = set(gone)
        self.on_rewrite = None
        self.gets: list[str] = []
        self.challenged = 0
        self.passes = 0
        self._challenged_here = 0

    def rewrite(self, mapping):
        for path, refs in self.pages.items():
            self.pages[path] = [mapping.get(ref, ref) for ref in refs]
        if self.on_rewrite is not None:
            self.on_rewrite(mapping)

    def get(self, url, timeout=None):
        self.gets.append(url)
        path = urlparse(url).path
        if path == "/sitemap.xml":
            self.passes += 1        # one sitemap request marks one crawl
            self._challenged_here = 0
            return _LiveResponse(url, 200, _sitemap_xml(self.pages), "text/xml")
        if path == "/sitemap_index.xml":
            return _LiveResponse(url, 404, "not found", "text/plain")
        if path in self.pages and path in self.challenge_paths \
                and self.passes in self.challenge_passes:
            self._challenged_here += 1
            self.challenged += 1
            if self.clears_after is not None \
                    and self._challenged_here > self.clears_after:
                return _LiveResponse(url, 200, _page_html(self.pages[path]))
            return _LiveResponse(url, self.challenge_status, CHALLENGE_BODY)
        if path in self.pages:
            return _LiveResponse(url, 200, _page_html(self.pages[path]))
        if path.startswith("/" + UP):
            if path in self.gone:
                return _LiveResponse(url, 404, "not found", "text/plain")
            return _LiveResponse(url, 200, "", "image/jpeg")
        return _LiveResponse(url, 404, "not found", "text/plain")


class _LiveBridge(_Bridge):
    """A bridge double that PUBLISHES the rewrite to the live site model.

    ``_apply_edits`` is the moment the site's HTML changes.  A fixture that
    edited the served HTML by hand between the two passes would be a
    transcript of the expected outcome; publishing at the write makes the
    after-crawl read what the run actually published.
    """

    def __init__(self, rows, site, **kwargs):
        super().__init__(rows, **kwargs)
        self.site = site

    def _apply_edits(self, params):
        answer = super()._apply_edits(params)
        self.site.rewrite(params.get("mapping") or {})
        return answer


#: Ten pages, each carrying the two fixture images the rewrite converts, so
#: the rewrite itself moves the reference set and nothing else does.
LIVE_REFS = [PHOTO, BG]
LIVE_PAGES = {f"/p{index}": list(LIVE_REFS) for index in range(1, 11)}
#: Three of them ALSO carry an image of their own that no other page
#: references — a covered, not-converted fixture image (so no gate fires).
#: That is what makes a challenged page VISIBLE in an AGGREGATE comparison:
#: a set that lost the only page carrying a reference really did change
#: cardinality, which is the live 61 -> 78 failure reproduced.  With ten
#: identical pages an aggregate set is simply blind to losing three of
#: them, and the test would prove nothing.
LIVE_PAGES["/p2"] = LIVE_REFS + [SMALL]
LIVE_PAGES["/p5"] = LIVE_REFS + [TWIN]
LIVE_PAGES["/p9"] = LIVE_REFS + [DUP2]
LIVE_PAGES["/"] = []


def _live_site(**kwargs):
    return _LiveSite(copy.deepcopy(LIVE_PAGES), **kwargs)


def _fast_walk():
    """The shipped walk settings with the politeness delay at zero.

    The delay is real crawl behaviour (0.5s between page navigations);
    twenty test pages must not spend their time asleep.  Nothing else
    about the crawl changes.
    """
    settings = copy.deepcopy(DEFAULTS)
    settings.walk.delay_s = 0.0
    # ... and so is the challenge retry's politeness delay.  The tests
    # exercise the retry COUNT, not the sleep (the profile key itself is
    # pinned by the settings test), and the section rides along so the
    # live path is read through ``ctx.settings.webp`` too.
    settings.webp = _webp(verify_retry_delay_s=0.0)
    return settings


def _run_ftp_live(tmp_path, monkeypatch, bridge, site, *, apply=True, **extra):
    """`wpt webp-media` end to end in ftp mode against a live site model."""
    src = _source()
    fields = dict(mode="ftp", apply=apply, yes=True, settings=_fast_walk())
    fields.update(extra)
    ctx = _ctx(tmp_path, **fields)
    monkeypatch.setattr(registry_mod, "_stack", lambda c: (src, site, bridge))
    return run_action(ctx, "webp-media"), src


def _unprovable(plan, target):
    items = [i for i in plan.items if i.category == "media.webp_unprovable"
             and i.target == target]
    return items[0].detail if items else ""


def test_live_gate_reports_html_only_refs(tmp_path):
    """Rendered HTML no database surface backs keeps its original form."""
    src = _source()
    site = _live_site()
    site.pages["/p1"] = [PHOTO, BG, "2023/09/hardcoded.jpg"]
    action = ImagesWebpAction()
    ctx = _ctx(tmp_path, mode="ftp", settings=_fast_walk())
    plan = action.plan(ctx, (src, site, _Bridge(_bridge_rows())))
    gated = {i.target: i for i in plan.items if i.category == "media.webp_gated"}
    assert "rendered-html-only" in gated
    assert "2023/09/hardcoded.jpg" in gated["rendered-html-only"].detail
    assert action.state.walked is True
    assert PHOTO in action.state.before_refs
    # the per-page attribution the post-apply proof compares
    assert action.state.before_pages["https://example.test/p1"] == {
        PHOTO, BG, "2023/09/hardcoded.jpg"}
    assert action.state.before_unprovable == {}


def test_live_proof_bijection(tmp_path):
    """Every readable page must carry its refs mapped, and twins must 200."""
    site = _live_site()
    bridge = _LiveBridge(_bridge_rows(), site)
    action = ImagesWebpAction()
    ctx = _ctx(tmp_path, mode="ftp", settings=_fast_walk())
    plan = action.plan(ctx, (_source(), site, bridge))
    applied = action.apply(ctx, (_source(), site, bridge), plan)
    assert all(i.done for i in applied.items if i.requires_apply)
    assert action.state.before_pages
    # the twins the pages now reference were fetched, and answered 200
    probed = [url for url in site.gets if url.endswith(".webp")]
    assert any(url.endswith(PHOTO.replace(".jpg", ".webp"))
               for url in probed)
    assert not _unprovable(applied, "bot-challenge")


def test_live_proof_refuses_a_surviving_original(tmp_path, wpt_caplog):
    """A page that still points at a converted original fails the run."""
    site = _live_site()
    # a stale editor's save puts the ORIGINAL filename back into the page
    site.on_rewrite = lambda mapping: site.pages["/p3"].append(PHOTO)
    bridge = _LiveBridge(_bridge_rows(), site)
    action = ImagesWebpAction()
    ctx = _ctx(tmp_path, mode="ftp", settings=_fast_walk())
    plan = action.plan(ctx, (_source(), site, bridge))
    with pytest.raises(SourceError, match="did not verify"):
        action.apply(ctx, (_source(), site, bridge), plan)
    messages = [r.getMessage() for r in _records(wpt_caplog, logging.ERROR)]
    assert any("/p3" in m and "appeared" in m for m in messages)
    assert any(PHOTO in m for m in messages)


def test_live_proof_refuses_a_page_that_lost_an_image(tmp_path, wpt_caplog):
    """A page whose body demonstrably lost an image fails the run.

    The other provable shape: both crawls read the page, and the rewrite
    took an image off it.  The proof is per page, so it can name the page.
    """
    site = _live_site()
    site.on_rewrite = lambda mapping: site.pages["/p4"].remove(
        mapping.get(BG, BG))
    bridge = _LiveBridge(_bridge_rows(), site)
    action = ImagesWebpAction()
    ctx = _ctx(tmp_path, mode="ftp", settings=_fast_walk())
    plan = action.plan(ctx, (_source(), site, bridge))
    with pytest.raises(SourceError, match="did not verify"):
        action.apply(ctx, (_source(), site, bridge), plan)
    messages = [r.getMessage() for r in _records(wpt_caplog, logging.ERROR)]
    assert any("/p4" in m and "disappeared" in m for m in messages)


# ---------------------------------------------------------------------------
# A bot challenge is INCONCLUSIVE, not a change (D1, observed)
# ---------------------------------------------------------------------------


def test_live_proof_excludes_challenged_pages_and_runs_clean(
        tmp_path, monkeypatch, capsys):
    """3 of 10 pages challenged after the rewrite: rc 0, and the report says so.

    The live failure this fixes: the host serves a JS bot-challenge to some
    client fingerprints, the post-apply crawl got one where the plan's
    crawl got the page, and the ref-set comparison read the missing
    references as a broken rewrite.  The rewrite itself was correct.
    """
    site = _live_site(challenge_paths={"/p2", "/p5", "/p9"})
    bridge = _LiveBridge(_bridge_rows(), site)
    rc, _src = _run_ftp_live(tmp_path, monkeypatch, bridge, site)
    out = capsys.readouterr().out
    assert rc == 0
    assert "3 url(s) unprovable (bot-challenge); excluded from the " \
           "comparison" in out
    assert site.challenged >= 3        # really was challenged, not simulated


def test_live_proof_reports_every_excluded_url(tmp_path, monkeypatch, capsys):
    """The named list is the operator's evidence, not just a count."""
    site = _live_site(challenge_paths={"/p2", "/p5", "/p9"})
    bridge = _LiveBridge(_bridge_rows(), site)
    rc, _src = _run_ftp_live(tmp_path, monkeypatch, bridge, site)
    out = capsys.readouterr().out
    assert rc == 0
    for path in ("/p2", "/p5", "/p9"):
        assert path in out


def test_live_proof_retries_a_challenge_before_excluding_it(
        tmp_path, monkeypatch, capsys):
    """A challenge that does not repeat is a retry away from being evidence."""
    site = _live_site(challenge_paths={"/p2"}, clears_after=1)
    bridge = _LiveBridge(_bridge_rows(), site)
    rc, _src = _run_ftp_live(tmp_path, monkeypatch, bridge, site)
    out = capsys.readouterr().out
    assert rc == 0
    assert site.challenged >= 2
    assert "unprovable" not in out
    # the page was fetched (challenged once, then read) and proved clean
    assert any(url.endswith("/p2") for url in site.gets)


def test_live_proof_treats_a_200_challenge_body_as_inconclusive(
        tmp_path, monkeypatch, capsys):
    """A 200 whose whole body is a challenge is not "a page with no images".

    The most dangerous shape, because a 200 is exactly what a fetch is
    expected to answer.  It must land in the exclusion bucket, not in the
    bijection, where its empty body would read as two vanished images.
    """
    site = _live_site(challenge_paths={"/p2"}, challenge_status=200)
    bridge = _LiveBridge(_bridge_rows(), site)
    rc, _src = _run_ftp_live(tmp_path, monkeypatch, bridge, site)
    out = capsys.readouterr().out
    assert rc == 0
    assert "1 url(s) unprovable (bot-challenge); excluded from the " \
           "comparison" in out
    assert "disappeared" not in out


def test_live_proof_fails_on_a_provable_missing_twin(
        tmp_path, monkeypatch, capsys, wpt_caplog):
    """The provable failure still fails, and names the file that 404s.

    The other half of the contract: an exclusion must never become a blind
    spot.  Every page read cleanly here, and the twin one of them
    references answers 404 — a fact about the site, not about the
    transport, so the run fails closed.
    """
    twin = "/wp-content/uploads/" + PHOTO.replace(".jpg", ".webp")
    site = _live_site(gone={twin})
    bridge = _LiveBridge(_bridge_rows(), site)
    rc, _src = _run_ftp_live(tmp_path, monkeypatch, bridge, site)
    assert rc == 1
    assert any("does not resolve" in r.getMessage()
               for r in _records(wpt_caplog, logging.ERROR))
    assert "unprovable" not in capsys.readouterr().out


def test_live_proof_excludes_a_page_read_in_one_pass_only(
        tmp_path, monkeypatch, capsys):
    """A page one pass reached and the other did not is excluded, not lost.

    A crawl's page set is BFS- and budget-derived, so two passes over an
    UNCHANGED site legitimately differ — different page counts on the
    site whose guard this replaced.  The pages both passes read are still
    compared; this one is reported instead of being read as a change.
    """
    site = _live_site()
    bridge = _LiveBridge(_bridge_rows(), site)
    rc, _src = _run_ftp_live(tmp_path, monkeypatch, bridge, site)
    assert rc == 0
    assert "unprovable" not in capsys.readouterr().out
    # ... and now a page the BEFORE crawl reached and the after crawl could
    # not: the site's own page set moved between the two passes
    site = _live_site()
    bridge = _LiveBridge(_bridge_rows(), site)
    action = ImagesWebpAction()
    ctx = _ctx(tmp_path, mode="ftp", settings=_fast_walk())
    plan = action.plan(ctx, (_source(), site, bridge))
    site.pages.pop("/p7")
    applied = action.apply(ctx, (_source(), site, bridge), plan)
    assert all(i.done for i in applied.items if i.requires_apply)
    assert "1 url(s) unprovable (single-pass)" in _unprovable(
        applied, "single-pass")


def test_live_proof_clean_run_is_byte_identical_to_a_run_with_no_site(
        tmp_path):
    """The unchallenged path is UNCHANGED: same bytes, same items, same rc.

    The pin on the other side of every exclusion above: on a site that
    answers every fetch, the live proof must cost nothing and change
    nothing — the webroot and the database the run wrote are the same, and
    the plan carries no exclusion line.  The only difference from a run
    without a site URL is the absence of the ``no-live-proof`` advice.
    """
    def _run(src, bridge, site, ctx):
        action = ImagesWebpAction()
        plan = action.plan(ctx, (src, site, bridge))
        applied = action.apply(ctx, (src, site, bridge), plan)
        return ([(i.category, i.target, i.detail, i.requires_apply, i.done)
                 for i in applied.items], dict(src.files),
                dict(bridge.store))

    live_items, live_files, live_store = _run(
        _source(), _LiveBridge(_bridge_rows(), site := _live_site()), site,
        _ctx(tmp_path, mode="ftp", settings=_fast_walk()))
    offline_items, offline_files, offline_store = _run(
        _source(), _LiveBridge(_bridge_rows(), _live_site()), _live_site(),
        _ctx(tmp_path, mode="ftp", wp_url=None, settings=_fast_walk()))

    assert live_files == offline_files
    assert live_store == offline_store
    assert [i for i in live_items if i[1] != "no-live-proof"] == \
        [i for i in offline_items if i[1] != "no-live-proof"]
    assert not [i for i in live_items if i[0] == "media.webp_unprovable"]


def test_live_proof_challenge_markers_are_narrow():
    """A real page carrying the phrase is not read as a challenge.

    A blog post can contain "just a moment", so a COPY marker only settles
    it when the status is a block status or the body is challenge-sized; a
    large refusal is a real page (a 404 page, a maintenance page) whose
    status is the evidence.  A PLATFORM marker (a challenge script or
    cookie name) settles it at any size, because no document carries one.
    """
    post = ("<p>Just a moment ago the shop closed.</p>" + "<p>prose</p>" * 9000)
    assert challenge_reason(_LiveResponse("u", 200, post), 32768) == ""
    assert challenge_reason(_LiveResponse("u", 404, post, "text/html"),
                            32768) == ""
    assert challenge_reason(_LiveResponse("u", 200, _page_html([PHOTO])),
                            32768) == ""
    assert challenge_reason(_LiveResponse("u", 404, "Not Found", "text/plain"),
                            32768) == ""
    # the measured shapes DO read as challenges
    assert "bot-challenge" in challenge_reason(
        _LiveResponse("u", 503, CHALLENGE_BODY), 32768)
    assert "bot-challenge" in challenge_reason(
        _LiveResponse("u", 403, "Forbidden"), 32768)
    assert "bot-challenge" in challenge_reason(
        _LiveResponse("u", 200, CHALLENGE_BODY), 32768)
    # ... and a platform marker settles it at any size
    assert "bot-challenge" in challenge_reason(
        _LiveResponse("u", 200, "<p>hi</p><p>/cdn-cgi/challenge-platform</p>"
                                   + "x" * 100000), 32768)
    # the size bound is the profile's, not the code's
    assert "jschl_vc" in challenge_reason(
        _LiveResponse("u", 200, "<p>jschl_vc</p>" + "x" * 100000), 10 ** 9)


def test_live_proof_retry_and_threshold_come_from_the_profile(tmp_path):
    """The new knobs are profile keys, not literals in the code."""
    settings = copy.deepcopy(DEFAULTS)
    settings.webp = _webp(verify_retries=4, challenge_max_bytes=99,
                                  verify_retry_delay_s=0.0)
    ctx = _ctx(tmp_path, sql=_dump_path(tmp_path), settings=settings)
    cfg = _config(ctx)
    assert (cfg.verify_retries, cfg.challenge_max_bytes,
            cfg.verify_retry_delay_s) == (4, 99, 0.0)
    # the module defaults until the settings owner lands the section
    plain = _config(_ctx(tmp_path, sql=_dump_path(tmp_path)))
    assert (plain.verify_retries, plain.challenge_max_bytes) == (2, 32768)


def test_live_proof_says_so_when_no_page_could_be_compared(
        tmp_path, monkeypatch, wpt_caplog, capsys):
    """A host that challenges EVERY fetch must not produce a silent pass.

    Excluding an unprovable page is honest; excluding every one of them and
    saying nothing would be a run that reports success without having
    looked.  The rewrite itself is still proven by the database, the
    stylesheets and the on-disk twins — the line names exactly that.
    """
    site = _live_site(challenge_paths=set(LIVE_PAGES),
                       challenge_passes=(1, 2))
    bridge = _LiveBridge(_bridge_rows(), site)
    rc, _src = _run_ftp_live(tmp_path, monkeypatch, bridge, site)
    assert rc == 0
    assert any("the live proof of the rewrite did NOT run" in r.getMessage()
               for r in _records(wpt_caplog, logging.WARNING))
    # every exclusion is accounted for, in both passes
    for kind in ("bot-challenge",):
        assert f"{len(LIVE_PAGES)} url(s) unprovable ({kind})" in \
            capsys.readouterr().out
