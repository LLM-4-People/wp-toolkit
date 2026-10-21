"""Tests for the optimize-media action (wpt.actions.optimize_media) — W7g.

REAL Pillow round-trips over synthetic images (fixed-seed random noise:
incompressible, so JPEG quality/resize changes dominate size; no
network, no sleeps, no tmp files — everything is in-memory).  FakeSource
trees + the shipped profile (tests/actions/test_clean_files.py
conventions); the registry end-to-end tests monkeypatch
``wpt.actions.registry._stack`` for the fake ftp-mode stack and run the
REAL ``run_action`` flow over a REAL ZipSource stack for local mode.

Test -> behavior map (W7g task list):
  test_registration ........................ optimize-media registered as
        the INSTANCE under applies=("ftp", "local")
  test_recompress_jpeg_quality_honored ..... a q95 noise JPEG recompresses
        to a SMALLER decodable JPEG at the settings quality, dims
        unchanged (no resize below max)
  test_recompress_jpeg_max_dim ............. a 3000px image comes back
        <= jpeg_max_dim on BOTH axes, aspect preserved, still JPEG
  test_recompress_png_max_dim .............. a 1600x600 PNG comes back
        <= png_max_dim on both axes, still PNG
  test_recompress_rgba_png_stays_png ....... an RGBA PNG recompresses to
        PNG with the alpha mode preserved (never JPEG)
  test_recompress_exif_orientation_ ........ a crafted orientation-6 JPEG
        (real EXIF bytes) recompresses to the DISPLAY orientation
        (dims swapped, orientation tag gone)
  test_recompress_exif_transpose_before_ .... order pin: a thumbnail spy
        sees the TRANSPOSED dims (3000x800 o6 -> (800, 3000)) — EXIF
        transpose happens BEFORE the resize
  test_recompress_undecodable_returns_none . garbage / truncated JPEG /
        non-image suffix -> None (the skip signal)
  test_plan_filters_candidates ............. uploads-only (plugins and
        webroot-root .jpg never planned), suffix gate (.gif skipped),
        case-insensitive suffix (.JPG planned), size gate (a tiny JPEG
        skipped), scan count in the summary
  test_plan_shipped_profile_protects_form_ .. the SHIPPED profile's
        gravity_forms exclusion: submission records are absent from the
        plan, the count lands in the plan summary, and the sibling image
        is still planned
  test_plan_set_override_replaces_the_ ...... --set with a custom prefix
        list REPLACES the shipped one (the form records come back into
        scope, the custom subtree leaves it), the count follows
  test_plan_empty_exclusion_list_ ... ...... an empty list means "no
        exclusions": every uploads image is planned again
  test_plan_excluded_file_is_never_read .... an excluded file is not even
        downloaded (a read that would raise proves the gate runs first)
  test_plan_exclusion_gauge_matches_apply .. the dry-run plan and the
        applied result cover exactly the same files (the live gauge)
  test_plan_skip_below_bytes_from_settings . skip_below_bytes=200000
        drops a 77KB candidate — the threshold comes from settings
  test_plan_min_savings_ratio_from_settings . min_savings_ratio=0.9
        drops a ~49%-savings candidate — the ratio comes from settings
  test_plan_savings_ratio_skips_already_ .... a q82-saved JPEG (the
        action's own encoder settings) and a within-dims PNG are NOT
        planned; the q95 sibling is
  test_plan_corrupt_skipped_with_debug_log . a >30KB garbage .jpg is
        skipped with exactly ONE debug log; the batch continues
  test_plan_sorted_items_with_bytes_and_ .... walk order != target order
        still yields target-sorted items; detail/bytes_est match the
        recompress formula; backup_tables == [] deliberate; ONE info
        summary
  test_plan_empty_tree ...................... no uploads -> empty plan,
        backup_tables == []
  test_apply_uploads_recompressed_bytes .... planned files really
        replaced in the FakeSource (write op per item, in plan order,
        byte-identical to _recompress, smaller), all done, per-upload
        info logs
  test_apply_fresh_no_savings_marks_ ........ the file replaced by an
        already-optimal version after the plan: done=True, detail
        "already optimal", NO upload
  test_apply_failing_write_continues ........ one injected write failure:
        that item done=False + one warning, the rest still applied
  test_apply_skips_non_apply_items .......... requires_apply=False items
        are neither uploaded nor marked done
  test_apply_local_zip_read_only ............ ZipSource: every write
        refused, all items done=False, warnings not exceptions
  test_registry_local_dry_run_zip_untouched . REAL zip stack, dry run:
        rc 0, plan printed, small/non-uploads leaves absent, every zip
        entry byte-identical afterwards
  test_registry_local_apply_refused ........ local --apply: rc 1, the
        audit-only refusal, zip untouched
  test_registry_ftp_apply_end_to_end ........ fake ftp stack apply+yes:
        the planned file uploaded to the FakeSource (read back smaller
        and byte-identical to _recompress), the pre-action snapshot
        manifest lists exactly the planned FILE, rc 0
"""

import io
import json
import logging
import random
import time
import zipfile
from dataclasses import replace

import PIL.Image
import pytest

from tests.fakes import FakeSource
from wpt.actions import registry as registry_mod
from wpt.actions.optimize_media import (
    OptimizeMediaAction,
    _recompress,
    _suffix_of,
)
from wpt.actions.registry import get_action, run_action
from wpt.audit.media import _UPLOADS_PREFIX
from wpt.cli import Ctx
from wpt.report import Plan, human_bytes
from wpt.settings import load
from wpt.sources.zip import ZipSource
from wpt.types import DeadlineExceeded, PlanItem, SourceError

#: The shipped profile — every threshold exactly as users get it
#: (jpeg_quality 82, jpeg_max_dim 2560, png_max_dim 1200,
#: min_savings_ratio 0.2, skip_below_bytes 30720, and the shipped
#: exclude_prefixes form-record subtree).
DEFAULTS = load()

#: The one planned JPEG used across plan/apply/registry tests: 256x256
#: fixed-seed noise at quality 95 (77,494 bytes — above skip_below_bytes;
#: recompressing at q82 saves ~49%, well over min_savings_ratio).
BIG_JPEG = "wp-content/uploads/2024/05/big.jpg"

#: A Gravity Forms submission record: a PEOPLE-uploaded photo in the form
#: plugin's upload dir.  An observed migration recompressed these under
#: a profile with no exclusion, which is why the shipped default covers
#: the subtree.
FORM_RECORD = "wp-content/uploads/gravity_forms/1/2/inbound-sample.jpg"

#: The shipped default list, as operators get it.
SHIPPED_EXCLUDES = ["wp-content/uploads/gravity_forms/"]


@pytest.fixture
def wpt_caplog(caplog):
    """caplog wired to the non-propagating wpt logger tree (see
    tests/actions/test_clean_files.py — the wpt parent never reaches root)."""
    parent = logging.getLogger("wpt")
    parent.addHandler(caplog.handler)
    with caplog.at_level(logging.DEBUG, logger="wpt"):
        yield caplog
    parent.removeHandler(caplog.handler)


class FailingWriteSource(FakeSource):
    """FakeSource whose write_bytes fails (SourceError) for fail_paths."""

    def __init__(self, fail_paths):
        super().__init__()
        self.fail_paths = set(fail_paths)

    def write_bytes(self, path, data, *, allow_config=False):
        if path in self.fail_paths:
            raise SourceError(f"injected write failure: {path}")
        super().write_bytes(path, data, allow_config=allow_config)


class UnreadablePathSource(FakeSource):
    """FakeSource whose read_bytes FAILS for forbidden paths — a SourceError
    is the plan phase's fail-closed signal, so a read the plan must never
    make fails the test loudly instead of passing quietly."""

    def __init__(self, forbidden):
        super().__init__()
        self.forbidden = set(forbidden)

    def read_bytes(self, path):
        if path in self.forbidden:
            raise SourceError(f"must not be read: {path}")
        return super().read_bytes(path)


# ------------------------------------------------------------------ helpers


def _ctx(tmp_path, *, settings=DEFAULTS, **overrides):
    """An optimize-media Ctx; ftp-mode defaults, overridable per test."""
    fields = dict(
        source="ftp://example.com",
        settings=settings,
        command="optimize-media",
        apply=False,
        yes=False,
        backup_dir=tmp_path / "backup",
        wp_url="https://example.com",
    )
    fields.update(overrides)
    return Ctx(**fields)


def _noise(w, h, mode="RGB", seed=1234):
    """A fixed-seed random noise image (incompressible)."""
    rng = random.Random(seed)
    bands = 4 if mode == "RGBA" else 3
    return PIL.Image.frombytes(mode, (w, h), rng.randbytes(w * h * bands))


def _jpeg(w, h, *, quality=95, seed=1234, orientation=None):
    """A noise JPEG; ``orientation`` embeds a real EXIF orientation tag."""
    img = _noise(w, h, seed=seed)
    buf = io.BytesIO()
    if orientation is not None:
        exif = PIL.Image.Exif()
        exif[274] = orientation  # ExifTags.Base.Orientation
        img.save(buf, format="JPEG", quality=quality, exif=exif)
    else:
        img.save(buf, format="JPEG", quality=quality)
    return buf.getvalue()


def _png(w, h, *, mode="RGB", seed=1234):
    buf = io.BytesIO()
    _noise(w, h, mode=mode, seed=seed).save(buf, format="PNG")
    return buf.getvalue()


def _optimal_jpeg(w, h, *, seed=1234, media=DEFAULTS.media_optimize):
    """A JPEG saved with the action's own encoder settings: recompressing
    it again cannot clear min_savings_ratio (a double-encode at the same
    quality is roughly size-neutral — measured ~2-6%)."""
    buf = io.BytesIO()
    _noise(w, h, seed=seed).save(
        buf, format="JPEG", quality=media.jpeg_quality,
        optimize=True, progressive=True)
    return buf.getvalue()


def _expected_item_fields(src, target, media=DEFAULTS.media_optimize):
    """(detail, bytes_est) the plan must produce for ``target``."""
    original = src.files[target]
    optimized = _recompress(original, _suffix_of(target), media)
    return (
        f"{target[len(_UPLOADS_PREFIX):]} "
        f"({human_bytes(len(original))} -> {human_bytes(len(optimized))})",
        len(original) - len(optimized),
    )


def _records(caplog, name, level):
    return [r for r in caplog.records if r.name == name and r.levelno == level]


def _write_ops(src):
    return [path for _ts, op, path in src.ops if op == "write"]


def _zip_fingerprint(zpath):
    """(name, size, crc) per entry — pins a zip's exact contents."""
    with zipfile.ZipFile(zpath) as zf:
        return [
            (info.filename, info.file_size, info.CRC)
            for info in sorted(zf.infolist(), key=lambda i: i.filename)
        ]


def _make_zip(tmp_path, name="site.zip"):
    """A real webroot zip: one compressible uploads JPEG, one tiny JPEG
    (below skip_below_bytes), one non-uploads .jpg that is never read, and
    one Gravity Forms submission record (in scope for every rule except the
    shipped exclusion — never planned, never touched)."""
    zpath = tmp_path / name
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("wp-content/uploads/2024/05/big.jpg", _jpeg(256, 256))
        zf.writestr("wp-content/uploads/2024/05/small.jpg",
                    _jpeg(16, 16, quality=90))
        zf.writestr(FORM_RECORD, _jpeg(256, 256, seed=41))
        zf.writestr("wp-content/plugins/x.jpg", b"j" * 40000)
        zf.writestr("wp-config.php", b"<?php cfg")
    return zpath


# ------------------------------------------------------------- registration


def test_registration():
    record = get_action("optimize-media")
    assert record is not None
    assert record.applies == ("ftp", "local")
    assert isinstance(record.action, OptimizeMediaAction)  # the instance


# --------------------------------------------------- _recompress unit tests


def test_R17_plan_and_apply_stop_at_the_run_deadline(monkeypatch, tmp_path):
    """R17-6-P2: optimize-media had no Deadline use, so a slow recompress
    outlived the budget and an expired apply still wrote.  Both phases now
    construct the ONE run deadline and check before every read/recompress/
    write and at the end."""
    import wpt.actions.optimize_media as mod

    src = FakeSource()
    src.files[BIG_JPEG] = _jpeg(256, 256, quality=95)
    ctx = _ctx(tmp_path, deadline_s=0.05)
    action = OptimizeMediaAction()

    def _slow(data, suffix, media):
        time.sleep(0.08)
        return data[:-100]

    monkeypatch.setattr(mod, "_recompress", _slow)
    started = time.monotonic()
    with pytest.raises(DeadlineExceeded):
        action.plan(ctx, (src, None, None))
    assert time.monotonic() - started < 0.5

    item = PlanItem(category="media.oversized", target=BIG_JPEG,
                    detail="d", bytes_est=100)
    plan = Plan(items=[item], backup_tables=[])
    before = src.files[BIG_JPEG]
    started = time.monotonic()
    with pytest.raises(DeadlineExceeded):
        action.apply(ctx, (src, None, None), plan)
    assert time.monotonic() - started < 0.5
    assert src.files[BIG_JPEG] == before
    assert item.done is False


def test_recompress_jpeg_quality_honored():
    media = DEFAULTS.media_optimize
    data = _jpeg(256, 256, quality=95)
    out = _recompress(data, "jpg", media)
    assert out is not None
    assert len(out) < len(data)  # quality 82 beats quality 95 on noise
    with PIL.Image.open(io.BytesIO(out)) as img:
        assert img.format == "JPEG"
        assert img.mode == "RGB"
        assert img.size == (256, 256)  # within dims: no resize, quality only


def test_recompress_jpeg_max_dim():
    media = DEFAULTS.media_optimize
    data = _jpeg(3000, 800, seed=5)
    out = _recompress(data, "jpg", media)
    assert out is not None
    with PIL.Image.open(io.BytesIO(out)) as img:
        assert img.format == "JPEG"
        assert img.width <= media.jpeg_max_dim
        assert img.height <= media.jpeg_max_dim
        assert abs(img.width / img.height - 3000 / 800) < 0.02  # aspect kept


def test_recompress_png_max_dim():
    media = DEFAULTS.media_optimize
    data = _png(1600, 600, seed=6)
    out = _recompress(data, "png", media)
    assert out is not None
    with PIL.Image.open(io.BytesIO(out)) as img:
        assert img.format == "PNG"
        assert img.width <= media.png_max_dim
        assert img.height <= media.png_max_dim
        assert abs(img.width / img.height - 1600 / 600) < 0.02  # aspect kept


def test_recompress_rgba_png_stays_png():
    media = DEFAULTS.media_optimize
    data = _png(1600, 600, mode="RGBA", seed=7)
    out = _recompress(data, "png", media)
    assert out is not None
    with PIL.Image.open(io.BytesIO(out)) as img:
        assert img.format == "PNG"  # never JPEG
        assert img.mode == "RGBA"   # alpha preserved


def test_recompress_exif_orientation_applied():
    # stored 40x20 with a real EXIF orientation-6 tag: the recompressed
    # pixels are the DISPLAY orientation (20x40) and carry no orientation
    # tag (crafted EXIF bytes — no monkeypatch needed here)
    media = DEFAULTS.media_optimize
    data = _jpeg(40, 20, orientation=6, seed=11)
    out = _recompress(data, "jpg", media)
    assert out is not None
    with PIL.Image.open(io.BytesIO(out)) as img:
        assert img.size == (20, 40)
        assert img.getexif().get(274) is None


def test_recompress_exif_transpose_before_resize(monkeypatch):
    # ORDER pin: a stored 3000x800 orientation-6 image displays as
    # 800x3000 — the resize must run on the TRANSPOSED image. A spy on
    # PIL.Image.Image.thumbnail records the dims it is called with.
    media = DEFAULTS.media_optimize
    data = _jpeg(3000, 800, orientation=6, seed=13)
    seen = []
    original_thumbnail = PIL.Image.Image.thumbnail

    def spy(self, size, resample=PIL.Image.Resampling.BICUBIC,
            reducing_gap=2.0):
        seen.append((self.size, size))
        return original_thumbnail(self, size, resample, reducing_gap)

    monkeypatch.setattr(PIL.Image.Image, "thumbnail", spy)
    out = _recompress(data, "jpg", media)
    assert seen == [((800, 3000), (media.jpeg_max_dim, media.jpeg_max_dim))]
    with PIL.Image.open(io.BytesIO(out)) as img:
        assert img.width <= media.jpeg_max_dim
        assert img.height <= media.jpeg_max_dim


def test_recompress_undecodable_returns_none():
    media = DEFAULTS.media_optimize
    assert _recompress(b"not an image at all" * 3000, "jpg", media) is None
    # truncated JPEG: open succeeds, the decode inside fails (OSError)
    whole = _jpeg(256, 256, seed=17)
    assert _recompress(whole[: len(whole) // 2], "jpg", media) is None
    # a suffix _recompress has no encoder for
    assert _recompress(_jpeg(64, 64, seed=19), "gif", media) is None


# ------------------------------------------------------------------- plan


def test_plan_filters_candidates(tmp_path, wpt_caplog):
    src = FakeSource()
    src.files = {
        BIG_JPEG: _jpeg(256, 256),                                   # planned
        "wp-content/uploads/2024/05/noise.JPG": _jpeg(256, 256, seed=2),  # .JPG
        "wp-content/uploads/2024/05/pic.jpeg": _jpeg(256, 256, seed=5),   # .jpeg
        "wp-content/uploads/2024/05/tiny.jpg": _jpeg(16, 16, quality=90),  # size gate
        "wp-content/uploads/2024/05/anim.gif": b"g" * 40000,         # suffix gate
        "wp-content/plugins/huge.jpg": _jpeg(256, 256, seed=3),     # path gate
        "banner.jpg": _jpeg(256, 256, seed=4),                      # path gate
    }
    plan = OptimizeMediaAction().plan(_ctx(tmp_path), (src, None, None))
    assert [i.target for i in plan.items] == [
        "wp-content/uploads/2024/05/big.jpg",
        "wp-content/uploads/2024/05/noise.JPG",  # case-insensitive suffix
        "wp-content/uploads/2024/05/pic.jpeg",
    ]
    assert all(i.category == "media.oversized" for i in plan.items)
    summaries = _records(wpt_caplog, "wpt.actions.optimize_media", logging.INFO)
    assert len(summaries) == 1
    assert "3 candidate(s) scanned" in summaries[0].getMessage()
    assert "3 optimizable" in summaries[0].getMessage()
    assert "0 file(s) skipped by exclude_prefixes" in summaries[0].getMessage()


def test_plan_shipped_profile_protects_form_records(tmp_path, wpt_caplog):
    """[live migration] The SHIPPED profile keeps the Gravity Forms
    submission records out of the plan entirely: a people-uploaded photo
    is a quasi-record, not site content to recompress."""
    assert DEFAULTS.media_optimize.exclude_prefixes == SHIPPED_EXCLUDES
    src = FakeSource()
    src.files = {
        FORM_RECORD: _jpeg(256, 256, seed=41),  # a submission record
        BIG_JPEG: _jpeg(256, 256),              # ordinary site content
    }
    plan = OptimizeMediaAction().plan(_ctx(tmp_path), (src, None, None))
    assert [i.target for i in plan.items] == [BIG_JPEG]
    # silence, not a finding: no item, no note, no path anywhere in the plan
    assert FORM_RECORD not in repr(plan.items)
    summaries = _records(wpt_caplog, "wpt.actions.optimize_media", logging.INFO)
    assert len(summaries) == 1
    assert "1 candidate(s) scanned" in summaries[0].getMessage()
    assert "1 optimizable" in summaries[0].getMessage()
    # operator visibility: the skipped COUNT is reported, the paths are not
    assert "1 file(s) skipped by exclude_prefixes" in summaries[0].getMessage()
    assert FORM_RECORD not in summaries[0].getMessage()


def test_plan_excluded_file_is_never_downloaded(tmp_path):
    """The exclusion runs BEFORE any read: an excluded candidate is never
    downloaded (the walk entry alone decides), and a plan that did read it
    would fail closed on this source."""
    src = UnreadablePathSource({FORM_RECORD})
    src.files = {FORM_RECORD: _jpeg(256, 256, seed=43), BIG_JPEG: _jpeg(256, 256)}
    plan = OptimizeMediaAction().plan(_ctx(tmp_path), (src, None, None))
    assert [i.target for i in plan.items] == [BIG_JPEG]


def test_plan_set_override_replaces_the_shipped_exclusions(tmp_path, wpt_caplog):
    """--set media_optimize.exclude_prefixes=... REPLACES the shipped list
    (the list contract every other collection follows): the operator's
    subtree is protected and the form records are in scope again."""
    settings = load(overrides={
        "media_optimize.exclude_prefixes": ["wp-content/uploads/2023/"],
    })
    assert settings.media_optimize.exclude_prefixes == \
        ["wp-content/uploads/2023/"]
    old = "wp-content/uploads/2023/10/a.jpg"
    src = FakeSource()
    src.files = {
        FORM_RECORD: _jpeg(256, 256, seed=41),
        old: _jpeg(256, 256, seed=45),
        BIG_JPEG: _jpeg(256, 256),
    }
    plan = OptimizeMediaAction().plan(
        _ctx(tmp_path, settings=settings), (src, None, None))
    assert [i.target for i in plan.items] == [BIG_JPEG, FORM_RECORD]
    summaries = _records(wpt_caplog, "wpt.actions.optimize_media", logging.INFO)
    assert "2 candidate(s) scanned" in summaries[0].getMessage()
    assert "1 file(s) skipped by exclude_prefixes" in summaries[0].getMessage()


def test_plan_empty_exclusion_list_optimizes_everything(tmp_path, wpt_caplog):
    """An empty list means "no exclusions" — the form records are planned
    again, exactly as before the key existed."""
    settings = load(overrides={"media_optimize.exclude_prefixes": []})
    assert settings.media_optimize.exclude_prefixes == []
    src = FakeSource()
    src.files = {FORM_RECORD: _jpeg(256, 256, seed=41), BIG_JPEG: _jpeg(256, 256)}
    plan = OptimizeMediaAction().plan(
        _ctx(tmp_path, settings=settings), (src, None, None))
    assert [i.target for i in plan.items] == [BIG_JPEG, FORM_RECORD]
    summaries = _records(wpt_caplog, "wpt.actions.optimize_media", logging.INFO)
    assert "2 candidate(s) scanned" in summaries[0].getMessage()
    assert "0 file(s) skipped by exclude_prefixes" in summaries[0].getMessage()


def test_plan_exclusion_gauge_matches_apply(tmp_path, wpt_caplog):
    """The live gauge: the dry-run plan and the applied result cover exactly
    the same files.  The exclusion lives in the plan, so the apply phase can
    only ever touch what the dry run showed."""
    src = FakeSource()
    originals = {
        FORM_RECORD: _jpeg(256, 256, seed=41),
        BIG_JPEG: _jpeg(256, 256),
        "wp-content/uploads/2024/05/other.jpg": _jpeg(256, 256, seed=47),
    }
    src.files = dict(originals)
    action = OptimizeMediaAction()
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, (src, None, None))
    planned = [i.target for i in plan.items]
    assert planned == [BIG_JPEG, "wp-content/uploads/2024/05/other.jpg"]
    applied = action.apply(ctx, (src, None, None), plan)
    assert [i.target for i in applied.items if i.done] == planned
    assert sorted(_write_ops(src)) == sorted(planned)
    # the submission record is byte-for-byte what it was
    assert src.files[FORM_RECORD] == originals[FORM_RECORD]


def test_plan_skip_below_bytes_from_settings(tmp_path, wpt_caplog):
    media = replace(DEFAULTS.media_optimize, skip_below_bytes=200000)
    settings = replace(DEFAULTS, media_optimize=media)
    src = FakeSource()
    src.files = {BIG_JPEG: _jpeg(256, 256)}  # 77KB < the raised gate
    plan = OptimizeMediaAction().plan(
        _ctx(tmp_path, settings=settings), (src, None, None))
    assert plan.items == []
    summaries = _records(wpt_caplog, "wpt.actions.optimize_media", logging.INFO)
    assert "0 candidate(s) scanned" in summaries[0].getMessage()


def test_plan_min_savings_ratio_from_settings(tmp_path):
    media = replace(DEFAULTS.media_optimize, min_savings_ratio=0.9)
    settings = replace(DEFAULTS, media_optimize=media)
    src = FakeSource()
    src.files = {BIG_JPEG: _jpeg(256, 256)}  # saves ~49% < the raised bar
    plan = OptimizeMediaAction().plan(
        _ctx(tmp_path, settings=settings), (src, None, None))
    assert plan.items == []


def test_plan_savings_ratio_skips_already_optimal(tmp_path):
    src = FakeSource()
    src.files = {
        BIG_JPEG: _jpeg(256, 256),  # q95: ~49% savings -> planned
        # saved at the action's own quality/flags: a fresh recompress is
        # roughly size-neutral -> NOT planned
        "wp-content/uploads/2024/05/optimal.jpg": _optimal_jpeg(256, 256),
        # PNG within png_max_dim: the lossless re-save saves ~0% -> NOT planned
        "wp-content/uploads/2024/05/flat.png": _png(600, 300, seed=8),
    }
    plan = OptimizeMediaAction().plan(_ctx(tmp_path), (src, None, None))
    assert [i.target for i in plan.items] == [BIG_JPEG]


def test_plan_corrupt_skipped_with_debug_log(tmp_path, wpt_caplog):
    src = FakeSource()
    src.files = {
        "wp-content/uploads/2024/05/broken.jpg": b"\x00 not an image" * 3000,
        BIG_JPEG: _jpeg(256, 256),
    }
    plan = OptimizeMediaAction().plan(_ctx(tmp_path), (src, None, None))
    assert [i.target for i in plan.items] == [BIG_JPEG]  # batch continued
    debugs = _records(wpt_caplog, "wpt.actions.optimize_media", logging.DEBUG)
    assert len(debugs) == 1
    assert "wp-content/uploads/2024/05/broken.jpg" in debugs[0].getMessage()


def test_plan_sorted_items_with_bytes_and_detail(tmp_path, wpt_caplog):
    src = FakeSource()
    src.files = {
        # walk order != target order: sibling dirs "2023" < "2023-old"
        # as NAMES, but "2023-old/..." < "2023/..." as full paths
        # ("-" sorts before "/") — the walk descends 2023 first, the
        # plan must still come out target-sorted
        "wp-content/uploads/2023/10/z-noise.jpg": _jpeg(256, 256, seed=21),
        "wp-content/uploads/2023-old/a-noise.jpg": _jpeg(256, 256, seed=22),
    }
    plan = OptimizeMediaAction().plan(_ctx(tmp_path), (src, None, None))
    expected = {}
    for target in ("wp-content/uploads/2023/10/z-noise.jpg",
                   "wp-content/uploads/2023-old/a-noise.jpg"):
        expected[target] = _expected_item_fields(src, target)
    assert [(i.category, i.target) for i in plan.items] == [
        ("media.oversized", "wp-content/uploads/2023-old/a-noise.jpg"),
        ("media.oversized", "wp-content/uploads/2023/10/z-noise.jpg"),
    ]
    for item in plan.items:
        detail, bytes_est = expected[item.target]
        assert item.detail == detail
        assert item.bytes_est == bytes_est
        assert item.requires_apply
        assert not item.done
    assert plan.est_bytes() == sum(i.bytes_est for i in plan.items)
    assert plan.backup_tables == []  # deliberate: no DB rows mutate
    summaries = _records(wpt_caplog, "wpt.actions.optimize_media", logging.INFO)
    assert len(summaries) == 1
    assert "2 candidate(s) scanned" in summaries[0].getMessage()


def test_plan_empty_tree(tmp_path):
    src = FakeSource()
    src.files = {"wp-content/plugins/img.jpg": b"x" * 40000}
    plan = OptimizeMediaAction().plan(_ctx(tmp_path), (src, None, None))
    assert plan.items == []
    assert plan.est_bytes() == 0
    assert plan.backup_tables == []  # deliberate even when empty


# ------------------------------------------------------------------ apply


def test_apply_uploads_recompressed_bytes(tmp_path, wpt_caplog):
    src = FakeSource()
    original = {
        BIG_JPEG: _jpeg(256, 256),
        "wp-content/uploads/2024/05/other.jpg": _jpeg(256, 256, seed=31),
    }
    src.files = dict(original)
    action = OptimizeMediaAction()
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, (src, None, None))
    applied = action.apply(ctx, (src, None, None), plan)
    assert applied is plan  # the same Plan object, items updated in place
    assert all(i.done for i in applied.items)
    # uploads in plan order, one write per planned file
    assert _write_ops(src) == [
        "wp-content/uploads/2024/05/big.jpg",
        "wp-content/uploads/2024/05/other.jpg",
    ]
    for target, before in original.items():
        after = src.files[target]
        assert len(after) < len(before)  # read back: smaller bytes
        # deterministic re-encode: byte-identical to a fresh _recompress
        assert after == _recompress(before, _suffix_of(target),
                                    DEFAULTS.media_optimize)
    infos = _records(wpt_caplog, "wpt.actions.optimize_media", logging.INFO)
    upload_logs = [r for r in infos if "apply:" in r.getMessage()]
    assert len(upload_logs) == 2
    assert all(target in upload_logs[0].getMessage()
               or target in upload_logs[1].getMessage()
               for target in original)


def test_apply_fresh_no_savings_marks_already_optimal(tmp_path, wpt_caplog):
    src = FakeSource()
    src.files = {BIG_JPEG: _jpeg(256, 256)}
    action = OptimizeMediaAction()
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, (src, None, None))
    assert len(plan.items) == 1
    # the file CHANGED since the plan: someone re-saved it optimally
    src.files[BIG_JPEG] = _optimal_jpeg(256, 256)
    applied = action.apply(ctx, (src, None, None), plan)
    item = applied.items[0]
    assert item.done  # a settled truth, not a failure
    assert "already optimal" in item.detail
    assert _write_ops(src) == []  # no upload
    assert src.files[BIG_JPEG] == _optimal_jpeg(256, 256)  # untouched
    infos = _records(wpt_caplog, "wpt.actions.optimize_media", logging.INFO)
    assert any("already optimal" in r.getMessage() for r in infos)
    assert not [
        r for r in wpt_caplog.records
        if r.name == "wpt.actions.optimize_media" and r.levelno >= logging.WARNING
    ]


def test_apply_failing_write_continues(tmp_path, wpt_caplog):
    good = "wp-content/uploads/2024/05/other.jpg"
    src = FailingWriteSource({BIG_JPEG})
    src.files = {
        BIG_JPEG: _jpeg(256, 256),
        good: _jpeg(256, 256, seed=31),
    }
    action = OptimizeMediaAction()
    ctx = _ctx(tmp_path)
    plan = action.plan(ctx, (src, None, None))
    applied = action.apply(ctx, (src, None, None), plan)
    by_target = {i.target: i for i in applied.items}
    assert not by_target[BIG_JPEG].done
    assert by_target[good].done  # the batch continued past the failure
    warnings = _records(wpt_caplog, "wpt.actions.optimize_media",
                        logging.WARNING)
    assert len(warnings) == 1
    assert BIG_JPEG in warnings[0].getMessage()
    # the failed target keeps its original bytes; the good one uploaded
    assert src.files[BIG_JPEG] == _jpeg(256, 256)
    assert _write_ops(src) == [good]
    assert len(src.files[good]) < len(_jpeg(256, 256, seed=31))


def test_apply_skips_non_apply_items(tmp_path):
    good = "wp-content/uploads/2024/05/b.jpg"
    src = FakeSource()
    src.files = {good: _jpeg(256, 256, seed=33)}
    plan = Plan(items=[
        PlanItem(category="media.oversized", target=good, detail="b"),
        PlanItem(category="media.info", target="advice", detail="n/a",
                 requires_apply=False),
    ])
    applied = OptimizeMediaAction().apply(
        _ctx(tmp_path), (src, None, None), plan)
    by_target = {i.target: i for i in applied.items}  # items mutate in place
    assert by_target[good].done
    assert not by_target["advice"].done  # neither applied nor marked done
    assert _write_ops(src) == [good]  # only the requires_apply item uploaded


def test_apply_local_zip_read_only(tmp_path, wpt_caplog):
    zpath = _make_zip(tmp_path)
    zsrc = ZipSource(zpath)
    try:
        action = OptimizeMediaAction()
        ctx = _ctx(tmp_path, source="local", zip=zpath)
        plan = action.plan(ctx, (zsrc, None, None))
        assert [i.target for i in plan.items] == [
            "wp-content/uploads/2024/05/big.jpg"
        ]
        applied = action.apply(ctx, (zsrc, None, None), plan)
        assert all(not i.done for i in applied.items)  # every write refused
        warnings = _records(wpt_caplog, "wpt.actions.optimize_media",
                            logging.WARNING)
        assert len(warnings) == len(plan.items)  # one per item, none raised
        assert "read-only" in warnings[0].getMessage()
    finally:
        zsrc.close()


# ------------------------------------------------------- registry end-to-end


def test_registry_local_dry_run_zip_untouched(tmp_path, capsys):
    zpath = _make_zip(tmp_path)
    before = _zip_fingerprint(zpath)
    rc = run_action(_ctx(tmp_path, source="local", zip=zpath), "optimize-media")
    assert rc == 0
    out = capsys.readouterr().out
    assert "## Plan" in out
    assert "wp-content/uploads/2024/05/big.jpg" in out
    assert "2024/05/big.jpg (" in out  # uploads-relative detail
    assert "small.jpg" not in out  # below skip_below_bytes: not scanned
    assert "x.jpg" not in out     # non-uploads: never planned
    assert "inbound-sample.jpg" not in out  # shipped exclusion: never planned
    assert _zip_fingerprint(zpath) == before  # the zip is untouched


def test_registry_local_apply_rehearses(tmp_path, wpt_caplog):
    """Local --apply is a REHEARSAL: rc 0, original zip byte-identical, a
    materialized twin where the big jpeg was actually recompressed — and
    the submission record came through the rehearsal untouched."""
    zpath = _make_zip(tmp_path)
    before = _zip_fingerprint(zpath)
    with zipfile.ZipFile(zpath) as zf:
        original = zf.read(BIG_JPEG)
        record = zf.read(FORM_RECORD)
    rc = run_action(
        _ctx(tmp_path, source="local", zip=zpath, apply=True, yes=True),
        "optimize-media",
    )
    assert rc == 0
    assert _zip_fingerprint(zpath) == before  # the original is the rollback
    rehearsed = sorted(tmp_path.glob("site-rehearsed-*.zip"))
    assert len(rehearsed) == 1
    with zipfile.ZipFile(rehearsed[0]) as zf:
        optimized = zf.read(BIG_JPEG)
        rehearsed_record = zf.read(FORM_RECORD)
    assert len(optimized) < len(original)
    assert rehearsed_record == record  # the excluded record is byte-identical


def test_registry_ftp_apply_end_to_end(tmp_path, capsys, monkeypatch):
    src = FakeSource()
    original = _jpeg(256, 256)
    record = _jpeg(256, 256, seed=41)
    src.files = {
        BIG_JPEG: original,
        "wp-content/uploads/2024/05/small.jpg": _jpeg(16, 16, quality=90),
        FORM_RECORD: record,  # excluded: never planned, never snapshotted
        "wp-content/plugins/x.jpg": b"j" * 40000,
    }
    monkeypatch.setattr(registry_mod, "_stack", lambda ctx: (src, None, None))
    rc = run_action(_ctx(tmp_path, apply=True, yes=True), "optimize-media")
    assert rc == 0
    # the planned file really uploaded to the FakeSource: smaller, and
    # byte-identical to a fresh _recompress of the original
    uploaded = src.files[BIG_JPEG]
    assert len(uploaded) < len(original)
    assert uploaded == _recompress(original, "jpg", DEFAULTS.media_optimize)
    assert _write_ops(src) == [BIG_JPEG]  # nothing else written
    assert src.files[FORM_RECORD] == record  # the record is byte-identical
    with PIL.Image.open(io.BytesIO(uploaded)) as img:
        assert img.format == "JPEG"  # read back: still a decodable JPEG
    # fail-closed pre-action backup: the manifest lists exactly the
    # planned FILE (backup_tables == [] -> no tables, no bridge)
    manifests = list((tmp_path / "backup").glob("*/*/manifest.json"))
    assert len(manifests) == 1
    manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
    assert manifest["action"] == "optimize-media"
    assert manifest["site"] == "example.com"
    assert [f["path"] for f in manifest["files"]] == [BIG_JPEG]
    assert all(not f["absent"] for f in manifest["files"])
    assert manifest["tables"] == []
    out = capsys.readouterr().out
    assert "## Plan" in out
    assert out.count("| yes |") == 1  # the applied item printed as done
