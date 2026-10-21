"""The cross-mode witness: a ``--sql`` dump as a SECOND MEASUREMENT of the
live database, for every destructive media action.

ONE owner, imported by ``trim_media`` and ``cull_media`` alike, because the
question it answers is one question: *may this run delete media on the
strength of a reference set it measured itself?*  Two actions that each
answered it would answer it twice, and the second answer is the one that
gets weaker — which is exactly what happened (``cull-media`` deleted through
the same ``media_delete`` op in the same ftp mode with no cross-check at
all).  So the gate, its refusals and their wording live here, and the two
actions call the same functions: the refusal an operator reads is literally
the same string, not two copies that drift.

WHY A WITNESS EXISTS
--------------------

The keep-set is a UNION — rendered references (a live walk) plus database
references (the bridge's ``media_map``, or the dump offline).  A deletion is
therefore authorized by a MEASUREMENT, and the failure this module exists to
stop is a measurement that measured nothing while agreeing with everything:
a cut-off transfer, another site's export, a schema-only dump and a dump
taken before this site's content all return a keep-set that references none
of the planned files, and an empty keep-set agrees with the live union about
every one of them.  The whole planned family is then deleted on the strength
of a witness that established nothing.

A witness is a witness only when ALL of these hold, and each is a property
of the DUMP, never of the outcome:

1. it reached its END — mysqldump writes ``-- Dump completed on <stamp>`` as
   its last line, so a dump that finished and a transfer that stopped inside
   a table are told apart.  Cheap first question (a 4 KB tail read).
2. it is THIS SITE'S — the options table's own ``siteurl``/``home``, read by
   the analyzer (the one owner of that read), against this run's
   ``--wp-url``.  A dump of another site names none of this site's files,
   which is indistinguishable from agreeing with all of them.
3. it MEASURED a reference set at all (``db_refs_from_dump`` is not None),
   and measured one where the live map measured one.
4. it DECLARES every table the live schema has.  The dump's own table set is
   compared with the live one ``db_audit`` reports, and a live table the
   dump does not declare is refused BY NAME: a dump taken before that table
   existed, or one whose DDL was cut, cannot certify anything about the
   rows that live in it now.
5. it is not BEHIND the live rows of a table that matters to this decision
   (the four the reference set is read from — options, posts, postmeta,
   termmeta — resolved by ``wpt.media_refs.dump_role_tables``, the
   measurement's OWN identity rule, so a bare-suffix decoy table such as
   ``wp_aioseo_posts`` or ``wp_edd_postmeta`` can never stand in for the
   table the reference set was actually read from, and a dump CONTESTING a
   role — ``aioseo_options`` beside ``wp_options`` — narrows the check to
   NO table at all, because the measurement read none).  A dump that
   PREDATES the live content cannot certify that anything is unreferenced:
   the row that referenced the file may not have existed when the dump was
   taken, which is the same undecidable state condition 3 refuses, one
   level down.  The tolerance is a profile key (:func:`behind_row_ratio`)
   because the live side is ``information_schema``'s ESTIMATE and a fixed
   fraction would either refuse every real site or pass a stale dump.

Conditions 4 and 5 are what the ``-- Dump completed`` trailer cannot see: a
resumed transfer, a concatenation and a hand edit all leave the trailer in
place, and a dump cut inside the ``INSERT INTO wp_postmeta`` rows with the
trailer appended satisfies conditions 1-3 while authorizing exactly the
deletion this gate exists to prevent.  Both new conditions are refused
fail-closed and deterministically, and both name the table and the numbers.

WHERE IT IS ASKED
-----------------

* the PLAN phase, before the registry takes the pre-action snapshot — a
  refusal there costs one ``stat`` where the same refusal inside the apply
  costs a full-site walk, an FTP download of the whole deletion scope and a
  ``db_dump`` of three tables (a cost that evicted a real snapshot from
  ``backup.keep_last`` on every attempt);
* the APPLY phase, as the backstop for a caller that reaches it without the
  plan having asked;
* both phases share ONE measurement (memoized under a key carrying the
  dump's identity), so the apply never pays for the parse twice.

Logging: ``get_logger("actions.dump_witness")`` — one warning per refusal,
naming the dump and the fact; never file lists or cell values (the refusal
line the operator reads carries the planned files, built by
:func:`witness_refusal`).
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from ..localmode.analyzer import analyze
from ..log import get_logger
from ..media_refs import db_refs_from_dump, dump_role_tables
from ..types import SourceError

if TYPE_CHECKING:
    from ..cli import Ctx
    from ..deadline import Deadline

__all__ = [
    "DumpWitness",
    "LiveSchema",
    "WitnessGate",
    "behind_row_ratio",
    "live_schema_from_audit",
    "witness_refusal",
]

log = get_logger("actions.dump_witness")

#: mysqldump's completion trailer.  Matched as a LINE START in the tail of
#: the file (not as a substring anywhere): the marker has to be a
#: statement-level line, and the tail window is what makes it a
#: completeness signal rather than a value a row happens to contain.
_DUMP_SENTINEL_RE = re.compile(rb"^-- Dump completed", re.MULTILINE)

#: How much of the END of a dump the completion trailer is looked for in:
#: big enough for mysqldump's own trailer plus the ``SET``/``LOCK``
#: statements an exporter may append after it, small enough that the read
#: is a constant regardless of the dump's size.  A structural constant of
#: the check, not an operator tunable — the same kind as
#: ``sql_dump._STMT_CAP``: no profile need exists, and a knob here would
#: only be a way to talk the check out of looking.
_DUMP_SENTINEL_TAIL_BYTES = 4096

#: The profile key that carries the "how far behind is too far" tolerance,
#: named in the SettingsError so a nonsense value says which key it was.
#: ``media.dump_behind_row_ratio`` — a FRACTION of the live row count the
#: dump must still carry for a table that matters to the decision.
BEHIND_RATIO_KEY = "media.dump_behind_row_ratio"

#: …and its documented default is ``MediaSettings.dump_behind_row_ratio``.
#: One half is the widest
#: tolerance that still refuses a dump that PREDATES the content — the case
#: this check exists for, where a table with thousands of live rows has
#: single digits in the dump (a ratio of ~0.001, two orders of magnitude
#: below the bound, not near it).

# --------------------------------------------------------------------------
# The refusals.  One clause each, and the sentence around them is built once
# by :func:`witness_refusal`, so no reason string can grow its own second
# sentence in a different shape.
# --------------------------------------------------------------------------

_NO_DUMP_REASON = (
    "an ftp apply needs a second measurement of the same database, so pass "
    "--sql DUMP.sql (this site's database export) — without it a reference "
    "the live tables no longer carry is indistinguishable from a real "
    "orphan"
)
_UNREADABLE_REASON = (
    "the cross-check dump could not be read ({reason}) — pass a readable "
    "--sql dump of THIS site's database, or retake it"
)
_UNMEASURABLE_REASON = (
    "{dump} measures no database reference set (no usable WordPress "
    "tables, or an ambiguous table identity — see the warning above) — "
    "pass a --sql dump of THIS site's database, or retake it"
)
_TRUNCATED_REASON = (
    "{dump} carries no `-- Dump completed on` trailer, so a transfer that "
    "was cut short cannot be told from one that finished — a dump that "
    "measured nothing agrees with a live union that measured nothing, "
    "which is exactly how a truncated witness would authorize the whole "
    "deletion; retake the dump with an exporter that writes the trailer "
    "(mysqldump does)"
)
_FOREIGN_REASON = (
    "{dump} is ANOTHER SITE's database — it states siteurl {siteurl} and "
    "home {home}, and this run targets {target} — a dump of a different "
    "site references none of this site's files, which is indistinguishable "
    "from agreeing with all of them; pass this site's own export"
)
_UNIDENTIFIED_REASON = (
    "{dump} states no siteurl and no home, so it cannot be shown to be "
    "THIS site's database (this run targets {target}) — pass this site's "
    "own export"
)
_SILENT_REASON = (
    "{dump} measures NO database reference at all while the live database "
    "map measured {measured} file(s) — the two measurements of one "
    "database disagree about whether the database references media, so "
    "neither can vouch for the other; retake the dump and compare it "
    "against a fresh --sql export before applying"
)
_NO_LIVE_SCHEMA_REASON = (
    "the live schema could not be read (the bridge's db_audit answered no "
    "usable table list), so {dump} cannot be compared with the tables this "
    "site has NOW — the completeness of a dump is only a fact against the "
    "live schema, and an uncomparable witness is not a witness; re-run "
    "with a working bridge"
)
_MISSING_TABLE_REASON = (
    "{dump} declares no {table} table, which the live schema HAS "
    "({live} row(s)) — so this dump PREDATES that table (or its DDL was cut "
    "and the trailer appended), and a dump taken before a table existed "
    "cannot certify anything about the rows in it now; retake the dump "
    "from the live database"
)
_BEHIND_REASON = (
    "{dump} carries {dumped} row(s) of {table} while the live table holds "
    "about {live} — this dump is BEHIND the live content, and a dump that "
    "predates it cannot say that a file is unreferenced (the row that "
    "referenced it may not have existed when the dump was taken); retake "
    "the dump from the live database"
)
_DISPUTE_REASON = (
    "{count} planned file(s) are referenced by the database in {dump} but "
    "not by the live site: {listed} — the two measurements of the same "
    "database disagree, so nothing was deleted; retake the dump (a fresh "
    "--sql) and review before applying"
)


def behind_row_ratio(settings: Any) -> float:
    """The "materially behind" tolerance, from the profile or its default.

    A FRACTION in (0, 1] — the share of the live row count a dump must
    still carry for a table that matters to the decision.  Anything else is
    a ``SettingsError`` naming the key, never a silent clamp: a tolerance
    of 0 would refuse every dump, one above 1 would accept a dump of
    nothing, and a string would compare as a TypeError three tables deep
    inside a destructive gate.

    Read through ``getattr`` because the profile is the schema's own
    declaration and the field is added to
    :class:`wpt.settings.MediaSettings` (an absent key is the documented
    default, which is what a profile written before this gate existed must
    keep meaning), and validated HERE as well as at load: the gate is the
    last chokepoint before a deletion, so it is the place where a nonsense
    value must be heard rather than assumed — a threshold that reached a
    destructive decision unexamined would be a knob nobody set and nobody
    checked.
    """
    from ..settings import MediaSettings, SettingsError

    media = getattr(settings, "media", None)
    raw = getattr(media, "dump_behind_row_ratio", None)
    if raw is None:
        return MediaSettings().dump_behind_row_ratio
    if isinstance(raw, bool) or not isinstance(raw, (int, float)) \
            or not math.isfinite(raw) or not 0 < raw <= 1:
        raise SettingsError(
            f"{BEHIND_RATIO_KEY}: expected a share of the live row count "
            f"strictly above 0 and at most 1 (got {raw!r}) — 0 would refuse "
            f"every dump, a value above 1 would accept a dump that lost "
            f"rows, and a witness with no tolerance cannot tell a stale "
            f"dump from a fresh one"
        )
    return float(raw)


@dataclass(frozen=True)
class LiveSchema:
    """The LIVE schema's base-table set and row counts, as ``db_audit`` saw
    them a moment ago — the half of the completeness comparison the dump is
    measured against.

    ``rows`` is ``{table name: information_schema row estimate}``; an empty
    map is UNKNOWN (the bridge answered no usable table list), never "this
    site has no tables", and an unknown live schema refuses the witness
    (:data:`_NO_LIVE_SCHEMA_REASON`) because completeness is only a fact
    against something to be compared with.
    """

    rows: dict[str, int]

    def __bool__(self) -> bool:
        return bool(self.rows)


def live_schema_from_audit(tables: Any) -> LiveSchema:
    """The :class:`LiveSchema` of one ``db_audit`` tables answer.

    The bridge's own row counts (``information_schema.TABLE_ROWS``) with the
    documented approximation left to the caller: this module compares
    COUNTS, never sizes, so it needs nothing else from the wire.
    """
    if not isinstance(tables, dict):
        return LiveSchema({})
    rows: dict[str, int] = {}
    for name, fact in tables.items():
        count = getattr(fact, "rows", None)
        if isinstance(count, int) and not isinstance(count, bool) and count >= 0:
            rows[name] = count
    return LiveSchema(rows)


@dataclass(frozen=True)
class DumpWitness:
    """The ``--sql`` dump as a cross-mode witness for this run.

    ``refs`` is the dump's measured database reference set and ``problem``
    is the ONE reason it cannot corroborate a deletion, or None when it
    can.  A problem is UNKNOWN, never an agreement: every state this class
    can be in other than "a measured set for this site, at least as
    current as the live schema" refuses.
    """

    refs: set[str] | None
    problem: str | None


def site_identity(url: object) -> tuple[str, str] | None:
    """One site URL -> the identity two dumps of one site must share.

    ``(host, path)``, with the parts that are NOT the site's identity
    dropped: the scheme (a site that was ``http`` when the dump was taken
    and is ``https`` now is the same site), a ``www.`` prefix on the host
    (the redirect alias WordPress itself serves) and the port.  The PATH
    is kept — a subdirectory install's ``siteurl`` carries it, and R14
    established that this tool reads ``ctx.wp_url`` verbatim rather than
    stripping it, so stripping it here would make the comparison looser
    than the URL the rest of the run uses.

    None for anything that names no host: a value that cannot be an
    identity is not one, and the caller says so rather than matching it.
    """
    if not isinstance(url, str):
        return None
    parts = urlsplit(url.strip())
    host = (parts.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    if not host:
        return None
    return host, parts.path.rstrip("/")


def witness_refusal(action: str, paths: list[str], reason: str) -> SourceError:
    """The ONE line every unusable witness ends with.

    It names the action (the caller passes its own name, so an operator
    reading a cull-media refusal is not told to pass a trim-media flag),
    the FILES the refusal is about — the planned deletions that have no
    usable cross-check, because the operator has to know what the apply was
    going to do — and the reason.  Built here so no reason string can carry
    its own second sentence, and so both actions produce the same wording.
    """
    listed = ", ".join(paths[:5]) + (" …" if len(paths) > 5 else "")
    return SourceError(
        f"{action} cannot cross-check the deletion of {len(paths)} planned "
        f"file(s) ({listed}): {reason}; nothing was deleted"
    )


def dispute_refusal(action: str, paths: list[str], dump: Any) -> SourceError:
    """The refusal for a witness that DISAGREES with the live measurement.

    Same function for the same reason as :func:`witness_refusal`: the two
    measurements of ONE database disagree about a file this apply is about
    to delete, and no wording is good enough to be written twice.
    """
    listed = ", ".join(sorted(paths)[:5]) + (" …" if len(paths) > 5 else "")
    return SourceError(
        f"{action}: {_DISPUTE_REASON.format(count=len(paths),
                                            dump=Path(str(dump)).name,
                                            listed=listed)}"
    )


class WitnessGate:
    """This run's ONE witness of ONE dump, memoized.

    An instance belongs to one action instance of one run: the plan phase
    and the apply phase ask the same questions of the same file and must
    get the same answers, and a dump replaced between the two is
    re-measured rather than silently reused (the memo key carries the
    file's identity, the media family and the walked uploads directories,
    because the two halves of one gate must measure one set).
    """

    def __init__(self) -> None:
        self._memo: tuple | None = None
        self._dirs: set[str] | None = None

    def remember_dirs(self, dirs: set[str] | None) -> None:
        """Hand over the walked uploads DIRECTORY set (the is-a-directory
        half of the keep-gate), so the witness measures with the same
        directories the plan enumerated with."""
        self._dirs = dirs

    # -- the free half ----------------------------------------------------

    def absence(self, sql: Any) -> str | None:
        """None when a dump was NAMED and can be opened, else the reason.

        The free half of the witness, answered from the argument and one
        ``stat``: it is the check the plan phase makes BEFORE it walks the
        site, so the refusal for the single most common way to have no
        witness — ``--sql`` not passed at all, which the CLI treats as
        optional in ftp mode — costs nothing.  What the dump turns out to
        be is :meth:`witness`'s business, and asking that costs a read.
        """
        if sql is None:
            return _NO_DUMP_REASON
        try:
            Path(sql).stat()
        except OSError as exc:
            return _UNREADABLE_REASON.format(reason=exc)
        return None

    # -- the whole witness -----------------------------------------------

    def witness(self, ctx: "Ctx", live_refs: set[str] | None,
                live: LiveSchema, deadline: "Deadline | None" = None,
                ) -> DumpWitness:
        """The dump as a cross-mode witness, or the ONE reason it is not.

        The five conditions, in the order an operator can act on them: the
        completion trailer (a 4 KB read, so a cut-off transfer costs
        nothing), the MEASUREMENT (whose own ``None`` names the most
        specific fact available — no usable WordPress tables), the identity
        (which can only be asked of a dump that holds a database at all),
        and then the two completeness conditions against the LIVE schema —
        the table set (refused by name) and the row counts of the tables
        that matter (refused with both numbers).  The last two need
        ``live``, the run's own ``db_audit`` answer, which is the only
        thing a dump's completeness can be a fact about.

        ``live_refs`` is the LIVE half of the "measured something" check —
        the run's own ``media_map`` ``mode=db`` answer — and the question
        is whether the witness measured something where the live
        measurement measured something, never whether the two sets are
        equal (the per-file dispute is the gate's own question, asked over
        the planned paths alone by :func:`dispute_refusal`).

        The dump's own verdict is memoized; the live half is applied on
        every call, so it always compares the two halves of the run that
        are actually asking.
        """
        if ctx.sql is None:
            return DumpWitness(None, _NO_DUMP_REASON)
        key = self._key(ctx)
        if self._memo is not None and self._memo[0] == key:
            refs, problem = self._memo[1], self._memo[2]
        else:
            problem = self._completeness(ctx)
            refs = None
            model = None
            if problem is None:
                try:
                    with open(ctx.sql, "rb") as dump:
                        refs = db_refs_from_dump(
                            dump, ctx.settings.media.extensions, self._dirs,
                            deadline=deadline,
                        )
                except OSError as exc:
                    log.warning("the cross-check dump could not be read "
                                "(%s): there is no second measurement of "
                                "this database", exc)
                    problem = _UNREADABLE_REASON.format(reason=exc)
                else:
                    if refs is None:
                        problem = _UNMEASURABLE_REASON.format(
                            dump=Path(str(ctx.sql)).name)
                    else:
                        try:
                            with open(ctx.sql, "rb") as dump:
                                model = analyze(dump, ctx.settings.db)
                        except OSError as exc:
                            problem = _UNREADABLE_REASON.format(reason=exc)
                        else:
                            problem = self._identity(ctx, model)
                            if problem is None:
                                problem = self._currency(
                                    ctx, model, live)
            self._memo = (key, refs, problem)
        if problem is None and live_refs and not refs:
            log.warning(
                "the cross-check dump %s measures no database reference "
                "while the live database map measured %d file(s): the two "
                "measurements of one database disagree about whether the "
                "database references media", ctx.sql, len(live_refs),
            )
            problem = _SILENT_REASON.format(
                dump=Path(str(ctx.sql)).name, measured=len(live_refs))
        return DumpWitness(refs, problem)

    # -- internals --------------------------------------------------------

    def _key(self, ctx: "Ctx") -> tuple:
        """The memo key: the dump's IDENTITY (mtime + size, so a dump
        replaced between two asks is re-measured), the media family and the
        walked uploads directories."""
        try:
            stat = Path(ctx.sql).stat()
            identity: tuple | None = (stat.st_mtime_ns, stat.st_size)
        except OSError:
            identity = None      # the reads above report the real reason
        return (str(ctx.sql), identity,
                tuple(ctx.settings.media.extensions),
                frozenset(self._dirs) if self._dirs is not None else None,
                behind_row_ratio(ctx.settings))

    def _completeness(self, ctx: "Ctx") -> str | None:
        """None when the dump reached its end, else the refusal reason.

        The cheapest of the five conditions and asked FIRST: a 4 KB read of
        the tail decides the truncation question before the dump is measured
        at all, so a cut-off transfer costs nothing.  Necessary and NOT
        sufficient — a resumed transfer, a concatenation and a hand edit all
        leave the trailer in place, which is what
        :meth:`_currency` is for.
        """
        try:
            with open(ctx.sql, "rb") as dump:
                dump.seek(0, 2)
                size = dump.tell()
                dump.seek(max(0, size - _DUMP_SENTINEL_TAIL_BYTES))
                tail = dump.read()
        except OSError as exc:
            return _UNREADABLE_REASON.format(reason=exc)
        if _DUMP_SENTINEL_RE.search(tail) is None:
            log.warning(
                "the cross-check dump %s carries no `-- Dump completed on` "
                "trailer: it cannot be told from a transfer that was cut "
                "short, and a witness that measured nothing agrees with "
                "anything", ctx.sql,
            )
            return _TRUNCATED_REASON.format(dump=Path(str(ctx.sql)).name)
        return None

    def _identity(self, ctx: "Ctx", model: Any) -> str | None:
        """None when the dump can be shown to be THIS site's, else why not.

        ``siteurl``/``home`` are read by the ANALYZER — the one owner of
        that read, the same :func:`wpt.localmode.analyzer.analyze` the local
        gather builds its whole model from — so "what this dump says it is"
        is decided by the same code everywhere in the tool and cannot drift
        from the offline audit's own answer.  Either of the two matching THIS
        run's ``--wp-url`` identifies the site: a site whose ``siteurl`` is
        stale after a migration and whose ``home`` is current is the same
        site.
        """
        stated = [
            identity for identity in
            (site_identity(model.siteurl), site_identity(model.home))
            if identity is not None
        ]
        if not stated:
            log.warning(
                "the cross-check dump %s states no siteurl and no home: it "
                "cannot be shown to be this site's database", ctx.sql,
            )
            return _UNIDENTIFIED_REASON.format(
                dump=Path(str(ctx.sql)).name, target=ctx.wp_url)
        target = site_identity(ctx.wp_url)
        if target is None or target not in stated:
            log.warning(
                "the cross-check dump %s is another site's database (siteurl "
                "%r, home %r) while this run targets %s", ctx.sql,
                model.siteurl, model.home, ctx.wp_url,
            )
            return _FOREIGN_REASON.format(
                dump=Path(str(ctx.sql)).name, siteurl=model.siteurl,
                home=model.home, target=ctx.wp_url,
            )
        return None

    def _currency(self, ctx: "Ctx", model: Any, live: LiveSchema) -> str | None:
        """None when the dump is at least as current as the live schema.

        THE CONDITION THE TRAILER CANNOT SEE.  A dump cut inside the
        ``INSERT INTO wp_postmeta`` rows with ``-- Dump completed on``
        appended to it — a resumed transfer, a concatenation, a hand edit —
        passes the trailer, the measurement and the identity checks and
        authorizes exactly the deletion this gate exists to prevent: the
        rows naming the files are the ones that were lost, so the dump
        references nothing and agrees with everything.

        Two structural facts decide it, both against the live schema this
        run just read:

        * the TABLE SET — a live base table the dump does not declare at
          all is refused BY NAME (the dump predates the table, or its DDL
          was cut);
        * the ROW COUNTS of the tables that MATTER to this decision — the
          ones :mod:`wpt.media_refs` reads the reference set from, asked of
          ITS OWN resolution
          (:func:`wpt.media_refs.dump_role_tables`, the prefix-derived
          identity the measurement uses) so the names are never a second
          guess and never a bare-suffix match that a decoy table
          (``wp_aioseo_posts``, ``wp_edd_postmeta``) could answer for.  A
          dump that CONTESTS a role resolves to no table AT ALL (the same
          UNKNOWN the keep-set measured), so this loop simply has nothing
          to compare: the run then refuses on the missing cross-check
          itself, which is the only honest outcome — this check exists to
          vouch for a table the measurement READ, and it read none.  A
          dump materially behind one of them is refused with both numbers,
          because a dump that predates the live content cannot certify that
          anything is unreferenced.
        """
        if not live:
            log.warning(
                "the live schema is unknown (no usable db_audit table list), "
                "so the cross-check dump %s cannot be compared with the "
                "tables this site has now", ctx.sql,
            )
            return _NO_LIVE_SCHEMA_REASON.format(
                dump=Path(str(ctx.sql)).name)
        dump_tables = getattr(model, "tables", None)
        if not isinstance(dump_tables, dict) or not dump_tables:
            return _UNMEASURABLE_REASON.format(dump=Path(str(ctx.sql)).name)
        declared = set(dump_tables)
        missing = sorted(name for name in live.rows if name not in declared)
        if missing:
            log.warning(
                "the cross-check dump %s declares none of the live table(s) "
                "%s: it predates them, or its DDL was cut and the trailer "
                "appended", ctx.sql, ", ".join(missing),
            )
            return _MISSING_TABLE_REASON.format(
                dump=Path(str(ctx.sql)).name, table=missing[0],
                live=live.rows[missing[0]],
            )
        ratio = behind_row_ratio(ctx.settings)
        # WHOSE TABLE: the measurement's own resolution, asked of
        # :mod:`wpt.media_refs` (which reads the reference set) and never
        # re-derived here.  These used to be resolved by bare SUFFIX (the
        # first ``sorted()`` name ending in ``posts``/``postmeta``), which is
        # a SECOND RULE: a dump declaring a decoy ``wp_aioseo_posts`` (a real
        # AIOSEO 4.x table) satisfied every other condition with a decoy count
        # while the core ``wp_posts`` held 2 of the live 80, and
        # ``wp_edd_postmeta`` displaced the real ``wp_postmeta`` so this loop
        # validated a table whose live count was 0 and skipped it.  Both are
        # a currency check on a table the measurement never read, which
        # proves nothing about the deletion it authorizes.
        for _role, stats in dump_role_tables(dump_tables).items():
            live_rows = live.rows.get(stats.name)
            if live_rows is None:
                continue        # declared here, gone live: not "behind"
            if live_rows == 0:
                continue        # nothing live to be behind
            dumped_rows = int(getattr(stats, "row_count", 0) or 0)
            if dumped_rows < live_rows * ratio:
                log.warning(
                    "the cross-check dump %s carries %d row(s) of %s while "
                    "the live table holds about %d: the dump is behind the "
                    "live content and cannot certify an unreferenced file",
                    ctx.sql, dumped_rows, stats.name, live_rows,
                )
                return _BEHIND_REASON.format(
                    dump=Path(str(ctx.sql)).name, table=stats.name,
                    dumped=dumped_rows, live=live_rows,
                )
        return None
