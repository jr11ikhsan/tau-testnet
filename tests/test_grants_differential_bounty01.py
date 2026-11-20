"""Bounty 01, G9: the grants differential stage.

Two evidence multipliers for the grant book (consensus/grants.py),
written against jimb000o's published 294-history enumeration for his
grants-as-rules design:

1. A WIDENED ENUMERATION of the funder shared cap: 5,184 histories
   (3 sequential draws x {Bob, Carol}^3 grant choice x 6^3 amounts x
   3 timing patterns across two shared periods), every history run
   against the REAL GrantBook and closed with a full deadline sweep
   of both grants. The original 108-history check lives in
   test_grants_bounty01.py; this is its extension, not a copy — the
   amounts grid, the third draw, the second shared period and the
   sweep are all new axes.

2. A RANDOMIZED DIFFERENTIAL: 300 seeded grant histories whose every
   draw and refund is predicted by an INDEPENDENT model of the issue
   #63 spec, written below from the spec text alone. The model imports
   nothing from consensus.grants and shares no code with the book; the
   book is driven only through its public API (create / draw /
   settle_expiry_refund / accounting / shared_period_total).

The spec the model encodes (issue #63 + the design table): a funder's
total is custodied at creation; the beneficiary draws against
calendar-anchored releases — release_per_period lands at the start of
each weekly period from the start, cumulative released is
min(total, release x periods begun), unreleased funds are never
spendable; the signed time conditions (lock, scheduled window,
inactivity-shortened deadline) combine by AND at draw time; a
funder's shared cap bounds the sum of settled draws across all their
grants per shared period, each settled draw counted exactly once; at
the effective deadline the sweep refunds exactly total - spent, once.

Seed discipline: case i uses random.Random(20261121 * 1000 + i), so
the corpus is a fixed, reproducible data set — regeneration produces
byte-identical histories on any machine.
"""
from collections import defaultdict
from datetime import datetime, timezone
from itertools import product
import random

from consensus.grants import GrantBook, GrantEntry, GrantSharedCapEntry
from consensus.standing_payments import SCHEDULE_WEEKLY

WEEK = 604_800
DAY = 86_400
DEC1 = int(datetime(2026, 12, 1, tzinfo=timezone.utc).timestamp())

FUNDER = "aa" * 48
OTHER_FUNDER = "dd" * 48
BOB = "bb" * 48
CAROL = "cc" * 48
BENEFICIARY_POOL = [BOB, CAROL, "ee" * 48, "ff" * 48, "99" * 48, "55" * 48]

MASTER_SEED = 20261121
RANDOM_CASES = 300


# --- the independent spec model (no consensus.grants imports) -----------------


class SpecGrant:
    """One grant's terms + spec-side progress. Pure arithmetic."""

    def __init__(self, funder, beneficiary, total, release, start, deadline,
                 locked_until=0, window_start=0, window_end=0, inactivity=0):
        self.funder = funder
        self.beneficiary = beneficiary
        self.total = total
        self.release = release
        self.start = start
        self.deadline = deadline
        self.locked_until = locked_until
        self.window_start = window_start
        self.window_end = window_end
        self.inactivity = inactivity
        self.spent = 0
        self.last_activity = None
        self.refunded = False

    def terms(self):
        return dict(
            funder=self.funder, beneficiary=self.beneficiary,
            total=self.total, release=self.release, start=self.start,
            deadline=self.deadline, locked_until=self.locked_until,
            window_start=self.window_start, window_end=self.window_end,
            inactivity=self.inactivity,
        )

    def period_index(self, ts):
        if ts < self.start:
            return -1
        return (ts - self.start) // WEEK

    def released(self, ts):
        period = self.period_index(ts)
        if period < 0:
            return 0
        return min(self.total, self.release * (period + 1))

    def spendable(self, ts):
        if ts < self.start:
            return 0
        return self.released(ts) - self.spent

    def effective_deadline(self):
        deadline = self.deadline
        if self.inactivity:
            last = (self.last_activity if self.last_activity is not None
                    else self.start)
            deadline = min(deadline, last + self.inactivity)
        return deadline


class SpecBook:
    """The #63 semantics over a set of SpecGrants, from the spec text."""

    def __init__(self, caps, grants):
        self.caps = dict(caps)          # funder -> (amount, period_secs, anchor)
        self.grants = list(grants)      # list[SpecGrant]
        self.shared = defaultdict(dict)  # funder -> {period: settled total}

    def shared_period(self, funder, ts):
        cap = self.caps.get(funder)
        if cap is None:
            return -1
        _, period_seconds, anchor = cap
        if ts < anchor:
            return -1
        return (ts - anchor) // period_seconds

    def shared_total(self, funder, period):
        return self.shared.get(funder, {}).get(period, 0)

    def draw(self, index, amount, ts):
        """Predict one draw. Returns (drawn, period_index, spendable_after,
        shared_period_index, shared_total_after) — the book's decision
        fields, computed spec-side."""
        g = self.grants[index]
        pidx = g.period_index(ts)
        sidx = self.shared_period(g.funder, ts)
        stot = self.shared_total(g.funder, sidx) if sidx >= 0 else 0

        def refused():
            return (False, pidx, g.spendable(ts), sidx, stot)

        if g.refunded:
            return refused()
        if amount < 1:
            return refused()
        if ts < g.start:
            return refused()
        if ts >= g.effective_deadline():
            return refused()
        if g.locked_until and ts < g.locked_until:
            return refused()
        if g.window_start or g.window_end:
            if not g.window_start <= ts < g.window_end:
                return refused()
        if amount > g.spendable(ts):
            return refused()
        if sidx >= 0 and stot + amount > self.caps[g.funder][0]:
            return refused()
        g.spent += amount
        g.last_activity = ts
        if sidx >= 0:
            self.shared[g.funder][sidx] = stot + amount
            stot += amount
        return (True, pidx, g.spendable(ts), sidx, stot)

    def refund(self, index):
        g = self.grants[index]
        assert not g.refunded
        g.refunded = True
        return g.total - g.spent


# --- driving the real book ------------------------------------------------------


def _entry(spec, version):
    return GrantEntry(
        funder_pubkey=spec.funder,
        beneficiary_pubkey=spec.beneficiary,
        total_amount=spec.total,
        release_per_period=spec.release,
        schedule_kind=SCHEDULE_WEEKLY,
        signed_day=0,
        start_ts=spec.start,
        deadline_ts=spec.deadline,
        locked_until_ts=spec.locked_until,
        window_start_ts=spec.window_start,
        window_end_ts=spec.window_end,
        inactivity_seconds=spec.inactivity,
        version=version,
    )


def _real_book(caps, specs):
    """A GrantBook holding the given caps + grants, creation-checked."""
    book = GrantBook()
    for funder, (amount, period_seconds, anchor) in caps.items():
        cap = GrantSharedCapEntry(
            funder_pubkey=funder, cap_amount=amount,
            period_seconds=period_seconds, period_anchor_ts=anchor,
            version=1,
        )
        ok, reason = book.can_set_shared_cap(cap, DEC1 - 100)
        assert ok, reason
        book.set_shared_cap(cap, DEC1 - 100)
    gids = []
    for i, spec in enumerate(specs):
        entry = _entry(spec, version=i + 1)
        ok, reason = book.can_create(entry, DEC1 - 100)
        assert ok, reason
        book.create(entry, DEC1 - 100)
        gids.append(entry.grant_id)
    return book, gids


def _assert_draw_matches(book, gid, spec_book, index, amount, ts):
    expected = spec_book.draw(index, amount, ts)
    d = book.draw(gid, amount, ts)
    assert d.drawn == expected[0], (index, amount, ts, d, expected)
    assert d.amount == (amount if expected[0] else 0)
    assert d.period_index == expected[1]
    assert d.spendable_after == expected[2]
    assert d.shared_period_index == expected[3]
    assert d.shared_total_after == expected[4]
    assert book.accounting(gid)["drawn"] == spec_book.grants[index].spent
    funder = spec_book.grants[index].funder
    for period, total in spec_book.shared.get(funder, {}).items():
        assert book.shared_period_total(funder, period) == total
    return d


def _assert_full_sweep(book, gids, spec_book, sweep_ts):
    expired = {e.grant_id for e in book.expired_grants(sweep_ts)}
    assert expired == set(gids)
    for i, gid in enumerate(gids):
        expected_refund = spec_book.refund(i)
        assert book.settle_expiry_refund(gid, sweep_ts) == expected_refund
        spec = spec_book.grants[i]
        assert book.accounting(gid) == {
            "principal": spec.total, "drawn": spec.spent,
            "held": 0, "refunded": expected_refund,
        }
        assert book.status(gid, sweep_ts) == "refunded"
    assert book.held_total() == 0
    # Aggregate balances: each beneficiary received exactly the settled
    # draws across their grants; each funder was refunded the rest.
    for funder in {g.funder for g in spec_book.grants}:
        model_refunded = sum(
            g.total - g.spent for g in spec_book.grants if g.funder == funder)
        book_refunded = sum(
            book.accounting(gid)["refunded"]
            for gid, g in zip(gids, spec_book.grants) if g.funder == funder)
        assert book_refunded == model_refunded
    for beneficiary in {g.beneficiary for g in spec_book.grants}:
        model_received = sum(
            g.spent for g in spec_book.grants if g.beneficiary == beneficiary)
        book_received = sum(
            book.accounting(gid)["drawn"]
            for gid, g in zip(gids, spec_book.grants)
            if g.beneficiary == beneficiary)
        assert book_received == model_received


# --- 1. the widened enumeration: 5,184 shared-cap histories ---------------------


def test_shared_cap_enumeration_5184_histories():
    """The 108-history gate, widened past the competitor's 294.

    Setup mirrors the original check — Alice's shared cap is 500/week;
    her grants to Bob and Carol each total 2,000 releasing 2,000/week,
    so the grants' own releases never bind (max one grant can draw is
    3 x 600 = 1,800) and every refusal is the shared cap's. Axes:
    2^3 grant choices for 3 sequential draws x 6^3 amounts
    {100..600} x 3 timing patterns (all draws in shared period 0;
    third draw in period 1; last two draws in period 1) = 5,184
    histories. Every draw's full decision is checked against the
    independent spec model, and every history closes with the deadline
    sweep of both grants: refund exactly total - spent, held 0.
    """
    caps = {FUNDER: (500, WEEK, DEC1)}
    amounts = (100, 200, 300, 400, 500, 600)
    patterns = ((0, 0, 0), (0, 0, 1), (0, 1, 1))
    histories = 0
    refused_draws = 0
    cap_stressed = 0
    for choices in product((0, 1), repeat=3):
        for draw_amounts in product(amounts, repeat=3):
            for pattern in patterns:
                histories += 1
                specs = [
                    SpecGrant(FUNDER, BOB, 2000, 2000, DEC1, DEC1 + 52 * WEEK),
                    SpecGrant(FUNDER, CAROL, 2000, 2000, DEC1,
                              DEC1 + 52 * WEEK),
                ]
                spec_book = SpecBook(caps, [SpecGrant(**s.terms())
                                            for s in specs])
                book, gids = _real_book(caps, specs)
                attempted_per_period = defaultdict(int)
                for step in range(3):
                    ts = DEC1 + pattern[step] * WEEK + 10
                    attempted_per_period[pattern[step]] += draw_amounts[step]
                    d = _assert_draw_matches(
                        book, gids[choices[step]], spec_book,
                        choices[step], draw_amounts[step], ts)
                    if not d.drawn:
                        refused_draws += 1
                if any(v > 500 for v in attempted_per_period.values()):
                    cap_stressed += 1
                for period in (0, 1):
                    assert book.shared_period_total(FUNDER, period) <= 500
                _assert_full_sweep(book, gids, spec_book, DEC1 + 52 * WEEK)
    assert histories == 5184
    assert refused_draws > 0       # the cap really refuses in the corpus
    assert cap_stressed > 0        # and histories really stress it


# --- 2. the randomized differential: 300 seeded histories ------------------------


def _generate_case(rng):
    """One randomized history as pure data: (caps, terms, draws, sweep_ts).

    Draw amounts are boundary-biased using a throwaway run of the spec
    model (exact spendable, spendable + 1, cap remainder, cap
    remainder + 1, occasional 0); the recorded history is then fixed
    data, replayed against a fresh model and the real book.
    """
    funders = [FUNDER]
    if rng.random() < 0.3:
        funders.append(OTHER_FUNDER)
    caps = {}
    if rng.random() < 0.7:
        caps[FUNDER] = (
            rng.choice([300, 500, 800, 1200]),
            WEEK,
            DEC1 + rng.choice([0, 0, 3 * DAY]),
        )
    pool = list(BENEFICIARY_POOL)
    rng.shuffle(pool)
    terms = []
    for funder in funders:
        for _ in range(rng.randint(1, 3)):
            total = rng.randrange(200, 3001, 50)
            release = rng.randrange(50, 1001, 50)
            deadline = DEC1 + rng.randint(2, 10) * WEEK
            locked = window_start = window_end = inactivity = 0
            if rng.random() < 0.25:
                locked = DEC1 + rng.randint(1, 13) * DAY
            if rng.random() < 0.25:
                a = rng.randint(0, 20) * DAY
                b = a + rng.randint(1, 20) * DAY
                if DEC1 + b > max(DEC1, locked) and DEC1 + a < deadline:
                    window_start, window_end = DEC1 + a, DEC1 + b
            if rng.random() < 0.2:
                inactivity = rng.choice([3 * DAY, WEEK, 2 * WEEK])
            terms.append(dict(
                funder=funder, beneficiary=pool.pop(), total=total,
                release=release, start=DEC1, deadline=deadline,
                locked_until=locked, window_start=window_start,
                window_end=window_end, inactivity=inactivity,
            ))
    gen = SpecBook(caps, [SpecGrant(**t) for t in terms])
    draws = []
    ts = DEC1 - 10 if rng.random() < 0.1 else DEC1
    for _ in range(rng.randint(4, 14)):
        ts += rng.choice([0, 10, 3600, DAY, 3 * DAY, WEEK, WEEK + 10])
        index = rng.randrange(len(terms))
        spec = gen.grants[index]
        roll = rng.random()
        if roll < 0.05:
            amount = 0
        elif roll < 0.20:
            amount = max(spec.spendable(ts), 1)
        elif roll < 0.35:
            amount = spec.spendable(ts) + 1
        elif roll < 0.50 and spec.funder in gen.caps:
            sidx = gen.shared_period(spec.funder, ts)
            if sidx >= 0:
                remainder = (gen.caps[spec.funder][0]
                             - gen.shared_total(spec.funder, sidx))
                amount = max(remainder + rng.choice([0, 1]), 0)
            else:
                amount = rng.randint(1, 900)
        else:
            amount = rng.randint(1, 900)
        draws.append((index, amount, ts))
        gen.draw(index, amount, ts)
    sweep_ts = max([t["deadline"] for t in terms] + [ts])
    return caps, terms, draws, sweep_ts


def test_randomized_differential_300_seeded_histories():
    """300 deterministic histories, model vs book, draw by draw + sweep.

    Varied axes: 1-2 funders (the second uncapped), optional shared
    cap (sometimes anchored mid-period), 1-3 grants per funder with
    random totals / releases / deadlines, AND-combined lock / window /
    inactivity conditions on a minority of grants, 4-14 draws at
    non-decreasing timestamps. Compared per draw: settled-or-refused,
    settled amount, grant period, spendable after, shared period,
    shared total after, and the book's drawn counter. Compared at the
    sweep: every refund, every grant's accounting, aggregate
    beneficiary receipts and funder refunds, held_total == 0.
    """
    total_draws = settled_draws = refused_draws = 0
    for case_index in range(RANDOM_CASES):
        rng = random.Random(MASTER_SEED * 1000 + case_index)
        caps, terms, draws, sweep_ts = _generate_case(rng)
        specs = [SpecGrant(**t) for t in terms]
        spec_book = SpecBook(caps, [SpecGrant(**t) for t in terms])
        book, gids = _real_book(caps, specs)
        for index, amount, ts in draws:
            d = _assert_draw_matches(
                book, gids[index], spec_book, index, amount, ts)
            total_draws += 1
            if d.drawn:
                settled_draws += 1
            else:
                refused_draws += 1
        _assert_full_sweep(book, gids, spec_book, sweep_ts)
    assert total_draws > 0
    assert settled_draws > 0
    assert refused_draws > 0
