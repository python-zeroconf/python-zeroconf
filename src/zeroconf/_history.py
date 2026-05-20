"""Multicast DNS Service Discovery for Python, v0.14-wmcbrine
Copyright 2003 Paul Scott-Murphy, 2014 William McBrine

This module provides a framework for the use of DNS Service Discovery
using IP multicast.

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301
USA
"""

from __future__ import annotations

from ._dns import DNSQuestion, DNSRecord
from .const import (
    _DUPLICATE_QUESTION_INTERVAL,
    _MAX_KNOWN_ANSWERS_PER_HISTORY_ENTRY,
    _MAX_QUESTION_HISTORY_ENTRIES,
)

# The QuestionHistory is used to implement Duplicate Question Suppression
# https://datatracker.ietf.org/doc/html/rfc6762#section-7.3

_float = float


class QuestionHistory:
    """Remember questions and known answers."""

    def __init__(self) -> None:
        """Init a new QuestionHistory."""
        self._history: dict[DNSQuestion, tuple[float, set[DNSRecord]]] = {}

    def add_question_at_time(self, question: DNSQuestion, now: _float, known_answers: set[DNSRecord]) -> None:
        """Remember a question with known answers."""
        if len(known_answers) > _MAX_KNOWN_ANSWERS_PER_HISTORY_ENTRY:
            # Refuse to pin an attacker-sized known-answer payload.
            # Any pre-existing entry for this question stays in place
            # so legitimate suppression continues; the cost is missing
            # one round of suppression for this (likely malicious)
            # query. Truncating instead would over-suppress because
            # `suppresses()` matches when the stored set is a subset
            # of the incoming known-answers (smaller set, easier match).
            return
        if question not in self._history and len(self._history) >= _MAX_QUESTION_HISTORY_ENTRIES:
            self._evict_to_make_room(now)
        self._history[question] = (now, known_answers)

    def suppresses(self, question: DNSQuestion, now: _float, known_answers: set[DNSRecord]) -> bool:
        """Check to see if a question should be suppressed.

        https://datatracker.ietf.org/doc/html/rfc6762#section-7.3
        When multiple queriers on the network are querying
        for the same resource records, there is no need for them to all be
        repeatedly asking the same question.
        """
        previous_question = self._history.get(question)
        # There was not previous question in the history
        if not previous_question:
            return False
        than, previous_known_answers = previous_question
        # The last question was older than 999ms
        if now - than > _DUPLICATE_QUESTION_INTERVAL:
            return False
        # The last question has more known answers than
        # we knew so we have to ask
        return not previous_known_answers - known_answers

    def async_expire(self, now: _float) -> None:
        """Expire the history of old questions."""
        removes: list[DNSQuestion] = []
        for question, now_known_answers in self._history.items():
            than, _ = now_known_answers
            if now - than > _DUPLICATE_QUESTION_INTERVAL:
                removes.append(question)
        for question in removes:
            del self._history[question]

    def clear(self) -> None:
        """Clear the history."""
        self._history.clear()

    def _evict_to_make_room(self, now: _float) -> None:
        """Drop expired or oldest entries when the history is at cap.

        Peeks at the oldest insertion (dict is ordered) — only runs the
        full O(n) async_expire sweep if it could actually reclaim
        something, else a sustained flood at cap turns each insert into
        a wasted scan. Falls back to oldest-first eviction.
        """
        oldest = next(iter(self._history))
        oldest_entry = self._history[oldest]
        oldest_than = oldest_entry[0]
        if now - oldest_than > _DUPLICATE_QUESTION_INTERVAL:
            self.async_expire(now)
        while len(self._history) >= _MAX_QUESTION_HISTORY_ENTRIES:
            del self._history[next(iter(self._history))]
