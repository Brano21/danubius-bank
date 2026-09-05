"""Week 4 - blue-team investigation (WEEK >= 4).

Week 4 is NOT a set of web vulnerabilities. This module is an evidence GENERATOR:
it renders one coherent incident (consistent with the W1/W2 attacks) into offline
artifacts - access.log, auth.log, a real capture.pcap and a benign Windows PE
sample - that the operator hands to players via CTFd. Players investigate; they
do not attack the app.

Kept Flask-free on purpose so the generation logic (artifacts.py / scenario.py /
generator.py) runs standalone with the standard library only. The optional
operator download page lives in web.py and is imported by the app factory.
"""
