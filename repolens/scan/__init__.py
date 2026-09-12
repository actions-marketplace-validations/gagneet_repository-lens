"""Static security and performance detectors over the Python source tree.

Read-only and import-free: files are parsed with `ast`, never imported or executed.
Every detector states its confidence. The ones that guess (a missing object-level check,
say) guess at LOW confidence and say what they could not see, rather than guessing at a
lower severity — so a report sorted by priority puts certain findings first without
pretending the uncertain ones are minor.
"""
