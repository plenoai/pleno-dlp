Owners: core-engineer, qa

The engine now records, per keyword-hit window, whether any hit was one of the detector's own keywords. Windows reached only through a keyword of a format registered for the detector's type (`detectors.RegisterFormats`) run the formats alone and skip the detector's `FromData`; detectors without keywords of their own keep running `FromData` on format hits. Finding sets on croc, rails and django git history are identical before and after, and django CPU drops about 3 % (closes #986, part of #978).
