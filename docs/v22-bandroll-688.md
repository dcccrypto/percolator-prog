# #688 band-roll straddle: sliding 1-h window

Problem: `observe_price` stepped the 1-h reference once an hour, so a fast move straddling the roll never exceeded 30 % against the reference and never tripped the breaker.

Fix (unreleased v2.2, no live guards): the band keeps `BAND_MARKS = 8` marks, at most one per 450 slots (1 h / 8). Each observation is checked against every mark younger than an hour, so the window slides. Not a Toly port (upstream has no lev_guard band). Matches keeper #126/#127.

Layout: `pb_ref_px`/`pb_ref_slot` (16 B at 128) become `_pad4` (must be zero); `pb_marks_px`/`pb_marks_slot` (128 B) appended at 360. Record 360 -> 488 B; guard body 4456 -> 4584 B. `LEV_GUARD_VERSION` 1 -> 2; `validate_guard` refuses version 1 records (on-chain, a v1 account is already rejected earlier by the body-length check). There is no close/realloc/migrate op and `OP_INIT` needs an empty PDA, so a pre-existing v1 guard (and a market with its guard flag set) is stuck: it must be replaced by a new market or program id. Acceptable only because v2.2 is unreleased and devnet guards are disposable; no on-chain check was done by this job. With samples at least every 450 slots the window looks back at least 7/8 h (up to 1 h); with sparser samples marks are further apart (tighter-or-equal than the keeper only inside that margin).
