# Stage U - fresh-eyes usability study and fixes

Method: a private `--offline-ai` server on 127.0.0.1:8799 against a copy of the demo DB,
Chrome at ~375 px (phone, touch) and ~1280 px (laptop), light and dark, zh-Hant / en /
de. Two personas, starting from the Overview with no prior knowledge:

- **P1** - a non-technical parent on a phone (zh-Hant).
- **P2** - a privacy-minded power user on a laptop (en, keyboard first).

## What the study found (before)

The app had grown to **15 top-level items** (Overview, Inbox, Devices, Map, People,
Security, Network health, Suggestions, Privacy, Activity, Family, AI assistant, System,
Settings + the wizard). On a phone four sat in the bottom bar, ten behind "More".

| # | Task | Steps before | Friction (P1 = parent, P2 = power user) |
|---|------|--------------|------------------------------------------|
| 1 | New device: what is it, mark known, name + owner | Inbox → row title → drawer (name, type, owner, room) | Fine once in the drawer, but the owner list had no way to add a person who is not there yet - a dead end for P1 ("Grandma" does not exist). "Trust" is netwarden jargon; the button had no explanation. |
| 2 | Kids' tablet to a child + school-night bedtime | Devices → drawer → owner; then More → **Family** (not People) → Bedtime rules | P1 opened "家庭成員" (People) looking for bedtime, then had to find "家庭" (Family) - two look-alike menu entries next to each other. |
| 3 | "Who's home" for yourself, then who is home now | More → People → person → presence | Worked; the Overview "Home now" strip answers the second half. |
| 4 | Quiet hours, then what was held overnight | More → Settings → Quiet hours; the held summary card on Overview/Inbox | Summary card button said "關閉 / Close" - P1 read it as "turn quiet hours off". |
| 5 | Why did an alert fire + less sensitive for one device | Inbox → "Why this alert?" → Tune | Each inbox row carried **5 equal buttons** (Got it, Mute, Snooze 3 days, Trust, Tune) with no explanation; P1 could not tell "Got it" from "Mute" or "Snooze". |
| 6 | Which device used most data last night (offline AI) vs dashboard | Ask AI → question; Network → Activity "Top talkers" | Page title said "AI 對話" while the menu said "AI 助理" - two names for one place. |
| 7 | Anything risky on the router + what to do | Security → hygiene card + UPnP card + "How to fix" links | OK for P2. P1 did not know Security sat apart from "Network health" and "Privacy". |
| 8 | Yesterday's outages | More → Network health → Outage log | OK, but "Network health" was one of ten items behind More. |
| 9 | Print weekly report; CSV; backup | Family → print; System → Export; Settings → Backup | "System" and "Settings" are near-synonyms (系統 / 設定); P1 opened the wrong one first every time. |
| 10 | Find a device by part of its name | `/` or the search box | Good (fuzzy, also "Trust X" / "Mute X" actions). |
| 11 | Undo a mistake; English and back | Toast "Undo", Ctrl+Z; language select | Good. |
| 12 | First-run wizard (empty DB); pairing with REQUIRE_AUTH | #/welcome; Settings → "Open on your phone" | Read through the code and existing Stage X/M tests; not re-run in the browser this round (see "Left as is"). |

Counts also disagreed: the Overview hero said "Needs your attention: 13", the Inbox
badge 19, the Security badge 13 and "More" 9 - the same alerts counted in up to three
places.

## What changed (after)

1. **Seven places, sub-tabs inside** (`GROUPS` in `static/app.js`):

   | Place | Pages (sub-tabs) |
   |-------|------------------|
   | Overview | - |
   | Inbox | Inbox · Suggestions |
   | Devices | Devices · Map |
   | Family | People · Screen time & bedtime |
   | Network | Security · Network health · Privacy · Activity |
   | AI assistant | - |
   | Settings | Settings · System status |

   Everyday places first, settings last. Every old route (`#/security`, `#/system`,
   `#/people/<id>`, drawers ...) is still a page of its own, so bookmarks, deep links,
   server `href`s and docs keep working without redirects; a place's link opens its first
   page. Phones: Overview, Inbox, Devices, Family in the bar; Network, AI, Settings under
   "More" (3 instead of 10). Keys **1-7** = the places; `g` + letter still reaches any
   page; the palette lists every page as "Network › Security" so either word finds it.
   Tasks 2, 7, 8 and 9 now take one obvious tap instead of a hunt.
2. **One badge per place**: only Inbox counts (it already holds every alert and
   suggestion) plus "the internet is down now" on Network. The per-page counts moved to
   the sub-tabs (Security 13, Suggestions 9), where they explain themselves. The Overview
   hero gained an "Open the inbox (19 to do)" button that names the inbox number.
3. **Inbox rows: two everyday buttons + "More options"**: "Got it"/"Done" and, for a
   device, "Trust" stay visible; Mute, Snooze, Dismiss and Tune sit in a disclosure, each
   with one plain sentence ("No more alerts of this kind for this device.", "Hide it for 3
   days, then show it again."). Every button's tooltip carries the same sentence. The
   keyboard triage (`a t m s d x u`) is unchanged.
4. **"Add a person…" in a device's owner list** (drawer): opens the person form on
   People with "After you save, roborock-vacuum will belong to this person."; saving
   creates the person and assigns the device (two toasts, each undoable). Not shown on a
   paired phone.
5. **Wording** (all 12 languages): "Family" (the screen-time page) is now "Screen time &
   bedtime" under the Family place; "System" is "System status"; the quiet-hours summary
   button "Close" is "Hide summary"; the AI page title uses the menu's name. A test keeps
   page and place names unique per language.

## Left as is (and why)

- The device drawer's type select repeats its label ("Type: automatic (...)") - harmless,
  and the "automatic" part is useful.
- The Security page's subtitle is a reassurance ("netwarden never changes your router")
  rather than a description; it answers the question P1 actually asked ("will this break
  my Wi-Fi?").
- Network health in the demo says "88% of DNS lookups are failing right now" next to a
  9% 7-day average: that is the demo story (a current ISP outage), not a bug.
- First-run wizard and phone pairing were not re-driven in the browser this round (one
  study server on :8799 only; both flows have browser checks and tests from Stages X/M
  and nothing in them changed except the place they sit in).
- No new settings, endpoints or data, so `scripts/demo_seed.py` needed no new story.

## Round 9 U - keyboard first

**Command palette** (`app.js`, "Command palette" section; `tests/js/palette_match_test.js`,
`tests/test_round9_u.py`). Ctrl+K / Cmd+K or the header search box (also the phone's search
button). Groups, in order: recent (empty query), devices, pages, people & rooms, services
and domains (the existing `/api/search`, debounced - no new endpoint), actions, settings,
"ask the assistant". Rules:

- Matching (`fold()` + `fuzzy()`): NFKD + no accents + lower case + `TS_PAIRS`
  (Traditional -> Simplified for the characters the UI and demo use). Tiers: substring >
  every word present > word-start initials (span <= 32), CJK characters count as word
  starts. Settings match their label and key, never their help text (too much noise).
- Device haystack `devHay()`: name, label, hostname, vendor, MAC (with and without
  separators), IPs, owner, room, type. The Devices / Map / person-picker filters use the
  same `matches()`.
- Permissions follow the buttons: scan, pair, backup/restore, check, wizard and settings
  are offered only on this computer (`!S.meta.remote`; scan not on the demo). Settings load
  lazily on the first palette open (local only).
- "Mute for 1 hour" = tuning snooze `for: '1h'` per alert kind of that device, skipping
  kinds that already have a longer rule; one toast, one Undo restores every row. "Pause
  routine alerts" leaves `tuning.CRITICAL_KINDS` alone.
- "Ask the assistant" opens the chat with the text pre-filled; it never sends.
- APG: input `role=combobox` + `aria-activedescendant`; `ul role=listbox` > `li role=group`
  (labelled) > `li role=option`; `#palcount` announces the result count. Focus returns to
  where it was BEFORE the chosen entry runs.

**Shortcuts.** Global keydown ignores `isComposing` / keyCode 229 first, then typing
targets, then single keys if they are off (`ui.shortcuts` = the home default via
`/api/meta.shortcuts`; `localStorage netwarden.single_keys` = this browser). Ctrl/Cmd+K and
Ctrl/Cmd+Z always work. `/` = `focusFilter()` (Devices, Map, people picker), else the palette.

**Remembered view.** `VIEW_PAGES` (devices, map, suggestions): each field validated
(`vStr` / `vOne`), stored under `netwarden.view.v1.<db>` and mirrored into the hash query
with `history.replaceState` (relative `#/...` only - ingress-safe). A link without a query
keeps the remembered view; one with a query sets it exactly. Scroll is saved per history
entry (`history.state.nw` + sessionStorage `netwarden.scroll`, 60 entries) and restored on
Back / reload until the user scrolls. `<details data-persist>` sections remember open/closed.

**Friction pass** (10 tasks, 1280 + 375 px, both themes, zh-Hant + en; keyboard-only for
rename, why-this-alert, a kid's phone, change language, undo). Fixed:

- Enter in a drawer field (name, room) saved but dropped focus to the page: now keeps it.
- Enter in the Devices filter did nothing: opens the only match, else focuses the first row.
- Two quiet-hours summaries had identical titles: with more than one, each names its night.
- Languages were only found by their own name: now also by their name in English and in
  the current language (`Intl.DisplayNames`).
- The demo's first-run card: the Overview button touched the text (spacing).
- The palette's "ask" row lost its label on phones under the hint: two-line layout.
- The shortcut switch sat under the long key list: moved to the top of the sheet.

Left as is: the drawer opens with focus on Close (three Tabs to Name) so a phone keyboard
does not pop up; the demo's two quiet-hours cards push the phone inbox down (demo story).
