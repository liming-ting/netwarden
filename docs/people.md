# People and presence ("who's home")

## People (`people.py`, `store.people`)

A person has a name (unique, case-insensitive, max 40), an avatar (an emoji or up to 3
letters; empty = initials), a color (`people.COLORS`), a child flag and a note (max 200).
Names, notes and avatars are hostile text: escaped everywhere.

- A device belongs to at most one person (`device_profiles.owner` = the person's name), to
  **Shared** (`device_profiles.shared = 1`, e.g. the TV) or to nobody.
- Migration: `store.sync_people()` creates a person for every owner named by a device or a
  bedtime rule. It runs in `_migrate` and is idempotent; it never touches existing people.
- A rename carries the person's devices and bedtime rules along (`store.save_person`).
- Delete: devices become unassigned and the person's bedtime rules go too. Undo works
  through `/api/people/restore` with a server-side token (`web.UNDO`, 15 min).
- Bedtime rules, screen time, the weekly report and the digest are per owner name, so they
  work per person.

## Presence (`presence.py`) - opt-in per person, OFF by default

A person is home when one of their **presence devices** was seen recently. The default is
their phones; the People page can choose other devices.

Signals come only from data netwarden already has:
- their DNS lookups;
- `devices.last_seen`;
- the light check `presence.check_recorded()` (runner loop, every `presence.check_minutes`,
  default 5, minimum 2). It uses `discovery.alive` (one ping + TCP knock), only for the
  presence devices of people who opted in, and only at private IPv4 addresses inside the
  local subnet. It never runs on the demo DB. An address is only pinged while fresh: not
  if the device was last seen more than `TARGET_HOURS` (24) ago, nor if a device seen more
  recently holds the same IP (a rotated private MAC / DHCP reuse). A device that answers
  gets `devices.last_seen` updated too, so the map / device list / AI agree with "home".
- **Backup restore never switches presence on** (a new person starts off, an existing one
  keeps their choice; chosen devices + notification switches are restored).
- AI lookups scoped to a person WITHOUT presence never include online / last-active times
  (docs/dev/ai_tools.md).

| state | when |
|---|---|
| `home` | seen within 10 min (or the grace period, if shorter) |
| `probably_home` | seen within `presence.grace_minutes` (default 20) |
| `away` | older than that, while the data is fresh |
| `unknown` | no presence device, never seen since it was turned on, or no fresh data at all for more than max(30 min, grace) |

- **Timeline:** sightings split wherever the gap is longer than the grace period. It gives
  arrivals and departures for today and the 6 days before, plus per-day "home" bars in
  local time. An arrival between 22:00 and 05:00 is marked "late".
- **Turning presence on** needs this computer (loopback) and `confirm: true` after the
  privacy text. History starts at that moment.
- **Forget** sets `presence_since = now` and deletes that person's presence samples.
- **Private MACs:** `link_suggestions()` offers a newly seen device (last 14 days) that
  matches one of a person's devices by hostname, announced name or vendor. A vendor match
  counts only if the old device went quiet; a match with two people is dropped as
  ambiguous. Link (`/api/presence/link`) copies the old device's type, room and label;
  undo with `/api/presence/unlink {undo}`. Dismiss = ack `(mac, presence:link)`; undo with
  `/api/unack`.

## Notifications (`notify.py`)

`notify.route(db, event)` is **the one function** that decides whether an event becomes a
notification. Today the events are `presence.arrive` and `presence.leave`. It returns the
event plus a dedupe `key`, or None.

An event is delivered only if all of these hold:
- the person has presence on;
- the per-person switch is on (`notify_arrive` / `notify_leave`);
- the event became known at most 30 min ago (`notify.MAX_AGE`). A departure is timestamped
  at the last sighting but only known a grace period later: `presence.events()` gives it a
  `due` (= ts + grace) and the age counts from that, so it is notified with any grace.

The dashboard shows the routed events as browser notifications (`app.js checkNotify`), so
nothing leaves the machine. Quiet hours (docs/dev/stageq.md) are decided in `route()` too.

The legacy owner field (`POST /api/profile {owner}`) goes through the same rules as
`POST /api/people` (`people.owner_name`: an existing person matches case-insensitively;
a new name is validated - 40 characters, the 50-person cap).

## API

| | |
|---|---|
| `GET /api/people` | cards: devices, today/week screen time, bedtime, alerts, top services, presence state; `shared`; `unassigned`; legacy `items` |
| `GET /api/person?id=` | card + 7-day screen time, bedtime rules, alerts, `presence_info` (404 `no_person`) |
| `GET /api/presence` | per-person state, reason, timeline; `home_now`; `links`; `notifications`; privacy texts |
| `POST /api/people {person}` | create/update (returns `before` for undo) |
| `POST /api/people/delete {id}` / `restore {undo}` | |
| `POST /api/people/assign {items:[{mac, person:id\|null, shared}]}` | max 200; returns `before` (post it back = undo) |
| `POST /api/presence/settings {id, enabled?, confirm?, devices?, default_devices?, notify_arrive?, notify_leave?}` | enabling or choosing devices: loopback only + `confirm` |
| `POST /api/presence/forget {id}`, `/link {mac, person, dismiss?}`, `/unlink {undo}` | |

## UI

- `#/people` and `#/people/<id>`: cards, detail, person form, presence card (timeline bars
  plus an events list), device picker.
- Other places: a "Home now" strip on Overview; the Person select in the device drawer;
  bulk selection on the Devices table; the palette ("Assign Samsung-TV to Mom", keyword
  `app.palette.assign_kw` in every language).

## AI

The snapshot has `household`: every person, their devices (display names), and screen time
today / over 7 days. It has `presence` only for people who opted in (state, why, last seen,
the last 10 arrivals/departures).

Person names are pseudonymised (`[P1]`) by the Redactor for redacting providers. Offline AI
answers "Is anyone home?" (section `presence`) and "screen time of X" (section `person`).

## Demo

- People: 爸爸, 媽媽 and 小孩 (child), each with phones / laptop / tablet; the TV and the
  Echo are Shared.
- Presence is on for 媽媽 (work days) and 小孩 (school days), with 8 days of check samples
  and one late arrival (22:50, two days ago).
- 爸爸's phone has a new private MAC that announces "爸爸的 iPhone", so a link suggestion
  is pending.
- Everything is seeded once (`meta demo_people`) and never overrides user edits.

## Perf (300-device perf DB, warm)

`/api/people` 23 ms, `/api/person` 21 ms, `/api/presence` 16 ms.

Fixed in this stage: the 12-request parallel page refresh overflowed the listen backlog of
5 and stalled about 1 s on SYN retries. `web.DashboardServer.request_queue_size = 64` fixes
it: 1010 ms → about 140 ms.
