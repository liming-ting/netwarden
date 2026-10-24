# Stage notes (moved out of CLAUDE.md to keep it short)

**Privacy / visibility / exposure (Stage D1):**
- GET `/api/privacy?lang=&hours=` {home{grade, line}, devices, worst, rules{adguard, pihole}},
  `/api/visibility` {items[{kind, mac, text}], summary, suggestions, rules}; `/api/device`
  adds privacy, visibility, ports (`new` per port), check_allowed/check_note.
- `POST /api/check {mac}` -> 202 {job} (409 {demo:true} on demo DBs); `GET /api/check/status
  ?job=`; CLI `netwarden check --mac M | --all`. `port_checks` history = "newly open".
- **All POSTs require `content-type: application/json`** (415 otherwise; CSRF hardening).
- Ack keys: `port:<n>`, `visibility:bypass|quiet`, `activity:night`, `bandwidth:spike`,
  `upnp:<PROTO>:<port>` (Stage N); `(mac, '')` = trust device (mutes everything for it).
- Demo: TV (ACR, grade F), phone DoH via dns.google, Echo quiet 9 h, Chromecast never in
  DNS, ipcam 23+554 newly open, router 80/443, printer 80/443/9100.

**Types / people / activity (Stage D2):**
- GET `/api/activity?mac=&lang=` (grid, hours, summary, unusual), `/api/timeline?mac=`,
  `/api/search?q=`, `/api/service?name=`, `/api/domain?d=`, `/api/people`, `/api/rooms`,
  `/api/types`. POST `/api/profile {mac, type?, owner?, room?}`: only sent fields change;
  ""/null clears; bad type -> 400 bad_type. Owner/room = hostile text: esc() always.
- Brain snapshot per device: privacy, dns_visibility, open_ports, type/owner/room,
  active_hours, night_share_7d, unusual_hours; top-level timezone, people, privacy.
- Demo: owners 爸爸/媽媽/小孩, rooms 客廳/書房/...; kid's Galaxy-Tab-A7 (randomized MAC) on
  TikTok ~01:00 the last two nights -> alert. 12 devices, 696 events.

**Chat / notifications / keyboard / perf (Stage E2):**
- `POST /api/chat/stream {mode: chat|insight, messages[], mac?, lang}` -> SSE `data: {"t"}`
  chunks, then `event: done` | `event: error {error}` (sanitized). Stop = AbortController ->
  closes the upstream LLM socket. /api/insight|ask|chat stay for scripts.
- Chat = one conversation (sessionStorage `netwarden.chat`, per db_id; open state never
  restored): #/ai or side panel (>= 1440 px side by side, sheet <= 760 px); chips; device
  context chip (mac -> brain FOCUS); safe md(); Stop; retry. LLMError.kind -> err.llm_*.
- Notifications opt-in (System; permission on click only; keys in localStorage
  `netwarden.notified.<db_id>`). Keys `?`, `g`+o/d/s/p/a/i/y, `c`, Esc (topmost layer first).
- Overview counts = attentionGrouped() (threats grouped per device) everywhere; > 8 -> link.

**Family insights (Stage F)** - algorithm, limits and API in docs/family.md:
- GET `/api/screentime?days=1..14&device=&owner=&lang=`, `/api/weekly?lang=`,
  `/api/bedtime?lang=`, `/report/weekly?lang=` (printable HTML page, A4 print CSS).
- POST `/api/bedtime {rule, restore?}` (create / update; 404 unknown id unless restore,
  409 > 50 rules), `/api/bedtime/delete {id}`, `/api/bedtime/preview {rule}` -> 400
  {error, field} on a bad rule. Ack key `bedtime:<rule id>:<night YYYY-MM-DD>`.
- Keys: `8` / `g f` = Family. Digest: "🛏️ Bedtime" + "👪 Family" sections (12 langs).
