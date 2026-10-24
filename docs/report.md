# Home report

[繁體中文](report.zh-TW.md)

A plain-language summary of your home network that you can save, print or send to the
family member or friend who helps you with computers. It is built from the same data the
dashboard shows. It needs no AI and makes no network request.

## What is in it

- **Home score**: the 0-100 score, what lowers it, and the trend.
- **Suggestions**: the top suggestions with their steps. Up to 8 are listed; any others
  stay in the dashboard.
- **Devices**: counts by type, devices new in the period, devices not yet identified, and
  (at the full level, or with names kept) a device table.
- **Security and privacy**: findings such as threats, open ports and DNS blind spots, plus
  privacy grades.
- **Network health**: the outages in the period, and DNS answers per day for the last 7 days.
- **Notable events**: highlights of the period.

The period is **7 days** (the default) or **30 days**. Charts are drawn inline (SVG).

## Privacy levels

| Level | What it shows | What it hides |
|---|---|---|
| **Shareable** (default) | Score, suggestions, devices, findings, health, events | MAC and IP addresses, raw domain names (service names are shown instead, such as "YouTube"), and copyable filter rules. Device names become their type ("Phone 2") and people become roles ("Child 1", "Family member 2"), unless you choose to keep names (a kept name that contains an address or a domain, such as `nas.example.org`, still has that part replaced by •••). |
| **Minimal** | Score and suggestions only | The same as shareable. Names are always replaced, with no option to keep them. |
| **Full detail** | Everything, including MAC/IP addresses and filter rules | Nothing from your network. |

Hidden values appear as `•••`. Room names stay, at every level.

No level ever contains API keys, tokens, pairing codes, passwords or configured server
URLs. The report never reads them.

## How to make one

**Dashboard**: open **Overview > Report**, press `g` then `r`, or type "report" in the
command palette (Ctrl+K). Choose the period, privacy level, names, people and format. Then
use **Preview**, **Download** or **Copy as Markdown**.

**Command line**:

```bash
python3 -m netwarden report                          # 7 days, shareable, HTML, default language
python3 -m netwarden report --period 30d --privacy minimal --lang en
python3 -m netwarden report --privacy shareable --names keep --people keep --out home.html
python3 -m netwarden report --format md --out -      # Markdown to stdout
```

The default file name includes the date, for example
`netwarden-report-2026-10-24-7d-shareable.html`. An `--out` file ending in `.md` selects
Markdown.

**API**: `GET /api/report?period=7|30&privacy=full|shareable|minimal&names=type|keep&people=roles|keep&format=html|md&lang=<code>`
returns the report as a file attachment. Add `inline=1` to view it in the browser instead.
An unknown option returns a localized 400 error.

## Phone / LAN mode

A paired phone (or any non-admin session) can download **shareable** and **minimal**
reports. **Full** needs admin access: the computer running netwarden, or an admin pairing
(`pair --admin`). Otherwise the server answers 403.

## The file

- One HTML file with its CSS inside. It has no scripts, loads no fonts or images from
  anywhere (a Content-Security-Policy blocks it), and opens offline.
- It prints on A4 and Letter, with each section on a new page. On screen it follows your
  light or dark theme. It always prints light.
- The header shows the date, the period, the privacy level, the netwarden version and the
  source URL.
- The same options always give the same file for the same data.

## Limitations

- Everything is an **estimate** from DNS and discovery data, like the dashboard.
- Security findings use the last 24 hours, even in a 30-day report. That is the window the
  alerts are computed for. Outages and events cover the whole period.
- The scrubbing hides every name, MAC address and IP address that netwarden knows, plus
  anything that looks like an IP address or a domain. A name it has never seen, such as a
  family name that is part of a device's announced model text, can still slip through.
  Read a report before you share it.
- The router's make and model stay at every level, so a helper knows which manual to open.
