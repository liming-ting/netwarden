## What and why

<!-- What does this change, and what problem does it solve? Link the issue if there is one. -->

## How it was tested

<!-- Commands you ran, new tests, browser checks (light/dark, ~375 px / ~1280 px). -->

## Checklist

- [ ] `python3 -m unittest discover -s tests` passes (and `node tests/js/map_layout_test.js` if map code changed)
- [ ] `python3 -m netwarden.i18n --check` passes; new user-facing text has keys in all 12 locale files
- [ ] No new runtime dependency; dashboard still has no build step and loads nothing from the internet
- [ ] Still read-only toward the network; the AI is only called on explicit user action
- [ ] Hostile text is escaped; no secrets in responses, logs or UI
- [ ] No real MAC/IP addresses, hostnames or personal data in code, tests, docs or screenshots
- [ ] Docs / CHANGELOG.md updated if behavior changed
