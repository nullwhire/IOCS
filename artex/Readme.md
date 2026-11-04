# artex-tracker (folder `artex/`)

Collects public feeds of exposed ARTEX instances and keeps ready-to-use lists
for detection. Runs every 6 hours on GitHub Actions.

An exposed ARTEX instance does not mean an attacker. The tool was released as a
pentest framework, so these lists also catch red teams, researchers and victims
who installed it without locking it down. A match means "contact with an ARTEX
instance", not "compromise".

## Sources

| Source | Content | Config |
|---|---|---|
| ThreatBook `Feeds/ARTEX.txt` | IP:port | none |
| Maltrail `malicious/artexai.txt` | IP:port and domains | none |
| ScanMalware (ARTEX hunt) | IPs/domains from the Atom feed | secret `SCANMALWARE_FEED` (feed.atom URL) |
| FOFA (`icon_hash="-576220750"`) | IP:port, hosts | secrets `FOFA_KEY`, `FOFA_EMAIL` |





## Output (`artex/data/`)

- `ips.txt` unique active IPs
- `ipport.txt` active IP:port pairs
- `domains.txt` active domains
- `master.csv` full history: type, indicator, sources, first_seen, last_seen, cdn

"Active" means seen in the last 14 days (`ACTIVE_DAYS`). `last_seen` is only
rewritten every 7 days (`REFRESH_DAYS`) so the daily commit does not touch
thousands of lines. An indicator that disappears from the sources can therefore
stay active for 7 to 14 days.

IPs in Cloudflare ranges stay in `master.csv` with `cdn=1` and are left out of
the lists, because they are anycast addresses shared by many sites.





## Limitations

- The ThreatBook and Maltrail parsers were tested against the real format
  (Maltrail) and a sample (ThreatBook). The ScanMalware parser extracts IPs and
  domains from all text in the Atom feed without knowing the exact format, and
  the FOFA one follows the API documentation without having been run. Check
  both on the first run.
- The feeds come from third parties. Keep the attribution (Maltrail is MIT) and
  do not republish them as your own feed without checking ThreatBook's terms.

