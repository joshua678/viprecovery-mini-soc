# VIP Recovery mini-SOC report (2026-01-09 PCAP)

- Time range (UTC): 2026-01-09T18:04:43.417655+00:00 -> 2026-01-09T18:05:07.866643+00:00
- Total events (all Zeek logs imported): 51

## Event volume by type

- files: 12
- http: 10
- x509: 9
- conn: 8
- dns: 6
- ssl: 4
- smtp: 2

## First-seen timestamp by type (UTC)

- conn: 2026-01-09T18:04:43.417655+00:00
- dns: 2026-01-09T18:04:43.417655+00:00
- ssl: 2026-01-09T18:04:43.535258+00:00
- x509: 2026-01-09T18:04:43.587532+00:00
- http: 2026-01-09T18:04:48.819253+00:00
- files: 2026-01-09T18:04:49.435145+00:00
- smtp: 2026-01-09T18:05:01.106788+00:00

## Hits for key indicators (derived from Zeek logs)

### checkip.dyndns.org (matches: 11)

- 2026-01-09T18:04:48.444009+00:00 [dns] checkip.dyndns.org
- 2026-01-09T18:04:48.819253+00:00 [http] checkip.dyndns.org
- 2026-01-09T18:04:49.441503+00:00 [http] checkip.dyndns.org
- 2026-01-09T18:04:50.568998+00:00 [http] checkip.dyndns.org
- 2026-01-09T18:04:50.876495+00:00 [http] checkip.dyndns.org
- 2026-01-09T18:04:51.241780+00:00 [http] checkip.dyndns.org
- 2026-01-09T18:04:51.541024+00:00 [http] checkip.dyndns.org
- 2026-01-09T18:04:51.953571+00:00 [http] checkip.dyndns.org

### eraqron.shop (matches: 3)

- 2026-01-09T18:05:00.248883+00:00 [dns] eraqron.shop
- 2026-01-09T18:05:01.106788+00:00 [smtp] rejump@eraqron.shop ['jump@eraqron.shop']
- 2026-01-09T18:05:05.919550+00:00 [smtp] rejump@eraqron.shop ['jump@eraqron.shop']

### firebasestorage.googleapis.com (matches: 2)

- 2026-01-09T18:04:43.417655+00:00 [dns] firebasestorage.googleapis.com
- 2026-01-09T18:04:43.535258+00:00 [ssl] firebasestorage.googleapis.com

### cubbit.eu (matches: 2)

- 2026-01-09T18:04:45.902836+00:00 [dns] 1zil1.s3.cubbit.eu
- 2026-01-09T18:04:46.131811+00:00 [ssl] 1zil1.s3.cubbit.eu

### reallyfreegeoip.org (matches: 2)

- 2026-01-09T18:04:49.825401+00:00 [dns] reallyfreegeoip.org
- 2026-01-09T18:04:49.947895+00:00 [ssl] reallyfreegeoip.org

### api.telegram.org (matches: 2)

- 2026-01-09T18:04:53.609398+00:00 [dns] api.telegram.org
- 2026-01-09T18:04:53.797196+00:00 [ssl] api.telegram.org

