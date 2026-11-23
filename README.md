# Splunk Detection Lab — BOTS v3 (Boss of the SOC)

Home lab, not employment. Splunk Enterprise (free licence, 500 MB/day) on a
Windows 11 host laptop (Intel i3 / 8 GB RAM), with the Splunk BOTS v3 dataset
— pre-indexed, ~320 MB, CC0, from https://github.com/splunk/botsv3 — loaded
as an app. No credit card, no VM for Splunk, DC01 kept off while Splunk runs.

Dataset: BOTS v3, fictional company Frothly (brewing). All data is from
20 Aug 2018 in the dataset. Search with `index=botsv3 earliest=0` — the
dates are old, so the default time range finds nothing.

## Setup

1. Install Splunk Enterprise for Windows, log in at http://localhost:8000
   as `admin`.
2. Apps > Manage Apps > Install app from file > select
   `botsv3_data_set.tgz` > Upload.
3. Restart Splunk (Settings > Server controls > Restart Splunk) — it did
   not prompt for a restart in this run, so it was restarted manually.
4. Verify: `index=botsv3 earliest=0 | head 5` — events show up.
   See `screenshots/setup-botsv3-loaded.png`.

Note: the install folder is not `E:\Splunk` and not
`C:\Program Files\Splunk`. Splunkd service was confirmed Running
(`Get-Service *splunk*`), the real path was never needed — the app was
loaded through Manage Apps in the web UI, not by copying files.

## Investigations (3)

### 1. S3 bucket exposed to the public — CONFIRMED

- 2018-08-20 18:31:46 — user `bstoll` from `107.77.212.175` ran
  `PutBucketAcl` on bucket `frothlywebcode`, granting
  `http://acs.amazonaws.com/groups/global/AllUsers` READ, WRITE and
  FULL_CONTROL. The bucket was open to the public.
- 2018-08-20 19:27:54 — `bstoll` ran `PutBucketAcl` again, AllUsers gone,
  only LogDelivery grants left. Open for about 56 minutes.
- External access inside the open window:
  - 18:33:46 — `35.182.246.222` — `GET.OBJECT OPEN_BUCKET_PLEASE_FIX.txt`,
    200, 377 bytes, and `GET.OBJECT frothly_html_memcached.tar.gz`,
    200, 3,057,116 bytes. `OPEN_BUCKET_PLEASE_FIX.txt` is a canary file
    scanners leave in open buckets.
  - 19:03:35 — `54.183.247.244`, assumed role
    `EC2InstanceRole/i-0cc93bade2b3cba63` — `GET.OBJECT
    frothly_html_memcached.tar.gz`, 200, 3,076,532 bytes.
- Verdict: the bucket was exposed AND accessed externally within 2 minutes
  of opening. The 19:03 download was by an authenticated EC2 instance
  role, not an anonymous AllUsers request, so anonymous exploitation is
  not proven from these logs alone — that EC2 instance is the follow-up.
- Screenshots: `inv1-putbucketacl.png`, `inv1-s3-download.png`,
  `inv1-timeline.png`. Full note: `findings/triage-notes.md`.

### 2. Windows logons — NO brute-force

- Failed logons (EventCode 4625): only 4 in the whole dataset —
  `SEPM$` 2, `Guest` 1, `MalloryKraeusen` 1.
- Successful logons (EventCode 4624): all machine accounts —
  `SYSTEM` 364, `BSTOLL-L$` 148, `PCERF-L$` 47, `BGIST-L$` 45,
  `MKRAEUS-L$` 40, `JWORTOS-L$` 33, `BTUN-L$` 30, `FYODOR-L$` 23,
  `ABUNGST-L$` 11.
- The 4625 rows are all local: `Source_Network_Address` is `-`,
  Logon_Type 3 and 5, no external IP. No burst of failures followed by
  a success.
- Verdict: no Windows brute-force in this dataset. This is a negative
  finding, recorded honestly — not an attack.
- Note: the Investigation 2 results were pasted as text, not saved as
  screenshot files, so there are no `inv2-*.png` files in this repo yet.
  The numbers above are the recorded results.

### 3. Network traffic — NORMAL

- Top DNS queries (`stream:dns`, 218,456 events): `splunk.froth.ly`
  5,684, `polaris.cr7wwvryvz4o.us-west-1.rds.amazonaws.com` 814,
  `outlook.office365.com` 721, `ssm.us-west-1.amazonaws.com` 422,
  `nexusrules.officeapps.live.com` 340. All normal Microsoft / AWS.
- Top talkers (`stream:ip`, 105,093 events): all internal IPs —
  `172.31.12.76` 14,066, `172.16.0.109` 13,385, `172.31.38.181` 13,255,
  `172.16.0.178` 13,198, `172.16.197.137` 7,426.
  `172.16.197.137` is a normal client (Chrome updates / file downloads,
  mostly HTTP 206), not an attacker — it was first picked up by a query
  using the wrong field name, then cleared.
- Cisco ASA denied (`cisco:asa action=denied`): 0 events, no results.
- Verdict: no suspicious domain, no external attacker IP, no denied
  connections in this slice.
- Screenshots: `inv3-top-dns.png`, `inv3-top-talkers.png`,
  `inv3-asa-denied.png`.

## Field names that tripped this lab up

BOTS v3 is pre-indexed with no Windows / CIM add-on, so the usual CIM
aliases do not exist. Use the raw field names:

- Windows source IP: `Source_Network_Address`, not `src_ip`
- Web status: `status`, not `http_status`; URI: `uri_path`, not `http_uri`
- Web logs are `sourcetype=stream:http`, not `access_combined`
- CloudTrail user: `userIdentity.userName`; IP: `sourceIPAddress`
- S3 access logs (`aws:s3:accesslogs`) have no extracted fields at all —
  search the raw text, e.g. `frothlywebcode "GET.OBJECT"`

## Structure

- `findings/triage-notes.md` — full SOC triage notes for all 3 investigations
- `queries/spl-queries.spl` — every SPL search used, copy-paste ready
- `screenshots/` — 7 screenshots (3 for Investigation 1, 3 for
  Investigation 3, 1 setup shot). Investigation 2 has no screenshot
  files yet — see above.

## Tools

Splunk Enterprise (free), BOTS v3 dataset, SPL. No other tools.
