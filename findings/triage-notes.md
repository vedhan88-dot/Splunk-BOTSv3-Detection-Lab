# SOC Triage Notes — Splunk BOTS v3

Dataset: `index=botsv3`, BOTS v3, Frothly. All times 20 Aug 2018 (dataset
dates). Analyst: Vedhan Lad. Lab, not a real incident.

## Investigation 1 — S3 bucket frothlywebcode exposed to the public

Severity: High. Status: Confirmed, with external access.

### What happened

| Time (2018-08-20) | Who / from | Event |
|---|---|---|
| 18:31:46 | `bstoll`, 107.77.212.175 | `PutBucketAcl` on `frothlywebcode` — granted `AllUsers` READ, WRITE, FULL_CONTROL |
| 18:33:46 | 35.182.246.222 | `GET.OBJECT OPEN_BUCKET_PLEASE_FIX.txt` 200, 377 bytes; `GET.OBJECT frothly_html_memcached.tar.gz` 200, 3,057,116 bytes |
| 19:03:35 | 54.183.247.244, assumed-role `EC2InstanceRole/i-0cc93bade2b3cba63` | `GET.OBJECT frothly_html_memcached.tar.gz` 200, 3,076,532 bytes |
| 19:27:54 | `bstoll`, 107.77.212.175 | `PutBucketAcl` again — AllUsers gone, only LogDelivery grants |

Exposure window: about 56 minutes (18:31:46–19:27:54).

### Evidence

- CloudTrail: `sourcetype=aws:cloudtrail eventName=PutBucketAcl` —
  `userIdentity.userName=bstoll`, `sourceIPAddress=107.77.212.175`,
  `requestParameters.bucketName=frothlywebcode`,
  `Grant{}.Grantee.URI=http://acs.amazonaws.com/groups/global/AllUsers`,
  `Grant{}.Permission=READ, WRITE, FULL_CONTROL`.
  See `screenshots/inv1-putbucketacl.png` and `inv1-timeline.png`.
- S3 access logs: `sourcetype=aws:s3:accesslogs frothlywebcode
  "GET.OBJECT"` — raw text, no extracted fields. The 18:33:46 rows from
  35.182.246.222 and the 19:03:35 row from 54.183.247.244 are in
  `screenshots/inv1-s3-download.png`.
- `OPEN_BUCKET_PLEASE_FIX.txt` is a canary file scanners leave in open
  buckets — the 18:33:46 access, 2 minutes after opening, is consistent
  with an external scanner finding the bucket.

### Verdict

The bucket was publicly exposed AND accessed externally during the
window. The 19:03:35 download was by an authenticated EC2 instance role,
not an anonymous AllUsers request, so anonymous exploitation is not
proven from these logs alone.

### Follow-up

1. Check whether EC2 instance `i-0cc93bade2b3cba63` was supposed to pull
   `frothly_html_memcached.tar.gz`, or whether its role was abused.
2. Check whether 35.182.246.222 accessed anything else in the account.
3. Rotate any credentials / secrets that were in the web code tarball.
4. Prevent recurrence: block public ACLs at the account level, alert on
   `PutBucketAcl` granting AllUsers.

## Investigation 2 — Windows logons (4624 / 4625)

Severity: None. Status: No attack found — negative finding.

### Results

- Failed logons, EventCode 4625, whole dataset: 4 total.
  `SEPM$` 2, `Guest` 1, `MalloryKraeusen` 1.
- Successful logons, EventCode 4624, top accounts: `SYSTEM` 364,
  `BSTOLL-L$` 148, `PCERF-L$` 47, `BGIST-L$` 45, `MKRAEUS-L$` 40,
  `JWORTOS-L$` 33, `BTUN-L$` 30, `FYODOR-L$` 23, `ABUNGST-L$` 11.
- Raw 4625 rows: host `MKRAEUS-L` / `SEPM`, Account_Name
  `MalloryKraeusen` / `SEPM$`, `Source_Network_Address` `-`,
  Logon_Type 3 and 5. All local, no external IP.

### Verdict

No Windows brute-force in this dataset. No burst of failures followed
by a success, and the successful logons are all machine / service
accounts. A negative finding is still a finding — it is recorded here
instead of inventing an attack.

Note: these results were pasted as text during the investigation; no
`inv2-*.png` screenshot files were saved, so none are in this repo.

## Investigation 3 — Network traffic (DNS, top talkers, ASA)

Severity: None. Status: Normal traffic, no indicator found.

### Results

- Top DNS (`stream:dns`, 218,456 events): `splunk.froth.ly` 5,684,
  `polaris.cr7wwvryvz4o.us-west-1.rds.amazonaws.com` 814,
  `outlook.office365.com` 721, `ssm.us-west-1.amazonaws.com` 422,
  `nexusrules.officeapps.live.com` 340, `mars.i-08e52f8b5a034012d`
  307, `mars.i-08e52f8b5a034012d.us-west-1.compute.internal` 307,
  `v10.events.data.microsoft.com` 283, `roaming.officeapps.live.com`
  279, `odc.officeapps.live.com` 276.
  See `screenshots/inv3-top-dns.png`.
- Top talkers (`stream:ip`, 105,093 events): `172.31.12.76` 14,066,
  `172.16.0.109` 13,385, `172.31.38.181` 13,255, `172.16.0.178`
  13,198, `172.16.197.137` 7,426, `192.168.247.131` 6,119,
  `172.16.133.131` 5,990, `172.16.0.145` 4,747, `192.168.247.129`
  4,203, `192.168.3.130` 3,981. All internal (RFC 1918 / 172.31).
  See `screenshots/inv3-top-talkers.png`.
- Cisco ASA denied: `sourcetype=cisco:asa action=denied` — 0 events,
  "No results found". See `screenshots/inv3-asa-denied.png`.

### Notes

- `172.16.197.137` was first flagged by a query using the wrong field
  name (`http_status`, which does not exist in `stream:http`). Checked
  properly, it is a normal client: mostly HTTP 206 partial downloads
  from `/filestreamingservice/files/...` and Chrome component updates,
  a few 200s on `/`, `/json`, `/en-US/livetile/preinstall`. Cleared.
- `stream:http` has no 401 events at all in this dataset, so there is
  no web password spray to report here.

### Verdict

No suspicious domain, no external attacker IP, no denied connections
in this slice. Investigation 3 is a clean bill of health for the
network data checked.
