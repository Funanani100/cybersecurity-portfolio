# TryHackMe — Strange & Unusual Activity

> **Category:** Network Forensics / Threat Hunting  
> **Difficulty:** Medium  
> **Platform:** TryHackMe  
> **Tools:** Kibana Discover, Elasticsearch, Zeek  
> **Primary data view:** `zeek-*`  
> **Traffic date stated in the brief:** 7 October 2025

## Table of Contents

- [1. Overview](#1-overview)
- [2. Objectives](#2-objectives)
- [3. Investigation Environment](#3-investigation-environment)
- [4. Investigation Methodology](#4-investigation-methodology)
  - [4.1 Prepare Kibana Discover](#41-prepare-kibana-discover)
  - [4.2 Identify the suspicious domain](#42-identify-the-suspicious-domain)
  - [4.3 Establish the callback interval](#43-establish-the-callback-interval)
  - [4.4 Identify the compromised workstation](#44-identify-the-compromised-workstation)
  - [4.5 Count the callbacks](#45-count-the-callbacks)
  - [4.6 Identify the largest outbound transfer](#46-identify-the-largest-outbound-transfer)
- [5. Findings and Indicators](#5-findings-and-indicators)
- [6. Analysis and Interpretation](#6-analysis-and-interpretation)
- [7. Defensive Recommendations](#7-defensive-recommendations)
- [8. Lessons Learned](#8-lessons-learned)
- [9. References](#9-references)

---

## 1. Overview

The **Strange & Unusual Activity** room presents a network threat-hunting scenario in which a threat-intelligence feed has flagged suspicious communications inside the corporate network `10.10.14.0/24`. The organisation's usual security monitoring did not generate an alert, so the investigation relies on network telemetry to identify the source and understand the activity.

The task is to examine a set of Zeek logs in Kibana, distinguish suspicious traffic from ordinary network activity, identify the workstation communicating with a suspected command-and-control (C2) service, measure the recurring callback pattern, and investigate the largest outbound transfer.

The investigation follows two main evidence sources:

- **Zeek DNS logs** (`zeek-dns`) to identify unusual domain lookups, determine the originating host, and examine the callback cadence.
- **Zeek connection logs** (`zeek-conn`) to correlate the workstation with the C2 destination and measure outbound bytes.

The central finding is a workstation at `10.10.14.160` repeatedly querying `edge-metrics-sync.net`, with an approximately five-minute callback cadence. Connection records also show a largest originator-to-responder transfer of `54,078,822` bytes to the associated destination.

## 2. Objectives

1. Examine the captured network activity for unusual communication patterns.
2. Identify a suspicious domain and determine whether its requests are periodic.
3. Identify the internal workstation responsible for the communications.
4. Correlate the DNS evidence with connection records.
5. Determine the largest amount of data sent from the workstation to the suspected C2 destination.

## 3. Investigation Environment

| Item | Value |
|---|---|
| Platform | TryHackMe |
| Room | Strange & Unusual Activity |
| Difficulty | Medium |
| Analysis interface | Kibana — Discover |
| Log source | Zeek |
| Data view | `zeek-*` |
| Relevant log types | DNS and connection (`zeek-dns`, `zeek-conn`) |
| Internal network in scope | `10.10.14.0/24` |
| Capture date stated in the brief | 7 October 2025 |

### Accessing the analyst workspace

1. Deploy the TryHackMe room machine.
2. Open the Kibana interface at `http://MACHINE_IP:5601` using the machine address supplied by the room.
3. Navigate to **Discover**.
4. Select the `zeek-*` data view.
5. Set the time picker to the period being investigated. Use UTC where possible so that displayed timestamps can be compared consistently.

> **Time-range note:** The room describes a 24-hour capture for 7 October 2025. However, the callback-count result reported for this challenge is **289** when the Discover time range includes the complete set of relevant callback records. A strict `2025-10-07 00:00:00` to `2025-10-08 00:00:00` UTC range has been reported to show **253** matching DNS records. If the count is 253, inspect the earliest and latest matching timestamps and expand the time picker to include the remaining related events. Do not silently describe 289 as the count inside the strict 24-hour interval; record the time range used for the count in your own evidence.

## 4. Investigation Methodology

The following queries use Kibana Query Language (KQL). Run them in the Discover search bar after selecting the `zeek-*` data view. Depending on the room's Kibana configuration, it may also be possible to select the `zeek-dns` or `zeek-conn` data view directly instead of filtering on `_index`.

### 4.1 Prepare Kibana Discover

1. Open **Discover**.
2. Select `zeek-*`.
3. Set the time picker to an absolute range covering the relevant logs.
4. Confirm that events are being returned before applying filters.
5. Add useful fields as columns while investigating. In Discover, search for a field in the left-hand field list and click the **Add** (`+`) control beside it.

Useful general fields include:

| Field | Purpose |
|---|---|
| `@timestamp` | Time at which the event was recorded |
| `_index` | Elasticsearch index containing the event |
| `id.orig_h` | Originator/source IP address |
| `id.resp_h` | Responder/destination IP address |
| `id.resp_p` | Responder/destination port |
| `proto` | Transport protocol |
| `service` | Service identified by Zeek, when available |
| `query` | DNS name requested by the client |
| `orig_bytes` | Bytes sent by the connection originator |
| `resp_bytes` | Bytes sent by the connection responder |

### 4.2 Identify the suspicious domain

**Goal:** Find DNS queries that do not fit the expected baseline of normal corporate activity.

Start by isolating DNS traffic:

```kql
_index: "zeek-dns" AND id.resp_p: 53
```

If the room's index naming differs, use the `zeek-*` data view and filter on the DNS destination port:

```kql
id.resp_p: 53
```

Next:

1. Locate the `query` field in the left-hand field list.
2. Expand its **Top values** to review the domains present in the DNS events.
3. Compare the domains rather than assuming that every unfamiliar domain is malicious.
4. Look for names that appear repeatedly and investigate their timestamps and associated source hosts.

The domain that stood out during this investigation was:

```text
edge-metrics-sync.net
```

Filter the dataset to that domain:

```kql
_index: "zeek-dns" AND query: "edge-metrics-sync.net"
```

This narrows the results to DNS events involving the suspected domain. Inspect the event details for the source IP (`id.orig_h`) and DNS answer data. The domain was associated in the lab data with `203.0.113.77`, which was then used to pivot into the Zeek connection records.

**Finding:** `edge-metrics-sync.net` was the suspected C2 domain.

### 4.3 Establish the callback interval

**Goal:** Determine whether the workstation contacts the suspicious domain at a recurring interval.

Use the domain filter:

```kql
_index: "zeek-dns" AND query: "edge-metrics-sync.net"
```

Then:

1. Add `@timestamp` and `id.orig_h` as columns.
2. Sort the events by `@timestamp` in ascending order.
3. Compare the timestamps of consecutive requests from the same source host.
4. Calculate the difference between each pair. Account for small variations rather than expecting every gap to be identical.

Example timestamp comparisons from the observed pattern:

| DNS event timestamp (UTC) | Time since previous event |
|---|---:|
| `21:21:39.890` | — |
| `21:26:45.287` | 305.397 seconds |
| `21:32:32.151` | 346.864 seconds |
| `21:37:45.702` | 313.551 seconds |

The gaps vary, but the repeated activity clusters around five minutes. The expected callback interval is therefore approximately:

```text
5 minutes × 60 seconds = 300 seconds
```

**Finding:** The callback interval is approximately **300 seconds**. Small timing differences may indicate jitter or ordinary scheduling/network variation; the key observation is the recurring cadence.

### 4.4 Identify the compromised workstation

**Goal:** Determine which internal system is generating the suspicious DNS requests.

With the suspicious-domain filter still applied:

```kql
_index: "zeek-dns" AND query: "edge-metrics-sync.net"
```

Inspect the `id.orig_h` field. You can also add it as a column or expand its Top values in the field sidebar.

The originating internal address associated with the suspicious DNS activity was:

```text
10.10.14.160
```

This address belongs to the `10.10.14.0/24` network specified in the incident brief.

**Finding:** The suspected compromised workstation is `10.10.14.160`.

### 4.5 Count the callbacks

**Goal:** Count the DNS check-ins associated with the suspicious domain and the identified workstation.

Use both the domain and source-host filters:

```kql
_index: "zeek-dns"
AND query: "edge-metrics-sync.net"
AND id.orig_h: "10.10.14.160"
```

Kibana Discover displays the number of matching documents above the results table. Treat each matching DNS query record as a check-in for the purpose of this room, and make sure the time picker covers the complete set of relevant events.

**Time-range discrepancy to account for:**

- Strict 7 October 2025 00:00 UTC to 8 October 2025 00:00 UTC: reported result of **253** matching events.
- Expanded range including the complete callback set: reported challenge result of **289** matching events.

The room's accepted callback answer is:

```text
289
```

For a reproducible portfolio record, capture a screenshot that shows the exact KQL query, the Discover time picker, and the document count. The time picker is important context for this result.

### 4.6 Identify the largest outbound transfer

**Goal:** Find the largest amount of data sent from the suspected workstation to the C2 destination.

The investigation now pivots from DNS records to Zeek connection records. The destination IP associated with the domain in the lab data is `203.0.113.77`.

Filter the connection records to traffic from the compromised workstation to that destination:

```kql
_index: "zeek-conn"
AND id.orig_h: "10.10.14.160"
AND id.resp_h: "203.0.113.77"
AND id.resp_p: 443
```

The destination-port condition narrows the results to the HTTPS/TLS service observed in the lab. If the records in your environment use different port values, first inspect the matching connection records and confirm the destination port instead of assuming it.

Add these fields as columns:

| Field | What it tells you |
|---|---|
| `@timestamp` | When the connection occurred |
| `id.orig_h` | Internal source/originator IP |
| `id.resp_h` | External destination/responder IP |
| `id.resp_p` | Destination port |
| `proto` | Transport protocol |
| `service` | Zeek service identification, if populated |
| `orig_bytes` | Bytes sent by the internal originator |
| `resp_bytes` | Bytes sent by the external responder |

The direction of the byte counters matters:

- `orig_bytes` represents data sent by the originator. In this filtered connection, the originator is the compromised workstation (`10.10.14.160`).
- `resp_bytes` represents data sent in the opposite direction by the responder (`203.0.113.77`).

To find the largest outbound transfer:

1. Locate the `orig_bytes` column.
2. Click the column heading to sort it from largest to smallest. If the current sort is based on `@timestamp`, change the sort to `orig_bytes`.
3. Inspect the first/highest record.
4. Confirm that its `id.orig_h` and `id.resp_h` values still match the workstation and C2 destination in the filter.

The largest originator byte count was:

```text
54078822
```

The corresponding record showed `54,078,822` originator bytes and `303` responder bytes.

**Finding:** The largest single outbound transfer to the suspected C2 server was **54,078,822 bytes** (approximately 54.1 MB in decimal units).

> **Forensic wording:** Zeek's connection metadata establishes the number of bytes recorded as sent by the originator. This supports a finding of a large outbound transfer consistent with possible data exfiltration. The connection record alone does not reveal the contents of the transferred data or prove what files, if any, were taken.

## 5. Findings and Indicators

| Investigation question | Finding |
|---|---|
| C2 domain | `edge-metrics-sync.net` |
| C2 destination IP in the lab data | `203.0.113.77` |
| Compromised workstation | `10.10.14.160` |
| Approximate callback interval | `300` seconds |
| Callback count reported by the room | `289` |
| Largest originator-to-responder transfer | `54,078,822` bytes |
| Destination service observed | TCP/443 |

### Indicators of Compromise (IOCs)

| Type | Value | Context |
|---|---|---|
| Domain | `edge-metrics-sync[.]net` | Suspicious, repeatedly queried domain; defanged for safe display |
| IPv4 | `10.10.14.160` | Internal workstation generating the suspicious requests/connections |
| IPv4 | `203.0.113.77` | Destination associated with the domain in the lab connection records |

**Lab-data caveat:** `203.0.113.77` is in `203.0.113.0/24`, the TEST-NET-3 range reserved for documentation and examples. Treat it as the destination represented in this training dataset, not as a real-world routable C2 address. See [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737).

## 6. Analysis and Interpretation

The evidence forms a consistent sequence:

1. DNS telemetry revealed repeated lookups for `edge-metrics-sync.net`.
2. The requests originated from the same internal system, `10.10.14.160`.
3. Consecutive timestamps showed an approximately five-minute recurring pattern, consistent with automated beaconing.
4. The DNS and connection evidence linked the workstation to the destination `203.0.113.77`.
5. Zeek connection metadata showed a much larger outbound transfer, with `54,078,822` bytes sent by the workstation in the largest observed connection.

Taken together, these observations are suspicious and consistent with a host communicating with command-and-control infrastructure and potentially sending data externally. The periodic check-ins are a useful behavioral indicator because they remain visible even when individual connections are not independently alarming.

The investigation does **not** establish the exact contents of the large transfer. Confirming the data involved would require additional evidence, such as packet-level captures, endpoint artefacts, file-access records, or proxy/TLS inspection data where legally and technically available.

## 7. Defensive Recommendations

In a real environment, the following actions would be appropriate, subject to the organisation's incident-response procedures:

1. **Contain the suspected workstation:** Isolate `10.10.14.160` from the network while preserving volatile and forensic evidence where possible.
2. **Preserve evidence:** Retain relevant Zeek DNS and connection logs, endpoint telemetry, firewall/proxy records, and any available packet captures.
3. **Investigate the endpoint:** Review running processes, persistence mechanisms, scheduled tasks, recently created files, browser artefacts, and authentication activity.
4. **Hunt across the environment:** Search DNS, proxy, firewall, and EDR telemetry for the domain, destination address, and similar periodic connection patterns from other hosts.
5. **Review outbound data movement:** Identify other large uploads, unusual destinations, unexpected TLS sessions, and transfers outside normal business patterns.
6. **Block and monitor carefully:** Apply controls for confirmed malicious indicators through the organisation's normal change process, and monitor for alternate domains, IPs, or callback methods.
7. **Improve detection coverage:** Alert on rare domains, repeated low-volume beacons, suspicious DNS frequency, and unusual outbound byte counts—not only on known-malicious signatures.

## 8. Lessons Learned

- **Baseline matters:** A domain or connection should be assessed in context. Unfamiliar does not automatically mean malicious.
- **Look for behavior, not just signatures:** Repeated communication at a stable interval can expose C2 activity that signature-based alerts miss.
- **Correlate data sources:** DNS logs help identify the domain and source host; connection logs help validate the destination and quantify data movement.
- **Understand Zeek's direction fields:** Correctly interpreting `orig_bytes` and `resp_bytes` is essential when measuring outbound traffic.
- **Time filters affect conclusions:** A result count is only meaningful when its time range is documented. This room has a reported difference between the strict 24-hour count and the expanded range used to obtain the accepted callback total.
- **Metadata has limits:** Connection byte counts can indicate potential exfiltration, but do not identify the content transferred.

## 9. References

- [TryHackMe — Strange & Unusual Activity](https://tryhackme.com/room/strangeunusualactivity)
- [RFC 5737 — IPv4 Address Blocks Reserved for Documentation](https://www.rfc-editor.org/rfc/rfc5737)

---

**Disclaimer:** This write-up documents analysis of a controlled TryHackMe training environment. The indicators and conclusions are specific to the lab dataset and should not be treated as evidence of a real-world compromise.

