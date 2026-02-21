---
layout: post
title:  NSA Codebreaker 2025 T2
description: A walkthrough of the NSA Codebreaker 2025 T1 challenge detailing how a forensic analysis of a PCAP in Wireshark uncovered a rogue DNS server, suspicious FTP activity, and multiple IP addresses assigned to a malicious device.
date:   2026-02-21 10:20:25 +0300
image:  '/images/Pasted image 20251220130411.png'
tags:   [Forensics]
---

# Challenge Overview
With your help, the team concludes that there was clearly a sophisticated piece of malware installed on that endpoint that was generating some network traffic. Fortunately, DAFIN-SOC also has an IDS which retained the recent network traffic in this segment.

DAFIN-SOC has provided a PCAP to analyze. Thoroughly evaluate the PCAP to identify potential malicious activity.

**Downloads**:

- PCAP to analyze (traffic.pcap)

**Prompt**:

- Submit all the IP addresses that are assigned to the malicious device, one per line

---

# Methodology

To start, I ran the `file` command to verify the file type.

```sh
traffic.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Linux cooked v2, capture length 65535)
```

This confirmed that the file is a network packet capture. To analyze the packet capture, we will use `Wireshark`.

Upon opening the network capture in `Wireshark`, it can be observed that there was a total of 2,344 packets utilizing various protocols. Utilizing Wireshark's built-in statistics feature, we can understand the `Protocol Hierarchy` and `Endpoints`.

![]({{site.baseurl}}/images/Pasted image 20251220120003.png)

![]({{site.baseurl}}/images/Pasted image 20251220120329.png)

This statistical overview provided insight into:

- Non-routable (local) and routable (remote) IP addresses
- Protocol distribution across the capture

Typically, a large percentage of user traffic is over `TCP`, so we began by examining `TCP streams`. Navigating to the first `TCP` packet, we can right-click and select `Follow > TCP Stream`. This view displays all packets associated with a given stream, with both source and destination.

`TCP Stream [0]` revealed `FTP` traffic. Since `FTP` transmits data unencrypted, the command, response, and data were visible:

![]({{site.baseurl}}/images/Pasted image 20251220120730.png)

Continuing this methodical approach for each stream, we can enumerate traffic between endpoints, looking for anomalies that indicate malicious activity.

## Phase 1

`TCP Stream [19]` immediately stood out as anomalous:

![]({{site.baseurl}}/images/Pasted image 20251220121148.png)

This stream showed communication between local IP `192.168.3.89` and remote IP `203.0.113.108`. While potentially benign, this exchange was the only notable deviation from typical traffic patterns. I applied `Wireshark` filters to track all communications involving these addresses:

```wireshark
ip.addr == 192.168.3.89
ip.addr == 203.0.113.108
```

Interestingly, these addresses appeared nowhere else in the capture, except in `TCP Stream [19]`. The `ip.addr` filter searches IPv4 header fields, so I expanded my search to look for the string value "203.0.113.108" in any packet. The string search returned a hit for packet 2027. This packet was a `DNS` request originating from `192.168.3.146`, a local client, requesting the DNS query for archive.ubuntu.com, which was sent to the local DNS server at `192.168.3.254`. The `DNS Server` responded, stating that the IP address for `archive.ubuntu.com` is `203.0.113.108`. 

![]({{site.baseurl}}/images/Pasted image 20251220122747.png)

To verify that this was a legitimate `Ubuntu` archive IP address, I used tools such as `Shodan` and `IP lookup` services. The results confirmed this was **not** a genuine Ubuntu archive:

![]({{site.baseurl}}/images/Pasted image 20251220123823.png)

While `203.0.113.108` is clearly malicious, the challenge prompt asks for IP addresses **assigned** to the malicious device. Since `203.0.113.108` is a remote address, it's not assigned to the local device. However, the DNS server `192.168.3.254` is local and malicious, making it our first confirmed address.

**First malicious IP identified**: `192.168.3.254`

## Phase 2

Now that there is a foothold for a malicious IP address, I used `192.168.3.254` as a filter in Wireshark to see where it was used in the capture.

```wireshark
ip.addr == 192.168.3.254
```

![]({{site.baseurl}}/images/Pasted image 20251220124336.png)

To track all IP addresses assigned to the malicious device, I pivoted to MAC address filtering. In the protocol breakdown pane, I identified `Linux cooked capture` containing `Source: VMware_77:42:f6 (00:0c:29:77:42:f6)`.
 
**Note**: While MAC addresses can be spoofed or modified, the NSA was being nice this time :)

The filtered traffic revealed additional communication involving `192.168.5.1`.

![]({{site.baseurl}}/images/Pasted image 20251220124859.png)

**Second malicious IP identified**: `192.168.5.1`

## Phase 3

Applying the `192.168.5.1` filter revealed `FTP` traffic. `FTP` uses two channels: `port 21` for commands and `port 20` (in active mode) or an ephemeral port (in passive mode) for data transfer.

The packet capture showed the following FTP command sequence from `192.168.5.1`:

![]({{site.baseurl}}/images/Pasted image 20251220125533.png)

TLDR of the FTP traffic:
- `TYPE I`: Binary transfer mode initiated
- `PASV`: Passive mode enabled, using an ephemeral port for data transfer
- `STOR ftp/router3_backup.config`: File upload attempted
	- Permission denied error when attempting to set the timestamp

Examining the subsequent FTP data stream revealed the contents of `router3_backup.config`:

![]({{site.baseurl}}/images/Pasted image 20251220130154.png)

The key malicious element is the loopback interface configured with the non-standard IP address `127.7.9.3` instead of the typical `127.0.0.1`. This creates a subtle backdoor that appears to be localhost-only but could evade typical scans, potentially allowing the attacker to run covert services or establish persistent access. 

**Third malicious IP identified**: `127.7.9.3`

## Solution

The IP addresses assigned to the malicious device are:

```c
192.168.3.254
192.168.5.1
127.7.9.3
```

Badge:

![]({{site.baseurl}}/images/Pasted image 20251220130411.png)