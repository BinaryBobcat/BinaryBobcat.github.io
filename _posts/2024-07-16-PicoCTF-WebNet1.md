---
layout: post
title:  PicoCTF WebNet1
description: In this write-up for the picoCTF challenge "WebNet1", we decrypt TLS traffic using a provided private key. Follow along as we use Wireshark to extract decrypted HTTP files and uncover the flag through analysis.
date:   2024-05-14 15:01:35 +0300
image:  '/images/WebNet1-1.png'
tags:   [CTF, Forensics, picoCTF]
---

# Write-up
This is a write-up for the picoCTF challenge "WebNet1", classified as a medium forensics challenge. The prompt states: "We found this packet capture and key. Recover the flag."

Upon downloading the challenge files, we receive `capture.pcap` and `picopico.key`. To begin, we inspect the key file to determine if it is a public or private key.

![]({{site.baseurl}}/images/Pasted image 20240716204208.png)

It appears to be a private key. This is crucial because it means we can potentially decrypt encrypted traffic. Next, let's open the PCAP file using Wireshark. The capture contains traffic running over TLS, which will be unreadable due to encryption.

![]({{site.baseurl}}/images/Pasted image 20240716204350.png)

Fortunately, we have a private key file that we can use to decrypt the traffic. In Wireshark, go to Edit > Preferences > Protocols > TLS. Click the "Edit" button under "RSA keys list," then add `picopico.key` and hit OK. This step allows us to decrypt the encrypted packets.

![]({{site.baseurl}}/images/Pasted image 20240716204902.png)

With the encryption key added, we can return to the capture display and view the decrypted packets. Now, we see HTTP packets exchanged between 128.237.140.23 and 172.31.22.220.

![]({{site.baseurl}}/images/Pasted image 20240716205059.png)

The first HTTP packet is a GET request for `/second.html`. In the HTTP header, there's a Pico-Flag `picoCTF{this.is.not.your.flag.anymore}`, which of course I tried but is not the correct flag 😅

![]({{site.baseurl}}/images/Pasted image 20240716205351.png)

The subsequent HTTP streams include more GET requests for files, including an image called `/vulture.jpg`. Instead of following each stream, let's extract all HTTP stream files from the capture.

In Wireshark, go to File > Export Objects > HTTP. We can save all listed files to a directory named `extracted`.

![]({{site.baseurl}}/images/Pasted image 20240716205709.png)

![]({{site.baseurl}}/images/Pasted image 20240716205920.png)

Now, let's open `second.html` since the other files appear to be supporting data.

![]({{site.baseurl}}/images/Pasted image 20240716210022.png)

We see the HTML, CSS, and image populated on the page. Scanning through the HTML and CSS is quick because they are ASCII printable and we can use the `strings` command. Next, we examine `vulture.jpg`.

Next, we examine `vulture.jpg`. With image files, I usually check for steganography first. One of my go-to tools is (Stegsolve)[https://github.com/Giotino/stegsolve]. In this case, I started with a hexdump to view the metadata inside the file and discovered the flag. It's always good to check the metadata first before diving into more complex steganographic analysis.

```shell
hexdump -C vulture.jpg | less
```

![]({{site.baseurl}}/images/Pasted image 20240716210645.png)

**picoCTF{honey.roasted.peanuts}**