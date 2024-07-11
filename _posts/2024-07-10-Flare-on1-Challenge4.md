---
layout: post
title:  Flare-on 1 Challenge 4
description: Dive into the depths of APT9001.pdf, a deceptive PDF file with hidden obfuscated JavaScript and encoded payloads. Using powerful tools like Origami and ndisasm, this post guides you through the meticulous process of deobfuscation, extraction, and shellcode analysis. Join me as we unravel the secrets within and uncover the hidden flag!
date:   2024-07-10 20:30:35 +0300
image:  '/images/flareon1_prize.png'
tags:   [RE, CTF, Flare-on]
---

# Write-up
Upon extracting the archive, we are presented with a file named `APT9001.pdf`, identified as a `PDF document, version 1.5`.

Running the `strings` command on the file reveals some obfuscated strings related to possible scripting. One particularly interesting string is `/Fla#74eDe#63o#64#65 /AS#43IIHexD#65cod#65 ]`, which decodes to `/FlateDecode /ASCIIHexDecode`.

![]({{site.baseurl}}/images/Pasted image 20240710161947.png)

To analyze any embedded scripts, we can use a tool called [Origami](https://github.com/gdelugre/origami)

`sudo apt install origami-pdf`

First, let's use `pdfcop`:

> Runs some heuristic checks to detect dangerous contents.
> 
> <cite> Origami - pdfcop </cite>

![]({{site.baseurl}}/images/Pasted image 20240710162702.png)

As shown in the screenshot, a `/Javascript` action was found. Next, let's use the `pdfextract` tool, also part of `Origami`.

> Runs some heuristic checks to detect dangerous contents.
> 
> <cite> Origami - pdfextract </cite>

![]({{site.baseurl}}/images/Pasted image 20240710194902.png)

![]({{site.baseurl}}/images/Pasted image 20240710194922.png)

Great, we have extracted a script file. Let's open it in the best text editor [Sublime](https://www.sublimetext.com/) 😉

![]({{site.baseurl}}/images/Pasted image 20240710195026.png)

It appears to be an obfuscated JavaScript file with excessively long variable names. Let's rename them for clarity.

![]({{site.baseurl}}/images/Pasted image 20240710195409.png)

Much better! In a previous blog post, [Unraveling the Mysteries of Malware in the Wild](https://binarybobcat.github.io/Unraveling-the-Mysteries-of-Malware-in-the-Wild) I encountered a similar malware sample in a PDF. From that experience, I know the `encodedPayload` is likely the key focus, containing the escaped data. We'll use the following JavaScript snippet to write out the unescaped raw binary data to a file:

```js
const fs = require('fs');

// Convert unescaped string to binary
function unicodeToBinary(unicodeString) {
    const binaryArray = [];
    for (let i = 0; i < unicodeString.length; i++) {
        const charCode = unicodeString.charCodeAt(i);
        binaryArray.push(charCode & 0xFF); // Low byte
        binaryArray.push(charCode >> 8);   // High byte
    }
    return new Uint8Array(binaryArray);
}

// Combine the secondaryDataArray into one string
let combinedData = '';
for (let i = 0; i < encodedPayload.length; i++) {
    combinedData += encodedPayload[i];
}

// Convert combined data to binary
const binaryPayload = unicodeToBinary(combinedData);

// Write binary data to file
fs.writeFileSync('encodedPayload.bin', Buffer.from(binaryPayload));

console.log('Binary data written to encodedPayload.bin');
```

After appending this code to the file, we run it to extract the "decoded" payload into `encodedPayload.bin`.

![]({{site.baseurl}}/images/Pasted image 20240710195806.png)

Now that we have the raw bytes of the payload, we need to determine its nature. My initial thought is that it could be shellcode. Let's use `ndisasm` to see if it disassembles into any recognizable opcodes.

```shell
ndisasm -b 32 -p intel encodedPayload.bin
```

The results are lengthy, but it’s clear this contains Intel opcodes and a section using XOR decryption.

![]({{site.baseurl}}/images/Pasted image 20240710200323.png)

To execute this shellcode, we can create a harness program. After several unsuccessful attempts creating my own harness programs related towards memory errors, I found another approach using [BlobRunner](https://github.com/OALabs/BlobRunner).

> BlobRunner is a simple tool to quickly debug shellcode extracted during malware analysis.
> 
> <cite> BlobRunner </cite>

```shell
.\blobrunner.exe encodedPayload.bin
```

![]({{site.baseurl}}/images/Pasted image 20240710200812.png)

With the program running, we can attach to the `blobrunner` process using `x32dbg` or `IDA`.

Next, we'll set a breakpoint at the "XOR decryption" section.

![]({{site.baseurl}}/images/Pasted image 20240710201257.png)

Continuing the program execution reveals a MessageBox.

![]({{site.baseurl}}/images/Pasted image 20240710201527.png)

We observe the data being XOR decrypted twice before being displayed.

![]({{site.baseurl}}/images/Pasted image 20240710201626.png)

Single-stepping through the decryption process shows the data before its final XOR operation.

![]({{site.baseurl}}/images/Pasted image 20240710201336.png)

**Flag**: wa1ch.d3m.spl01ts@flare-on.com
