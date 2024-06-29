---
layout: post
title:  Flare-on 1 Challenge 1
description: Embark on an adventure with me as I dive into a challenge from the FireEye Flare-On CTF. In this post, we'll go over the first challenge from Flare-on 1. I'll share my methodologies and the tools I use to navigate these intricate digital puzzles, offering insights and practical tips for anyone from beginners to seasoned pros. So, grab a coffee and let's explore the excitement of Flare-On together!
date:   2024-06-29 18:01:35 +0300
image:  '/images/flareon1_prize.png'
tags:   [RE, CTF, Flare-on]
---

# Write-up

To kick things off, I like to gather basic information about the file I'm working with, such as its type and size. The `file` command is a great first step for this.

```shell
file Challenge1.exe

Challenge1.exe: PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows
```

This tells us that we are dealing with a 64-bit .NET Windows binary. If this were malware, I wouldn’t run it right away, but since it's a CTF challenge, let's go ahead and execute the program.

![]({{site.baseurl}}/images/flare-on1-chall1-pic.png)

The application opens up to a GUI featuring a Bob Ross painting and a "Decode" button. When we press the "Decode" button, the image changes and we're presented with a garbled string output.

![]({{site.baseurl}}/images/flare-on1-chall1-pic1.png)

Next, let's explore what happens when we click the "Decode" button. My go-to tool for decompiling .NET programs is dnSpy. Loading the binary in dnSpy, we can locate several functions, with the `btnDecode_Click` function standing out.

![]({{site.baseurl}}/images/flare-on1-chall1-pic2.png)

Inside this function, there are three for loops generating strings. Let's set a breakpoint at the end of these loops and run the program to inspect their values.

![]({{site.baseurl}}/images/flare-on1-chall1-pic3.png)

The string `text1` is being built from `dat_secret` which appears to be the flag, while the other two strings, `text2` and `text3`, seem to further mangle each other until the final result is displayed as an unreadable string.

That was a straightforward challenge! 😂

**Flag:** 3rmahg3rd.b0b.d0ge@flare-on.com