---
layout: post
title:  Flare-on 1 Challenge 5
description: In this blog post, I explore the 5get_it challenge from the FireEye Flare-On series, where I used Ghidra to dissect a 32-bit Windows DLL.
date:   2024-07-11 13:32:35 +0300
image:  '/images/flareon1_prize.png'
tags:   [RE, CTF, Flare-on]
---

# Write-up
Upon extracting the archive, we come across `5get_it`, a 32-bit Windows Dynamic Link Library (DLL). We'll start with our usual triage of static analysis, running commands like `strings`. There weren't many notable strings, but a few log file names and control characters stood out.

![]({{site.baseurl}}/images/Pasted image 20240711114152.png)

Next, let's load the program into Ghidra to examine the disassembly and decompilation. The 'main' function of the program sets up parameters and dependencies before calling a function, which I've renamed `main_key_log_func()`, on line 37.

![]({{site.baseurl}}/images/Pasted image 20240711115117.png)

Inside `main_key_log_func()`, there are two functions of interest that I've renamed `key_press()` and `log_key_presses()`.

![]({{site.baseurl}}/images/Pasted image 20240711115255.png)

The `log_key_presses()` function is straightforward, taking the input character and logging it to a file named `svchost.log`.

![]({{site.baseurl}}/images/Pasted image 20240711120736.png)

The `key_press()` function checks which key has been pressed. In some cases, it simply returns the character, but in other cases, it performs checks on global variables.

![]({{site.baseurl}}/images/Pasted image 20240711115657.png)

For example, let's look at the check for `0x44`.

![]({{site.baseurl}}/images/Pasted image 20240711115827.png)

It appears to check if the variables in the data section are set to 0 or 1. Based on this, it performs some logic to change other data section variables.

![]({{site.baseurl}}/images/Pasted image 20240711120003.png)

The function I named `10000_func()` is particularly interesting. At first glance, it seemed like a flag function due to its length. This function contains many of the references we saw in the conditional statements above.

![]({{site.baseurl}}/images/Pasted image 20240711120136.png)

Let's use cross-references to see what causes these variables to change from 0 to 1. Starting with `DAT_10019460`, which changes to 1 in `FUN_100009aa0`, we see that `FUN_100009aa0` requires the key 'L'.

![]({{site.baseurl}}/images/Pasted image 20240711121954.png)

![]({{site.baseurl}}/images/Pasted image 20240711122039.png)

We'll continue this process, renaming the data references to the keys that need to be pressed.

![]({{site.baseurl}}/images/Pasted image 20240711132157.png)

**Flag**: l0gging.ur.5tr0ke5@flare-on.com