---
layout: post
title:  Flare-on 1 Challenge 3
description: Uncover the complexities of `such_evil`, a challenge from Flare-On 1 that is a 32-bit Windows executable (PE32). Initially appearing normal, it conceals intricate shellcode and decodes strings dyanamically during runtime. Whether you're new to CTF challenges or seasoned, join me in decoding the puzzle.
date:   2024-07-03 18:39:35 +0300
image:  '/images/flareon1_prize.png'
tags:   [RE, CTF, Flare-on]
---

# Write-up
Upon extracting the archive, we come across `such_evil`, identified as a 32-bit Windows executable (`PE32`). Despite lacking a `.exe` extension, it functions as a typical Windows binary. This underscores the importance of looking beyond file extensions and examining the file's magic bytes to accurately identify its format and architecture.

```shell
file such_evil

such_evil: PE32 executable (console) Intel 80386 (stripped to external PDB), for MS Windows
```

Running `strings` reveals standard library calls (`msvcrt.dll`) and typical Windows executable declarations but there is nothing interesting.

```
!This program cannot be run in DOS mode.
.text
`.data
%(0@
%,0@
%00@
%40@
%80@
%<0@
%@0@
msvcrt.dll
_controlfp
__set_app_type
__getmainargs
exit
_XcptFilter
_exit
_except_handler3
```

Using `binwalk`, the entropy analysis shows normal distribution, suggesting no potential for encryption or compression.

```shell
binwalk -E such_evil
```

![]({{site.baseurl}}/images/Pasted image 20240703155339.png)

Lets jump over to [IDA](https://hex-rays.com/). Recall that because this is a Windows binary, `PE`, to be able to run this program we will need to be on a Windows machine.

Examining the start function of the program, we see the typical setup of a main function and then a call to `sub_401000`

![]({{site.baseurl}}/images/Pasted image 20240703163535.png)

The function `sub_401000` has many `mov` instructions and eventually does a load, `lea` into `eax` and then calls it. This is typical of shellcode that is written into the program that is unraveled layer after layer then loaded into memory to be executed. Lets set a breakpoint on `call eax` and step into the shellcode.

![]({{site.baseurl}}/images/Pasted image 20240703163720.png)

Inside the call, we see the first part of the shellcode.

![]({{site.baseurl}}/images/Pasted image 20240703164335.png)

Continuing to step through the execution, we can see that an area of memory is being XOR'd with 66 hex. This is decrypting a string and possible further shellcode. We can set a breakpoint on the `jmp loc_19FD60` and run to it.

![]({{site.baseurl}}/images/Pasted image 20240703164534.png)

We can see the string that was being decoded, `"and so it begins"`.  Continuing to step through we get to the next part of the shellcode.

![]({{site.baseurl}}/images/Pasted image 20240703164647.png)

Once again, lets run to the `jmp loc_19FDD4` and let the program do its decoding. The next strings we see that are decoded is `"get ready to get nop'd so damn hard in the paint"`. If we keep running through we eventually get a decoded string that is the flag.

![]({{site.baseurl}}/images/Pasted image 20240703163321.png)

If you end up going to far and just let the program run, you will get a BrokenByte error.

![]({{site.baseurl}}/images/Pasted image 20240703165039.png)

**Flag**: such.5h311010101@flare-on.com


