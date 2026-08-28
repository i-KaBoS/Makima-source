# Makima Source

This repo has the complete source of makima internal cheat, most of the decompiling was done by AI so expect mistakes and bad decompile throughout the code.

website: makima.rip

server ip: 172.67.167.195

they use BTCPay Server for payments at pay.makima.rip running version 2.3.x which might be vulnerable to some CVEs.

The app is not safe at all, the owners can swap the DLL on their website anytime and the loader will just download and run it on your machine, meaning they can push malicious code to customers without them knowing.

The app also takes screenshots of your entire screen and sends them to their servers via https://makima.rip/api/v3/loader/sync which is a clear privacy violation. If their detection finds a debugger or even a harmless program they have blocked, it will ban you and send a screenshot immediately through the same endpoint.

All of this is visible in the source code for anyone to verify, and there might be other risks that havent been fully uncovered yet.

https://discord.gg/y5nhG4RnCB
