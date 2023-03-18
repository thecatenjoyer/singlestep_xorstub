# singlestep xorstub

## What is it?

A stub for decrypting shellcode and re-encrypting on the fly, useful for evading dynamic signature detection.

## How?

By using the CPU trapflag utility, we can singlestep through code and perform operations in-between execution of instructions. We exploit that function to decrypt and encrypt code on the fly.