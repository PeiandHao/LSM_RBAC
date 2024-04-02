#!/bin/bash
gcc lsm_init.c -static -o ./fs_extract/lsm_init
cd fs_extract
find .| cpio -o --format=newc > ../initramfs.cpio


