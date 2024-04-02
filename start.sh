#!/bin/bash
#
qemu-system-x86_64 \
    -kernel ./bzImage \
    -initrd ./initramfs.cpio \
    --enable-kvm \

