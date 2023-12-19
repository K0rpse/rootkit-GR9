#!/usr/bin/env sh


apk add openrc neovim util-linux build-base nasm bash shadow linux-headers strace vim coreutils
ln -s agetty /etc/init.d/agetty.ttyS0
echo ttyS0 > /etc/securetty
rc-update add agetty.ttyS0 default
rc-update add root default
echo "root:root" | chpasswd
adduser -D user
echo "user:user" | chpasswd
echo "alpine-2600" > /etc/hostname
rc-update add devfs boot
rc-update add procfs boot
rc-update add sysfs boot
mkdir -p /home/user
for d in bin etc lib root sbin usr; do tar c "/$d" | tar x -C /my-rootfs; done
for dir in dev proc run sys var; do mkdir /my-rootfs/${dir}; done
