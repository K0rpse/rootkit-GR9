#!/usr/bin/env sh


apk add openrc neovim util-linux build-base nasm bash shadow linux-headers strace vim coreutils
ln -s agetty /etc/init.d/agetty.ttyS0
echo ttyS0 > /etc/securetty
rc-update add agetty.ttyS0 default
rc-update add root default


echo "root:2600" | chpasswd

adduser -D user
echo "user1:user1" | chpasswd

echo "alpine-2600" > /etc/hostname

### Mount pseudo fs
rc-update add devfs boot
rc-update add procfs boot
rc-update add sysfs boot

mkdir -p /home/user1


### Copy directories into the mounted tmpfs
for d in bin etc lib root sbin usr; do tar c "/$d" | tar x -C /my-rootfs; done

### Create some dirs
for dir in dev proc run sys var; do mkdir /my-rootfs/${dir}; done
