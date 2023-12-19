#!/bin/sh

if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root."
    exit 1
fi

ROOT_PROJECT_DIR=$(pwd)
LINUX_DIR='./linux-5.15.130/'
ROOTKIT_DIR='./src/'
TMP_DIR='/tmp/my-rootfs'

## Trapping & hiding Ctrl+C
stty -echoctl
trap 'cleanup' SIGINT

# Compiler le rootkit
echo "####################################################"
echo "             ROOTKIT COMPILATION                    "
echo "####################################################"

cd "$ROOTKIT_DIR"
make
cd "$ROOT_PROJECT_DIR"
echo "[+] COMPILATION ROOTKIT DONE"

echo "####################################################"
echo "             LFS CREATION                           "
echo "####################################################"

echo "---------------------------------------------------"
read -p "Do you want to compile the linunx kernel? (y/N) : " answer
if [ "$answer" = "y" ]; then
        cd "$LINUX_DIR"
        sed -i 's/CONFIG_MODULE_SIG=y/CONFIG_MODULE_SIG=n/' .config
        sed -i 's/CONFIG_MODULE_SIG_ALL=y/CONFIG_MODULE_SIG_ALL=n/' .config
        sed -i 's/CONFIG_MODULE_SIG_FORCE=y/CONFIG_MODULE_SIG_FORCE=n/' .config
        make mrproper
        make defconfig
        make -j 10
fi


#image boot
truncate -s 450M disk.img
/sbin/parted -s ./disk.img mktable msdos 
/sbin/parted -s ./disk.img mkpart primary ext4 1 "100%"
/sbin/parted -s ./disk.img set 1 boot on 

#Mount img
losetup -Pf disk.img 
mkfs.ext4 /dev/loop0p1
mkdir -p $TMP_DIR
mount /dev/loop0p1 $TMP_DIR                                                                                                                                                                                                                                                                                                                                                                   


cp alpine_config.sh $TMP_DIR                                                                                    


echo "[+] LANCEMENT DU DOCKER"

sudo docker run --rm -v /tmp/my-rootfs:/my-rootfs alpine /my-rootfs/alpine_config.sh

rm -rf $TMP_DIR/alpine_config.sh


echo "Welcome to your alpine linux" > /tmp/my-rootfs/etc/issue


## Ajouter internet à la VM
echo "[Setup Alpine] - Add network interface in $TMP_DIR/etc/network/interfaces"
echo 'auto eth0' >> $TMP_DIR/etc/network/interfaces
echo 'iface eth0 inet dhcp' >> $TMP_DIR/etc/network/interfaces


mkdir -p $TMP_DIR/boot/grub
sudo cp $LINUX_DIR/arch/x86/boot/bzImage /tmp/my-rootfs/boot/vmlinuz

config_grub="serial
terminal_output serial
set root=(hd0,1)
menuentry "Linux2600" { linux /boot/vmlinuz root=/dev/sda1 rw console=ttyS0 }"

echo "$config_grub" > /tmp/my-rootfs/boot/grub/grub.cfg

grub-install --directory=/usr/lib/grub/i386-pc --boot-directory=/tmp/my-rootfs/boot /dev/loop0

cp $ROOTKIT_DIR/vuln.ko $TMP_DIR
umount $TMP_DIR

rm -rf $TMP_DIR

losetup -d /dev/loop0

echo "####################################################"
echo "                   LFS READY                        "
echo "####################################################"


## If typing "n" or "N" then exit, else run the LFS
echo "---------------------------------------------------"
read -p "Want to launch the LFS ? (Y/n) : " continue

if [ "$continue" = "n" ] || [ "$continue" = "N" ]; then
    exit 0
fi


qemu-system-x86_64 -hda disk.img -nographic