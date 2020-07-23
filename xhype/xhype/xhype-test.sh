# cargo test -- --test-threads=1
# export KN_PATH=/Users/changyuanl/Developer/xhyve/test/vmlinuz
# export KN_PATH=/Users/changyuanl/Downloads/bzImage
# export KN_PATH=/Users/changyuanl/Developer/vmlinuz
# export KN_PATH="/Volumes/GoogleDrive/My Drive/cpu-linux/bzImage"
# export KN_PATH="/Volumes/GoogleDrive/My Drive/flash-linux/bzImage"
# export KN_PATH="/Users/changyuanl/test/tinycore5.4.3/vmlinuz64"
# export RD_PATH="/Volumes/GoogleDrive/My Drive/rdfs/initramfs.cpio.gz"

#tiny core 5.4.3
# export KN_PATH=/Users/changyuanl/test/tinycore5.4.3/vmlinuz64
# export RD_PATH=/Users/changyuanl/test/tinycore5.4.3/corepure64.gz

# original
# export KN_PATH="/Volumes/GoogleDrive/My Drive/kernel.s/flashkernel"
# export KN_PATH="/Volumes/GoogleDrive/My Drive/kernel.s/cpukernel"

# my 5.6.19, minimal
# export KN_PATH="/Volumes/GoogleDrive/My Drive/kernel.s/5.6.19/bzImage"

# my cpukernel
# export KN_PATH="/Volumes/GoogleDrive/My Drive/kernel.s/mycpukernel5.5.1/bzImage"

# my busyboxkernel
# export KN_PATH="/Volumes/GoogleDrive/My Drive/kernel.s/mybusyboxkernel5.5.1/bzImage"


# my myflashkernel
# export KN_PATH="/Volumes/GoogleDrive/My Drive/kernel.s/myflashkernel5.5.1/bzImage"

# mycpukern4c3
# export KN_PATH="/Volumes/GoogleDrive/My Drive/kernel.s/mycpukernel5rc3/bzImage"

# cpu kernel virtio
# export KN_PATH="/Volumes/GoogleDrive/My Drive/kernel.s/cpukernel-virtio/bzImage"

# flash kernel
export KN_PATH="/Volumes/GoogleDrive/My Drive/kernel.s/flashkenel-virtio/bzImage"

# flash kernel minimal change
# export KN_PATH="/Volumes/GoogleDrive/My Drive/flashkernel_minimal_change/bzImage"

export CMD_Line="loglevel=7 earlyprintk=serial console=ttyS0  tsc=unstable "
export RUST_LOG=none
# export RUST_BACKTRACE=1
cargo run --release