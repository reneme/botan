#/bin/bash

set -ex

tmp_dir="/tmp/mytpm2"
dbus_name="net.randombit.botan.tabrmd"
tcti="tabrmd:bus_name=${dbus_name},bus_type=session"
test_pwd="password"

echo "Setting up TPM..."
swtpm_setup --create-config-files overwrite

# "Endorsement Key"  - baked into the TPM (signed by the manufacturer)
# "Platform Key"     - signed serial number of the EK (signed by the OEM; eg. the laptop manufacturer)
# "Storage Root Key" - created by the user (signed by the EK)
rm -fR $tmp_dir && mkdir $tmp_dir
swtpm_setup --tpmstate $tmp_dir    \
            --create-ek-cert       \
            --create-platform-cert \
            --create-spk           \
            --overwrite --tpm2     \
            --ecc --display

echo "Starting TPM2 simulator..."
swtpm socket --tpmstate dir=$tmp_dir               \
             --ctrl type=tcp,port=2322             \
             --server type=tcp,port=2321           \
             --flags not-need-init                 \
             --daemon --tpm2

echo "Starting TPM2 resource manager..."
tpm2-abrmd --tcti=swtpm --session --dbus-name="${dbus_name}" &
echo "Resource manager running as PID: $!"

echo "Create a key to play with..."
tpm2_createprimary --tcti="$tcti" -C e -g sha256 -G rsa -c $tmp_dir/primary.ctx
tpm2_create --tcti="$tcti" -C $tmp_dir/primary.ctx -G rsa -u $tmp_dir/rsa.pub -r $tmp_dir/rsa.priv -p $test_pwd
tpm2_load --tcti="$tcti" -C $tmp_dir/primary.ctx -u $tmp_dir/rsa.pub -r $tmp_dir/rsa.priv -c $tmp_dir/rsa.ctx
tpm2_evictcontrol --tcti="$tcti" -C o -c $tmp_dir/rsa.ctx 0x81000008
