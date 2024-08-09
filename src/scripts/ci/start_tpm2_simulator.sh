#/bin/bash

#
# Sets up a TPM2 simulator that is running behind a user-space TPM2 resource
# manager. Applications can discover the resource manager via D-Bus and use
# the resource manager's TCTI (aka. tabrmd).
#
# The simulator is populated with persistent keys for testing.
#

set -e

tmp_dir="${1:-/tmp/mytpm2}"
dbus_name="net.randombit.botan.tabrmd"
tcti_name="tabrmd"
tcti_conf="bus_name=${dbus_name},bus_type=session"
tcti="${tcti_name}:${tcti_conf}"
test_pwd="password"
persistent_rsa_key_handle="0x81000008"

if ! systemctl is-active --quiet dbus; then
    echo "DBus is not running. Starting it..."
    sudo systemctl start dbus
fi

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
            --display

echo "Starting TPM2 simulator..."
swtpm socket --tpmstate dir=$tmp_dir               \
             --ctrl type=tcp,port=2322             \
             --server type=tcp,port=2321           \
             --flags not-need-init                 \
             --daemon --tpm2

echo "Starting TPM2 resource manager..."
tpm2-abrmd --tcti=swtpm --session --dbus-name="${dbus_name}" &
echo "Resource manager running as PID: $!"

echo "Waiting a for the dbus name to be available..."
waited=5
while ! dbus-send --session --dest=org.freedesktop.DBus --type=method_call --print-reply \
    /org/freedesktop/DBus org.freedesktop.DBus.ListNames | grep -q "${dbus_name}"; do
    sleep 1
    echo "..."
    waited=$((waited - 1))
    if [ $waited -eq 0 ]; then
        echo "Failed to start the TPM2 resource manager"
        exit 1
    fi
done

echo "Create a key to play with..."
tpm2_createprimary --tcti="$tcti" -C e -g sha256 -G rsa -c $tmp_dir/primary.ctx
# Use default key template of tpm2_create for rsa. This means that the key will NOT be "restricted".
tpm2_create --tcti="$tcti" -C $tmp_dir/primary.ctx -G rsa -u $tmp_dir/rsa.pub -r $tmp_dir/rsa.priv -p $test_pwd
tpm2_load --tcti="$tcti" -C $tmp_dir/primary.ctx -u $tmp_dir/rsa.pub -r $tmp_dir/rsa.priv -c $tmp_dir/rsa.ctx
tpm2_evictcontrol --tcti="$tcti" -C o -c $tmp_dir/rsa.ctx $persistent_rsa_key_handle

echo "Effectively disable dictionary attack lockout..."
tpm2_dictionarylockout --tcti="$tcti" --setup-parameters --max-tries=1000 --recovery-time=1 --lockout-recovery-time=1

# check that we're running on GitHub Actions
if [ -n "$GITHUB_ACTIONS" ]; then
    echo "Setting up GitHub Actions environment..."
    echo "BOTAN_TPM2_TCTI_NAME=$tcti_name"                                 >> $GITHUB_ENV
    echo "BOTAN_TPM2_TCTI_CONF=$tcti_conf"                                 >> $GITHUB_ENV
    echo "BOTAN_TPM2_PERSISTENT_KEY_AUTH_VALUE=$test_pwd"                  >> $GITHUB_ENV
    echo "BOTAN_TPM2_PERSISTENT_RSA_KEY_HANDLE=$persistent_rsa_key_handle" >> $GITHUB_ENV
fi
