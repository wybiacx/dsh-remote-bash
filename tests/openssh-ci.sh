#!/usr/bin/env bash
# Run only inside the disposable CI container. Never provision a developer host.
set -Eeuo pipefail
umask 077
if [[ ${GITHUB_ACTIONS:-} != true || ${RB_OPENSSH_CI_CONTAINER:-} != 1 || ! -f /.dockerenv || $(id -u) != 0 ]]; then
  echo 'OpenSSH fixture provisioning is restricted to the root disposable CI container.' >&2
  exit 2
fi
for binary in node ssh-keygen useradd userdel chpasswd getent visudo sudo ps pkill pgrep; do
  command -v "$binary" >/dev/null || { echo "Missing integration dependency: $binary" >&2; exit 2; }
done
[[ -x /usr/sbin/sshd ]] || { echo 'Missing /usr/sbin/sshd' >&2; exit 2; }

fixture=$(mktemp -d /tmp/dsh-rb-openssh.XXXXXXXX)
fixture=$(realpath -- "$fixture")
[[ $fixture == /tmp/dsh-rb-openssh.* && $fixture != /tmp ]] || exit 2
suffix=$(node -e 'process.stdout.write(require("node:crypto").randomBytes(6).toString("hex"))')
auth_user="rb_auth_${suffix}"
nopass_user="rb_nopass_${suffix}"
sudoers="/etc/sudoers.d/rb_openssh_${suffix}"
auth_uid=''
nopass_uid=''
sshd_pid=''
sudoers_created=0

cleanup() {
  local result=$?
  trap - EXIT INT TERM
  set +e
  # Only signal the daemon whose recorded executable/config match this fixture.
  if [[ $sshd_pid =~ ^[0-9]+$ && -r /proc/$sshd_pid/cmdline ]]; then
    local command_line executable
    command_line=$(tr '\0' ' ' < "/proc/$sshd_pid/cmdline")
    executable=$(readlink "/proc/$sshd_pid/exe")
    if [[ $executable == /usr/sbin/sshd && $command_line == *"$fixture/sshd_config"* ]]; then
      kill -TERM "$sshd_pid"
    else
      echo 'Refusing to signal sshd: fixture identity no longer matches.' >&2
      result=1
    fi
  fi
  # Match both immutable numeric UID and home before touching either test user.
  local user expected_uid expected_home record current_uid current_home attempt
  for user in "$auth_user" "$nopass_user"; do
    if [[ $user == "$auth_user" ]]; then expected_uid=$auth_uid; else expected_uid=$nopass_uid; fi
    [[ -n $expected_uid ]] || continue
    expected_home="$fixture/home-$user"
    record=$(getent passwd "$user")
    current_uid=$(cut -d: -f3 <<< "$record")
    current_home=$(cut -d: -f6 <<< "$record")
    if [[ $current_uid == "$expected_uid" && $current_home == "$expected_home" && $expected_uid -gt 0 ]]; then
      pkill -TERM -u "$expected_uid" 2>/dev/null || true
      pkill -KILL -u "$expected_uid" 2>/dev/null || true
      for ((attempt=0; attempt<100; attempt++)); do
        pgrep -u "$expected_uid" >/dev/null 2>&1 || break
        sleep 0.05
      done
      # Keep the home under the fixture root; remove that verified tree once below.
      userdel "$user" || result=1
    else
      echo 'Refusing user cleanup: fixture identity no longer matches.' >&2
      result=1
    fi
  done
  if [[ $sudoers_created == 1 ]]; then
    if [[ $(realpath -m -- "$sudoers") == "/etc/sudoers.d/rb_openssh_${suffix}" && ! -L $sudoers ]]; then
      rm -f -- "$sudoers"
    else
      echo 'Refusing sudoers cleanup: path no longer matches.' >&2
      result=1
    fi
  fi
  if [[ $(realpath -- "$fixture") == "$fixture" && $fixture == /tmp/dsh-rb-openssh.* && ! -L $fixture ]]; then
    rm -rf -- "${fixture:?}"
  else
    echo 'Refusing fixture cleanup: path no longer matches.' >&2
    result=1
  fi
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Parent is searchable so the two dedicated users can reach their own 0700 homes.
chmod 0711 "$fixture"
for user in "$auth_user" "$nopass_user"; do
  ! getent passwd "$user" >/dev/null || { echo 'Generated fixture user already exists.' >&2; exit 2; }
  useradd --create-home --home-dir "$fixture/home-$user" --shell /bin/bash --no-user-group "$user"
  if [[ $user == "$auth_user" ]]; then auth_uid=$(id -u "$user"); else nopass_uid=$(id -u "$user"); fi
  chmod 0700 "$fixture/home-$user"
done
password=$(node -e 'process.stdout.write("RB-CI-" + require("node:crypto").randomBytes(24).toString("hex"))')
# Password enters chpasswd through stdin, never argv or logged shell tracing.
printf '%s:%s\n%s:%s\n' "$auth_user" "$password" "$nopass_user" "$password" | chpasswd
ssh-keygen -q -t ed25519 -N '' -f "$fixture/client_key"
ssh-keygen -q -t ed25519 -N '' -f "$fixture/host_key"
for user in "$auth_user" "$nopass_user"; do
  install -d -m 0700 -o "$user" "$fixture/home-$user/.ssh"
  install -m 0600 -o "$user" "$fixture/client_key.pub" "$fixture/home-$user/.ssh/authorized_keys"
done

# Timestamp semantics are explicitly scoped to the temporary account. This makes
# the cached-auth case reproducible across independent SSH exec channels.
cat > "$fixture/sudoers" <<EOF
Defaults:$auth_user timestamp_type=global,timestamp_timeout=5,passwd_tries=1,!requiretty
Defaults:$nopass_user timestamp_type=global,timestamp_timeout=0,passwd_tries=1,!requiretty
$auth_user ALL=(root) PASSWD: /usr/bin/bash
$nopass_user ALL=(root) NOPASSWD: /usr/bin/bash
EOF
visudo -cf "$fixture/sudoers"
[[ ! -e $sudoers && ! -L $sudoers ]] || { echo 'Generated sudoers path already exists.' >&2; exit 2; }
# Flag before install so even an interrupted/failed copy is cleaned up.
sudoers_created=1
install -m 0440 "$fixture/sudoers" "$sudoers"

port=$(node <<'NODE'
const net = require('node:net')
const server = net.createServer()
server.listen(0, '127.0.0.1', () => {
  const port = server.address().port
  server.close(() => process.stdout.write(String(port)))
})
server.on('error', error => { console.error(error.message); process.exitCode = 1 })
NODE
)
[[ $port =~ ^[0-9]+$ && $port -gt 1024 && $port -le 65535 ]] || exit 2
cat > "$fixture/sshd_config" <<EOF
Port $port
AddressFamily inet
ListenAddress 127.0.0.1
HostKey $fixture/host_key
PidFile $fixture/sshd.pid
AuthorizedKeysFile .ssh/authorized_keys
AllowUsers $auth_user $nopass_user
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
UsePAM no
PermitEmptyPasswords no
PermitTTY yes
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
UseDNS no
PrintMotd no
PrintLastLog no
LogLevel VERBOSE
Subsystem sftp internal-sftp
EOF
# PermitTTY stays enabled: the client must explicitly decline PTY. Disabling it
# server-side would hide the regression this suite is meant to detect.
install -d -m 0755 /run/sshd
/usr/sbin/sshd -t -f "$fixture/sshd_config"
/usr/sbin/sshd -D -f "$fixture/sshd_config" -E "$fixture/sshd.log" &
sshd_pid=$!
# Foreground daemon + shell-owned PID avoids a race reading a daemonized pidfile.
RB_OPENSSH_PORT="$port" node <<'NODE'
const net = require('node:net')
const deadline = Date.now() + 5000
function probe() {
  const socket = net.connect({ host: '127.0.0.1', port: Number(process.env.RB_OPENSSH_PORT) })
  socket.setTimeout(250, () => socket.destroy(new Error('probe timeout')))
  socket.once('connect', () => socket.destroy())
  socket.once('error', () => {
    if (Date.now() >= deadline) {
      console.error('Loopback fixture sshd did not become ready')
      process.exitCode = 1
    } else setTimeout(probe, 50)
  })
}
probe()
NODE

export RUN_OPENSSH_TESTS=1
export RB_OPENSSH_PORT="$port"
export RB_OPENSSH_AUTH_USER="$auth_user"
export RB_OPENSSH_NOPASS_USER="$nopass_user"
export RB_OPENSSH_PASSWORD="$password"
export RB_OPENSSH_KEY="$fixture/client_key"
RB_OPENSSH_FINGERPRINT=$(ssh-keygen -lf "$fixture/host_key.pub" -E sha256 | awk '{ print $2 }')
export RB_OPENSSH_FINGERPRINT
# Explicit file selection + enabled mode prevents accidental silent CI skips.
node --test tests/openssh.test.mjs
