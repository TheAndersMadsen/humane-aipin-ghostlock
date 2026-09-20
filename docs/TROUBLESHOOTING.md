# Troubleshooting

## ADB says unauthorized or offline

This project does not acquire ADB authorization. Confirm authorization through
your existing device setup, reconnect the data path, and wait until
`adb devices` reports `device`. Do not download or share another person's
ADB private key.

## The target is unsupported

Compare the full output from:

```sh
adb -s YOUR_SERIAL shell getprop ro.build.fingerprint
adb -s YOUR_SERIAL shell uname -a
adb -s YOUR_SERIAL shell getprop ro.boot.slot_suffix
```

Do not edit the constants to bypass the mismatch. A successful profile is tied
to exact kernel data layout, code generation, and allocator geometry.

## The pinned NDK is not found

Install revision `28.2.13676358`:

```sh
sdkmanager "ndk;28.2.13676358"
```

If `sdkmanager` is not on `PATH`, use the SDK root configured by either
`ANDROID_SDK_ROOT` or `ANDROID_HOME`:

```sh
"${ANDROID_SDK_ROOT:-$ANDROID_HOME}/cmdline-tools/latest/bin/sdkmanager" "ndk;28.2.13676358"
```

The launcher recognizes both variables when locating the installed NDK.

If it is installed outside the normal Android SDK path:

```sh
./ghostlock build --ndk /path/to/ndk/28.2.13676358
```

Other NDK revisions are rejected to keep release hashes reproducible.

## KASLR anchors are unavailable

The runner needs at least two agreeing symbolized WARN anchors from the current
boot's live kernel log inside a bugreport. If none are present, it stops before
triggering the vulnerability.

Reboot once, wait for the Pin to finish starting, run `check`, and make one
new attempt. Do not reuse a bugreport from another boot and do not supply a
guessed KASLR base.

## Same-PFN reclaim verification fails

The controlled socket-buffer allocation did not prove that it captured the
released order-3 page. The payload stops before the write trigger. Reboot
before another attempt; allocator state from a failed attempt is not a valid
starting point.

## The runner says this boot was already attempted

That is intentional. Reboot and confirm that UID is 2000, the context is
`u:r:shell:s0`, and SELinux is enforcing before retrying.

## ADB disappeared

The Pin may have rebooted, panicked, or hard-hung. Wait briefly for a normal
reconnect. If it remains unavailable, follow the battery-drain recovery steps
in [SAFETY.md](SAFETY.md). Do not keep issuing exploit commands.

## Root verification fails after a success message

Treat the result as uncertain and reboot. Do not manually restart the broker or
rerun only the final write stage. Preserve the private run directory locally
and create a redacted report with `./ghostlock report`.
