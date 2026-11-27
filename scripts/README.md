# USB debug scripts

Python helpers that talk to a running nkey board over USB CCID (PC/SC). They
need no third-party packages: Windows uses `winscard.dll`, Linux uses
`libpcsclite.so.1`.

Run them from the firmware repository root (or pass an absolute path). Plug in
the board first so the host can see the smart-card reader interface.

## Credential management

| Script | Role |
| --- | --- |
| `mgr.list.py` | List index rows, or `ssh` / `passwd` / `fido` crypt stores |
| `mgr.add.ssh.py` | Add one resident OpenSSH ed25519-sk credential |
| `mgr.add.passwd.py` | Add one password slot |
| `mgr.del.py` | Delete one SSH credential or password slot by id |

Examples:

```sh
python scripts/mgr.list.py
python scripts/mgr.list.py ssh
python scripts/mgr.add.ssh.py root@192.168.1.1 mybox
python scripts/mgr.add.passwd.py 'secret' github work
python scripts/mgr.del.py 1122334455667788
```

Privileged add/delete waits for the physical button (blue LED). Plain list
commands do not.

## Board configuration (PHY)

`conf.py` reads and writes the rescue PHY record (`EF_PHY`): LED GPIO,
brightness, color order, USB VID/PID, and related options.

```sh
python scripts/conf.py show
python scripts/conf.py set --led-gpio 16 --brightness 128 --led-order grb
python scripts/conf.py set --vidpid 2E8A:10FE --reboot
python scripts/conf.py clear-vidpid --reboot
```

A PHY write replaces the whole record, so `set` always reads first, merges the
requested tags, then writes. Press the button when prompted.

## Self-tests

Offline checks that do not need a board:

```sh
python scripts/mgr.list.py --self-test
python scripts/mgr.add.ssh.py --self-test
python scripts/mgr.add.passwd.py --self-test
python scripts/mgr.del.py --self-test
python scripts/conf.py --self-test
```
