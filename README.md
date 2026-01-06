# vRubberDucky

Small shell script that types the contents of a file into a target X11 window using simulated keyboard events.

Its primary purpose is to transfer files from a host system into a virtualized or restricted environment where traditional mechanisms are unavailable or deliberately disabled, such as:

- Clipboard copy/paste disabled
- Drag-and-drop disabled
- Shared folders disabled
- No network connectivity
- Air-gapped or challenge-based virtual machines (CTF, exams, labs)

The script leverages `xdotool` to emulate real user input, making it effective even in environments designed to block automated file transfer.


## Typical Use Cases

- Security labs or exams with hardened virtual machines
- Capture The Flag (CTF) challenges
- Malware analysis sandboxes
- Isolated VMs without clipboard or shared folders
- Remote desktop sessions with restricted features

---

## How It Works

1. The script activates a target X11 window by its window ID.
2. It reads a file line by line on the host.
3. Each line is typed character-by-character into the target window.
4. A manual Return key event is sent after each line to ensure correct input handling.

Explicit key events are used instead of embedded newline characters to guarantee compatibility across applications and toolkits.

## Requirements

- Linux host with X11
- `xdotool` installed
- A focused application in the target environment capable of receiving keyboard input (terminal, editor, browser, etc.)

Install `xdotool` (example for Debian-based systems):

```sh
sudo apt install xdotool
```

## Usage

./script.sh --window-id <id> --file <file> \[options\]

### Mandatory options

`-w, --window-id <id>`
X11 window ID of the target window.

`-f, --file <file>`
File whose contents will be typed into the window.

Optional options

`--delay-character <ms>`
Delay in milliseconds between each typed character.
Default: `1`

`--delay-line <ms>`
Delay in milliseconds between each line (Return key).
Default: `2`

`-h, --help`
Display help and exit.
