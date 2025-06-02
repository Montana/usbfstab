# usbfstab

![Blue Corporate Medical Logo  (5)](https://github.com/user-attachments/assets/5e24bf36-29ac-48ff-ae4e-a4251731b831)

**usbfstab** is an anti-forensic USB defense tool that continuously monitors connected USB devices and enforces a system kill-switch upon detection of unauthorized hardware changes. Inspiration by `usbkill`.

Here is a properly formatted `README.md` section in **Markdown** that lists the functions from your `usbfstab` project:

---

## Function Reference

### Core Execution

#### `main()`

Initializes startup checks, loads configuration, registers signal handlers, and launches the monitoring loop.

#### `loop(settings)`

Continuously checks for changes in connected USB devices. If the list deviates from the initial state or the whitelist, the kill sequence is triggered.

---

### Device Monitoring

#### `lsusb()`

Returns a list of USB devices on Linux using `lsusb`. Falls back to `lsusb_darwin()` on macOS.

#### `lsusb_darwin()`

Uses `system_profiler` to extract USB device information in macOS and parses it.

#### `DeviceCountSet`

A subclass of `dict` used to store and compare counts of USB device identifiers.

---

### Kill Switch Logic

#### `kill_computer(settings)`

Triggers all configured shutdown behaviors: logs USB state, shreds files/folders, executes kill commands, optionally wipes RAM/swap, and powers off the system.

#### `shred(settings)`

Performs secure deletion of files and folders specified in the configuration. Can also remove the script itself if `melt_usbkill` is `True`.

#### `log(settings, msg)`

Writes a log entry with a timestamp and the current USB state to the log file.

---

### Initialization and Utilities

#### `startup_checks()`

Ensures the script runs as root, verifies required system binaries, and creates the log directory if needed.

#### `program_present(program)`

Returns `True` if a given executable is available in the system’s `PATH`.

#### `load_settings(filename)`

Parses a `.ini` file and returns a `Settings` object containing runtime configuration.

#### `secure_file_operation(filepath, mode)`

A context manager that safely opens a file with error handling.

## Author

Michael Mendy (c) 2025. 

