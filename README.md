# File Monitor

A Python-based tool that monitors directories for file events (creation, modification, and deletion). This script logs detailed metadata—such as file hashes, sizes, permissions, owners, and timestamps—and supports email notifications for changes. Built using [watchdog](https://pypi.org/project/watchdog/) and [pandas](https://pandas.pydata.org/), this project provides an efficient way to track file changes in real time.

## Features

- **Real-Time Monitoring:** Automatically detect file creation, modification, and deletion.
- **Detailed Logging:** Record file metadata including SHA-256 hash, size (in KB), owner, permissions, and timestamps.
- **CSV Logging:** All events are logged to a specified CSV file.
- **Email Notifications:** Optional email alerts when a file’s hash changes.
- **Configurable:** Easily adjust monitoring directory, CSV log file, and email settings via command-line arguments.

## Prerequisites

- **Python:** Version 3.6 or higher.
- **Dependencies:**  
  Install required packages using the provided `requirements.txt`:
  ```bash
  pip install -r requirements.txt
