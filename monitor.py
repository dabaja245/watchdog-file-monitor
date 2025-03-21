import os
import sys
import time
import logging
import hashlib
import argparse
from datetime import datetime
from pwd import getpwuid
from stat import filemode
from smtplib import SMTP

import pandas as pd
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


def compute_hash(file_path, retries=3, delay=1):
    """Compute SHA-256 hash of a file with retry logic."""
    sha256_hash = hashlib.sha256()
    for attempt in range(retries):
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except FileNotFoundError as e:
            logging.warning(f"Attempt {attempt + 1} - File not found: {file_path}. Exception: {e}")
            time.sleep(delay)
    logging.error(f"Failed to compute hash for {file_path} after {retries} attempts")
    return None


def get_file_metadata(event, action_type="created"):
    """Retrieve file metadata and hash."""
    file_hash = compute_hash(event.src_path)
    if file_hash is None:
        return None

    try:
        file_stats = os.stat(event.src_path)
        file_size = file_stats.st_size / 1024  # Convert bytes to KB
        file_owner = getpwuid(file_stats.st_uid).pw_name
        file_permissions = filemode(file_stats.st_mode)
    except Exception as e:
        logging.error(f"Error retrieving metadata for {event.src_path}: {e}")
        return None

    return {
        'file_path': event.src_path,
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'event_type': action_type,
        'file_hash': file_hash,
        'file_size_kb': file_size,
        'owner': file_owner,
        'permissions': file_permissions
    }


def send_notification(email, password, recipient, subject, body, smtp_host="smtp.example.com", smtp_port=587):
    """Send an email notification."""
    try:
        with SMTP(smtp_host, smtp_port) as smtp:
            smtp.starttls()
            smtp.login(email, password)
            message = f"Subject: {subject}\n\n{body}"
            smtp.sendmail(email, recipient, message)
            logging.info("Email notification sent")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")


class FileEventHandler(FileSystemEventHandler):
    def __init__(self, hash_dict, csv_file, email_settings=None):
        super().__init__()
        self.hash_dict = hash_dict
        self.csv_file = csv_file
        # Store absolute path for comparison
        self.csv_file_abs = os.path.abspath(csv_file)
        self.email_settings = email_settings

    def log_event(self, metadata):
        """Log metadata to CSV."""
        if metadata:
            new_df = pd.DataFrame([metadata])
            try:
                with open(self.csv_file, 'a') as f:
                    new_df.to_csv(f, index=False, header=f.tell() == 0)  # Write header only if file is new
            except Exception as e:
                logging.error(f"Error writing to CSV: {e}")

    def on_created(self, event):
        if event.is_directory:
            return
        # Ignore events for the CSV file
        if os.path.abspath(event.src_path) == self.csv_file_abs:
            return
        logging.info(f"File created: {event.src_path}")
        metadata = get_file_metadata(event, "created")
        if metadata:
            self.hash_dict[event.src_path] = metadata['file_hash']
            self.log_event(metadata)

    def on_modified(self, event):
        if event.is_directory:
            return
        # Ignore events for the CSV file
        if os.path.abspath(event.src_path) == self.csv_file_abs:
            return
        logging.info(f"File modified: {event.src_path}")
        current_hash = compute_hash(event.src_path)
        if current_hash and event.src_path in self.hash_dict:
            previous_hash = self.hash_dict[event.src_path]
            if current_hash != previous_hash:
                logging.info(f"Hash changed for modified file: {event.src_path}")
                metadata = get_file_metadata(event, "modified")
                if metadata:
                    self.hash_dict[event.src_path] = current_hash
                    self.log_event(metadata)
                    # Send notification if email settings are provided
                    if self.email_settings:
                        subject = "File Modification Alert"
                        body = f"The file '{event.src_path}' was modified and its hash has changed."
                        send_notification(
                            self.email_settings['email'],
                            self.email_settings['password'],
                            self.email_settings['recipient'],
                            subject,
                            body,
                            smtp_host=self.email_settings.get('smtp_host', 'smtp.example.com'),
                            smtp_port=self.email_settings.get('smtp_port', 587)
                        )
            else:
                logging.info(f"File modified but hash is unchanged: {event.src_path}")
        elif current_hash:
            metadata = get_file_metadata(event, "modified")
            if metadata:
                self.hash_dict[event.src_path] = current_hash
                self.log_event(metadata)

    def on_deleted(self, event):
        if event.is_directory:
            return
        # Ignore events for the CSV file
        if os.path.abspath(event.src_path) == self.csv_file_abs:
            return
        logging.info(f"File deleted: {event.src_path}")
        if event.src_path in self.hash_dict:
            del self.hash_dict[event.src_path]
            # Remove entry from CSV
            self.remove_entry_from_csv(event.src_path)

    def remove_entry_from_csv(self, file_path):
        """Remove a file entry from the CSV."""
        try:
            df = pd.read_csv(self.csv_file)
            df = df[df['file_path'] != file_path]
            df.to_csv(self.csv_file, index=False)
            logging.info(f"Removed {file_path} from CSV.")
        except FileNotFoundError:
            logging.warning("CSV file not found, cannot remove entry.")
        except Exception as e:
            logging.error(f"Error removing entry from CSV: {e}")


def load_existing_hashes(csv_file):
    """Load existing file hashes from a CSV file."""
    hash_dict = {}
    try:
        df = pd.read_csv(csv_file)
        for _, row in df.iterrows():
            hash_dict[row['file_path']] = row['file_hash']
    except FileNotFoundError:
        logging.info("CSV file not found. Starting fresh.")
    return hash_dict


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Monitor a directory for file creation and modification events."
    )
    parser.add_argument("-p", "--path", type=str, default='.', help="Directory to monitor (default: current directory)")
    parser.add_argument("-c", "--csv", type=str, default="file_events.csv", help="CSV file to store file events (default: file_events.csv)")
    parser.add_argument("--email", type=str, help="Email address for notifications")
    parser.add_argument("--password", type=str, help="Email password for notifications")
    parser.add_argument("--recipient", type=str, help="Recipient email for notifications")
    parser.add_argument("--smtp_host", type=str, default="smtp.example.com", help="SMTP server host")
    parser.add_argument("--smtp_port", type=int, default=587, help="SMTP server port")
    args = parser.parse_args()

    # Validate that the monitoring path exists and is a directory
    if not os.path.isdir(args.path):
        logging.error(f"The specified path does not exist or is not a directory: {args.path}")
        sys.exit(1)

    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')

    hash_dict = load_existing_hashes(args.csv)

    email_settings = None
    if args.email and args.password and args.recipient:
        email_settings = {
            "email": args.email,
            "password": args.password,
            "recipient": args.recipient,
            "smtp_host": args.smtp_host,
            "smtp_port": args.smtp_port
        }

    event_handler = FileEventHandler(hash_dict, args.csv, email_settings)
    observer = Observer()
    observer.schedule(event_handler, args.path, recursive=True)

    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Keyboard interrupt received. Stopping observer...")
        observer.stop()
    observer.join()
    logging.info("Observer stopped. Exiting program.")
