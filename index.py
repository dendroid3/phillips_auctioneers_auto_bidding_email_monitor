#!/usr/bin/env python3
import imaplib
import email
from email.utils import parseaddr
import argparse
import sys
import time
import re
import requests

# Constants
HARDCODED_SENDER = 'denis.mwangi24@students.dkut.ac.ke'
POLL_INTERVAL = 15
API_ENDPOINT = 'http://localhost:8000/api/auction/new_email'

def extract_email_body(msg):
    print("Extracting email body...")  # Debug
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_dispo = str(part.get('Content-Disposition'))

            if content_type == 'text/plain' and 'attachment' not in content_dispo:
                try:
                    charset = part.get_content_charset() or 'utf-8'
                    body = part.get_payload(decode=True).decode(charset, errors='replace')
                    print(f"Multipart body found (charset: {charset})")  # Debug
                    break
                except Exception as e:
                    print(f"Failed to decode multipart: {e}")  # Debug
    else:
        try:
            charset = msg.get_content_charset() or 'utf-8'
            body = msg.get_payload(decode=True).decode(charset, errors='replace')
            print(f"Plain body found (charset: {charset})")  # Debug
        except Exception as e:
            print(f"Failed to decode plain text: {e}")  # Debug
    return body.strip()

def parse_bid_info(body):
    print("Parsing bid info...")  # Debug
    bid_match = re.search(r'Current bid:\s*KSh\s?([\d,]+)', body)
    current_bid = bid_match.group(1).replace(',', '') if bid_match else None
    print(f"Current bid: {current_bid}")  # Debug

    url_match = re.search(r'https?://[^\s<>")]+', body)
    url = url_match.group(0) if url_match else None
    print(f"URL: {url}")  # Debug

    return current_bid, url

def send_to_api(url, current_bid):
    if not url or not current_bid:
        print("Skipping API call (missing data)")  # Debug
        return

    payload = {
        "url": url,
        "current_bid": current_bid
    }
    print(f"Sending to API: {payload}")  # Debug

    try:
        response = requests.post(API_ENDPOINT, json=payload, timeout=10)
        print(f"API response: {response.status_code}")  # Debug
    except Exception as e:
        print(f"API call failed: {e}")  # Debug

def monitor_emails(email_addr, password):
    seen_ids = set()
    print(f"[+] Starting monitor for: {email_addr}")  # Debug

    try:
        print("[+] Connecting to IMAP...")  # Debug
        mail = imaplib.IMAP4_SSL('imap.gmail.com', 993)
        
        print("[+] Logging in...")  # Debug
        mail.login(email_addr, password)
        print("[+] Login successful!")  # Debug

        mail.select('inbox')
        print("[+] Inbox selected")  # Debug

        while True:
            print(f"[+] Polling... (interval: {POLL_INTERVAL}s)")  # Debug
            mail.noop()  # Keep connection alive
            status, msg_ids = mail.search(None, 'UNSEEN')
            print(f"[+] Search status: {status}, Emails: {msg_ids}")  # Debug

            if status == 'OK' and msg_ids[0]:
                for msg_id in msg_ids[0].split():
                    msg_id = msg_id.decode('utf-8')  # Convert bytes to string
                    print(f"[+] New email ID: {msg_id}")  # Debug

                    if msg_id in seen_ids:
                        print(f"[!] Skipping already seen email: {msg_id}")  # Debug
                        continue
                    seen_ids.add(msg_id)

                    status, msg_data = mail.fetch(msg_id, '(RFC822)')
                    if status != 'OK' or not msg_data:
                        print(f"[!] Failed to fetch email {msg_id}")  # Debug
                        continue

                    msg = None
                    for part in msg_data:
                        if isinstance(part, tuple) and isinstance(part[1], bytes):
                            msg = email.message_from_bytes(part[1])
                            break

                    if not msg:
                        print("[!] No message parsed")  # Debug
                        continue

                    from_header = msg.get('From', '')
                    real_email = parseaddr(from_header)[1].lower()
                    print(f"[+] Email from: {real_email}")  # Debug

                    if HARDCODED_SENDER.lower() != real_email:
                        print(f"[!] Skipping: Not from target sender ({HARDCODED_SENDER})")  # Debug
                        continue

                    body = extract_email_body(msg)
                    current_bid, url = parse_bid_info(body)
                    send_to_api(url, current_bid)

            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        print("\n[!] Stopped by user")
    except Exception as e:
        print(f"[!!!] CRITICAL ERROR: {e}", file=sys.stderr)  # Debug
    finally:
        try:
            mail.close()
            mail.logout()
            print("[+] IMAP connection closed")  # Debug
        except Exception as e:
            print(f"[!] Failed to close connection: {e}")  # Debug

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Monitor Gmail inbox for auction emails')
    parser.add_argument('email', help='Gmail address')
    parser.add_argument('password', help='Gmail password or app password')
    args = parser.parse_args()

    print("[+] Starting script...")  # Debug
    monitor_emails(args.email, args.password)