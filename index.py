#!/usr/bin/env python3
import imaplib
import email
from email.utils import parseaddr
import argparse
import sys
import time
import re
import requests
import threading
import socket

# Constants
HARDCODED_SENDER = 'denis.mwangi24@students.dkut.ac.ke'
POLL_INTERVAL = 15
API_ENDPOINT = 'http://127.0.0.1:80/api/auction/new_email'
HEARTBEAT_ENDPOINT = 'http://127.0.0.1:80/api/email/heartbeat'
INIT_ENDPOINT = 'http://127.0.0.1:80/api/email/init'
HEARTBEAT_INTERVAL = 60  # 60 seconds = 1 minute

def send_init_response(email_addr, success=True, error_message=None):
    """
    Sends initialization response to the API endpoint.
    """
    status_code = 200 if success else 404
    message = "Email monitoring successfully initiated" if success else (
        error_message or "Email monitoring unsuccessfully initiated due to wrong credentials"
    )
    
    payload = {
        "email": email_addr,
        "status": status_code,
        "message": message,
        "timestamp": int(time.time())
    }
    
    try:
        print(f"[Init] Sending initialization status: {payload}")
        response = requests.post(INIT_ENDPOINT, json=payload, timeout=10)
        print(f"[Init] API response: {response.status_code}")
    except Exception as e:
        print(f"[Init] Failed to send initialization status: {e}")

def send_heartbeat(email_addr):
    """
    Continuously sends heartbeat signals with the email address to the heartbeat endpoint.
    """
    while True:
        try:
            payload = {
                "email": email_addr,
                "timestamp": int(time.time())
            }
            print(f"[Heartbeat] Sending heartbeat: {payload}")
            response = requests.post(HEARTBEAT_ENDPOINT, json=payload, timeout=10)
            print(f"[Heartbeat] Response: {response.status_code}")
        except Exception as e:
            print(f"[Heartbeat] Failed to send: {e}")
        
        time.sleep(HEARTBEAT_INTERVAL)

def extract_email_body(msg):
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_dispo = str(part.get('Content-Disposition'))

            if content_type == 'text/plain' and 'attachment' not in content_dispo:
                try:
                    charset = part.get_content_charset() or 'utf-8'
                    body = part.get_payload(decode=True).decode(charset, errors='replace')
                    break
                except Exception as e:
                    print(f"Failed to decode multipart: {e}")
    else:
        try:
            charset = msg.get_content_charset() or 'utf-8'
            body = msg.get_payload(decode=True).decode(charset, errors='replace')
        except Exception as e:
            print(f"Failed to decode plain text: {e}")
    return body.strip()

def parse_bid_info(body):
    bid_match = re.search(r'Current bid:\s*KSh\s?([\d,]+)', body)
    current_bid = bid_match.group(1).replace(',', '') if bid_match else None

    url_match = re.search(r'https?://[^\s<>")]+', body)
    url = url_match.group(0) if url_match else None

    return current_bid, url

def send_to_api(url, current_bid):
    if not url or not current_bid:
        print("Skipping API call (missing data)")
        return

    payload = {
        "url": url,
        "current_bid": current_bid
    }
    print(f"Sending to API: {payload}")

    try:
        response = requests.post(API_ENDPOINT, json=payload, timeout=10)
        print(f"API response: {response.status_code}")
    except Exception as e:
        print(f"API call failed: {e}")

def monitor_emails(email_addr, password):
    seen_ids = set()
    mail = None  # Initialize mail variable outside try block
    
    try:
        print(f"[+] Starting monitor for: {email_addr}")
        print("[+] Connecting to IMAP...")
        
        try:
            mail = imaplib.IMAP4_SSL('imap.gmail.com', 993)
        except socket.gaierror:
            error_msg = "Failed to resolve IMAP server address"
            print(f"[!!!] DNS Error: {error_msg}")
            send_init_response(email_addr, success=False, error_message=error_msg)
            return
        except Exception as e:
            error_msg = f"Connection error: {str(e)}"
            print(f"[!!!] Connection Error: {error_msg}")
            send_init_response(email_addr, success=False, error_message=error_msg)
            return

        try:
            print("[+] Logging in...")
            mail.login(email_addr, password)
            print("[+] Login successful!")
            send_init_response(email_addr, success=True)
        except imaplib.IMAP4.error as e:
            error_msg = f"Login failed: {str(e)}"
            print(f"[!!!] Login Error: {error_msg}")
            send_init_response(email_addr, success=False, error_message=error_msg)
            return

        # Start heartbeat thread after successful login
        heartbeat_thread = threading.Thread(
            target=send_heartbeat,
            args=(email_addr,),
            daemon=True
        )
        heartbeat_thread.start()
        print("[+] Started heartbeat thread")

        mail.select('inbox')
        print("[+] Inbox selected")

        while True:
            print(f"[+] Polling... (interval: {POLL_INTERVAL}s)")
            try:
                mail.noop()  # Keep connection alive
                status, msg_ids = mail.search(None, 'UNSEEN')
                
                if status == 'OK' and msg_ids[0]:
                    for msg_id in msg_ids[0].split():
                        msg_id = msg_id.decode('utf-8')
                        print(f"[+] New email ID: {msg_id}")

                        if msg_id in seen_ids:
                            continue
                        seen_ids.add(msg_id)

                        status, msg_data = mail.fetch(msg_id, '(RFC822)')
                        if status != 'OK' or not msg_data:
                            continue

                        msg = None
                        for part in msg_data:
                            if isinstance(part, tuple) and isinstance(part[1], bytes):
                                msg = email.message_from_bytes(part[1])
                                break

                        if not msg:
                            continue

                        from_header = msg.get('From', '')
                        real_email = parseaddr(from_header)[1].lower()

                        if HARDCODED_SENDER.lower() != real_email:
                            continue

                        body = extract_email_body(msg)
                        current_bid, url = parse_bid_info(body)
                        send_to_api(url, current_bid)

                time.sleep(POLL_INTERVAL)
            except Exception as e:
                print(f"[!] Polling error: {e}")
                time.sleep(POLL_INTERVAL * 2)  # Longer wait after error
                continue

    except KeyboardInterrupt:
        print("\n[!] Stopped by user")
    except Exception as e:
        print(f"[!!!] CRITICAL ERROR: {e}", file=sys.stderr)
    finally:
        if mail:
            try:
                mail.close()
                mail.logout()
                print("[+] IMAP connection closed")
            except Exception as e:
                print(f"[!] Failed to close connection: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Monitor Gmail inbox for auction emails')
    parser.add_argument('email', help='Gmail address')
    parser.add_argument('password', help='Gmail password or app password')
    args = parser.parse_args()

    monitor_emails(args.email, args.password)