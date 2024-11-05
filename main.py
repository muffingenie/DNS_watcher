import dns.resolver
import time
import json
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


DOMAIN = "example.com"  # Change Me
RECORD_TYPES = ["A", "MX", "NS", "TXT", "CNAME"]
INTERVAL = 300  #update time


SMTP_SERVER = "your_smtp_server"
SMTP_PORT = 587
EMAIL_ADDRESS = "sender_email_addr"
EMAIL_PASSWORD = "sender_email_password"
EMAIL_TO = "dest_email_address"

def send_email_alert(changes):
    subject = f"Alert: DNS modifications detected for {DOMAIN}"
    body = "The following DNS modifications were detected:\n\n"
    
    for record_type, change in changes.items():
        body += f"Record type: {record_type}\n"
        body += f"Old: {change['old']}\n"
        body += f"New: {change['new']}\n\n"
    
    message = MIMEMultipart()
    message["From"] = EMAIL_ADDRESS
    message["To"] = EMAIL_TO
    message["Subject"] = subject
    message.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.send_message(message)
        print("Email alert sent.")
    except Exception as e:
        print(f"Error sending email: {e}")

def get_dns_records(domain, record_type):
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return sorted([str(rdata) for rdata in answers])
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        print(f"Cannot find {domain}.")
        return None
    except Exception as e:
        print(f"Error retrieving DNS records: {e}")
        return None

def check_for_changes(domain, record_types, last_records):
    changes = {}
    for record_type in record_types:
        current_records = get_dns_records(domain, record_type)
        if current_records is None:
            continue
        if record_type not in last_records or last_records[record_type] != current_records:
            changes[record_type] = {"old": last_records.get(record_type, []), "new": current_records}
            last_records[record_type] = current_records
    return changes

def save_records(records, filename="dns_records.json"):
    try:
        with open(filename, "w") as f:
            json.dump(records, f, indent=4)
    except Exception as e:
        print(f"Error saving records: {e}")

def load_records(filename="dns_records.json"):
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        print("Error decoding JSON. Starting with an empty record.")
        return {}

def main():
    last_records = load_records()
    while True:
        changes = check_for_changes(DOMAIN, RECORD_TYPES, last_records)
        if changes:
            print("Change detected:")
            for record_type, change in changes.items():
                print(f"\nRecord type: {record_type}")
                print("Old:", change["old"])
                print("New:", change["new"])
            
            send_email_alert(changes)
            save_records(last_records)
        else:
            print("No change detected.")

        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()
