import win32evtlog
from datetime import datetime, timedelta
import smtplib

# logging to see the logs
server = 'localhost'
log_type = 'Security'

# opening the logs
handle = win32evtlog.OpenEventLog(server, log_type)

now = datetime.now()
thirty_minutes_ago = now - timedelta(minutes=30)

# here are the IDs that we are looking for
id_searcher = {
    "Failed login": 4625, # failed login attempt (wrong password or other issues)
    "Special logon": 4798 # special logon (elevated privileges or administrative access)
}

all_events = []
list_of_failed_logins = []
list_of_special_failed_logins = []

# setting a counter for them
failed_login_count = 0
special_login_count = 0

# by default win32evtlog is looking for a stack of logs. setting the loop like this will allow us to loop till the end
events = True
while events:
    events = win32evtlog.ReadEventLog(handle,win32evtlog.EVENTLOG_SEQUENTIAL_READ | win32evtlog.EVENTLOG_BACKWARDS_READ, 0)

    for event in events:
        # convert event time to datetime
        # - 1st we obtain it as a string
        event_time = event.TimeGenerated.Format("%Y-%m-%d %H:%M:%S")
        # - 2nd we convert it into a datetime
        event_time = datetime.strptime(event_time, "%Y-%m-%d %H:%M:%S")

        if event_time < thirty_minutes_ago:
            break  # stopping the loop since we exceeded the 30-min window

        all_events.append(f"Time: {event.TimeGenerated}, Event ID: {event.EventID}, Source: {event.SourceName}")
        if event.EventID == list(id_searcher.values())[0]:
            failed_login_count += 1
            list_of_failed_logins.append(event_time)
        elif event.EventID == list(id_searcher.values())[1]:
            special_login_count += 1
            list_of_special_failed_logins.append(event_time)

# moving the events to .txt file
with open("SIEM_logs.txt", "w") as f:
    f.write("\n".join(all_events))

# checking for failed and special logins in the last 30 minutes
# setting the "alerts to a blank list, so we can have dynamic alerts"

alerts = []
if len(list_of_failed_logins) >= 4:
    alerts.append(f"Alert: More than 4 failed logins in the last 30 minutes! ({len(list_of_failed_logins)} times)")
else:
    alerts.append("All good with failed logins.")

if len(list_of_special_failed_logins) >= 4:
    alerts.append(
        f"Alert: More than 4 special failed logins in the last 30 minutes! ({len(list_of_special_failed_logins)} times)")
else:
    alerts.append("All good with special logins.")

# MITRE ATT&CK links
failed_LogIn_Link = "https://attack.mitre.org/techniques/T1110/"
special_Login_Link = "https://attack.mitre.org/techniques/T1078/"

# setting up the email
EMAIL_ADDRESS = "YourEmail@gmail.com"
EMAIL_PASSWORD = "***********"  # use the password that Gmail is going to provide for your app (Python in this case)
TO_EMAIL = "RecepientEmail@gmail.com"


def send_email(alerts):
    """Send captured alerts via email."""
    subject = "SIEM Alert: Suspicious Activity Detected"

    # Construct the body with dynamic content
    body = "\n".join(alerts)
    body += f"\n\nFor remediation, visit the MITRE ATT&CK pages:\n " \
            f"Failed login details: {failed_LogIn_Link}\n " \
            f"Special login details: {special_Login_Link}"

    email_text = f"Subject: {subject}\n\n{body}"

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.sendmail(EMAIL_ADDRESS, TO_EMAIL, email_text)
        print("Alert sent via email successfully!")  # confirmation message when the email is sent
    except Exception as e:
        print(f"Error sending email: {e}")  # this will print an error message if there is one


# sending the email if there are any alerts
if len(alerts) >= 1:
    send_email(alerts)
