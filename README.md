
# SIEM Tool - Security Event Monitoring

This project is a simple Security Information and Event Management (SIEM) tool that monitors Windows Security logs for suspicious activity, particularly focusing on failed login attempts and special logins. The tool retrieves events from the Event Viewer, analyzes them, and generates alerts when specific thresholds are met.

### Features:
- Monitors Windows Security logs for failed login attempts (Event ID 4625) and special logins (Event ID 4798).
- Tracks and counts failed login attempts within the last 30 minutes.
- Sends email alerts when suspicious activity (e.g., more than 4 failed logins in 30 minutes) is detected.
- Provides links to MITRE ATT&CK pages for further remediation actions.

### Use Cases:
- **Security monitoring:** Quickly detect and respond to failed login attempts.
- **Suspicious activity alerts:** Get notified via email when potential brute-force attacks or unauthorized login attempts occur.
- **Automated reporting:** Generate logs for further analysis or integration with other security monitoring systems.

### MITRE ATT&CK Mapping:
- Failed logins are mapped to **T1110** (Brute Force).
- Special logins are mapped to **T1078** (Valid Accounts).
