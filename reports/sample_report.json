INCIDENT REPORT
---------------
Date/Time     : 2024-01-15 02:30 AM
Severity      : CRITICAL
Type          : Brute Force Attack

Summary:
5 consecutive failed login attempts detected from IP 192.168.1.105
targeting the 'admin' account, followed by a successful login.
This pattern is consistent with a brute force attack.

IOCs:
- Source IP  : 192.168.1.105
- Target User: admin
- Event IDs  : 4625 (x5), 4624 (x1)
- Time       : 02:30 AM (off-hours)

Actions Taken:
1. Blocked source IP at firewall level
2. Locked admin account pending investigation
3. Escalated to L2 analyst
4. Notified IT manager

Recommendations:
- Enable MFA on admin accounts
- Implement account lockout after 3 failed attempts
- Add IP to threat watchlist
