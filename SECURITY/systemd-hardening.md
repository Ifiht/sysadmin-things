# SYSTEMD Hardening

https://www.freedesktop.org/software/systemd/man/systemd.exec.html

1. `systemd-analyze security` Show unhardened services.
2. `systemctl edit <INSECURE>.service` Edit an unsafe service.
3. `systemctl daemon-reload` Reload changes.
4. `systemctl restart <INSECURE>.service` Restart the service.
5. `systemctl --type=service` Check for anything broken.
