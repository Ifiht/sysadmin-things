# SYSTEMD Hardening

https://www.freedesktop.org/software/systemd/man/systemd.exec.html

1. `systemd-analyze security` Show unhardened services.
2. `systemctl show -pUID,FragmentPath,ControlGroup` Determine if it's a system or user service.
3. `systemctl edit <INSECURE>.service` Edit an unsafe service.
4. `systemctl daemon-reload` Reload changes.
5. `systemctl restart <INSECURE>.service` Restart the service.
6. `systemctl --type=service` Check for anything broken.
