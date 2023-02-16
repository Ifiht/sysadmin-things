# SYSTEMD Hardening

https://www.freedesktop.org/software/systemd/man/systemd.exec.html

1. `systemd-analyze security` Show unhardened services.
2. `systemctl show -pUID,FragmentPath,ControlGroup` Determine if it's a system or user service.
3. `systemctl edit <INSECURE>.service` Edit an unsafe service.
4. `systemctl daemon-reload` Reload changes.
5. `systemctl restart <INSECURE>.service` Restart the service.
6. `systemctl --type=service` Check for anything broken.

## Strictest settings possible
_NOTE: do NOT use as-is, this list must be manually vetted before applying to any service, or you WILL break things!!_

ProtectSystem=
Takes a boolean argument or the special values "full" or "strict". If true, mounts the /usr/ and the boot loader directories (/boot and /efi) read-only for processes invoked by this unit. If set to "full", the /etc/ directory is mounted read-only, too. If set to "strict" the entire file system hierarchy is mounted read-only, except for the API file system subtrees /dev/, /proc/ and /sys/ (protect these directories using PrivateDevices=, ProtectKernelTunables=, ProtectControlGroups=). This setting ensures that any modification of the vendor-supplied operating system (and optionally its configuration, and local mounts) is prohibited for the service. It is recommended to enable this setting for all long-running services, unless they are involved with system updates or need to modify the operating system in other ways. If this option is used, ReadWritePaths= may be used to exclude specific directories from being made read-only. This setting is implied if DynamicUser= is set. This setting cannot ensure protection in all cases. In general it has the same limitations as ReadOnlyPaths=, see below. Defaults to off.

ProtectHome=
Takes a boolean argument or the special values "read-only" or "tmpfs". If true, the directories /home/, /root, and /run/user are made inaccessible and empty for processes invoked by this unit. If set to "read-only", the three directories are made read-only instead. If set to "tmpfs", temporary file systems are mounted on the three directories in read-only mode. The value "tmpfs" is useful to hide home directories not relevant to the processes invoked by the unit, while still allowing necessary directories to be made visible when listed in BindPaths= or BindReadOnlyPaths=.

Setting this to "yes" is mostly equivalent to setting the three directories in InaccessiblePaths=. Similarly, "read-only" is mostly equivalent to ReadOnlyPaths=, and "tmpfs" is mostly equivalent to TemporaryFileSystem= with ":ro".

It is recommended to enable this setting for all long-running services (in particular network-facing ones), to ensure they cannot get access to private user data, unless the services actually require access to the user's private data. This setting is implied if DynamicUser= is set. This setting cannot ensure protection in all cases. In general it has the same limitations as ReadOnlyPaths=, see below.

This option is only available for system services, or for services running in per-user instances of the service manager when PrivateUsers= is enabled.

RuntimeDirectory=, StateDirectory=, CacheDirectory=, LogsDirectory=, ConfigurationDirectory=
These options take a whitespace-separated list of directory names. The specified directory names must be relative, and may not include "..". If set, when the unit is started, one or more directories by the specified names will be created (including their parents) below the locations defined in the following table. Also, the corresponding environment variable will be defined with the full paths of the directories. If multiple directories are set, then in the environment variable the paths are concatenated with colon (":").

In case of RuntimeDirectory= the innermost subdirectories are removed when the unit is stopped. It is possible to preserve the specified directories in this case if RuntimeDirectoryPreserve= is configured to restart or yes (see below). The directories specified with StateDirectory=, CacheDirectory=, LogsDirectory=, ConfigurationDirectory= are not removed when the unit is stopped.

Except in case of ConfigurationDirectory=, the innermost specified directories will be owned by the user and group specified in User= and Group=. If the specified directories already exist and their owning user or group do not match the configured ones, all files and directories below the specified directories as well as the directories themselves will have their file ownership recursively changed to match what is configured. As an optimization, if the specified directories are already owned by the right user and group, files and directories below of them are left as-is, even if they do not match what is requested. The innermost specified directories will have their access mode adjusted to the what is specified in RuntimeDirectoryMode=, StateDirectoryMode=, CacheDirectoryMode=, LogsDirectoryMode= and ConfigurationDirectoryMode=.

These options imply BindPaths= for the specified paths. When combined with RootDirectory= or RootImage= these paths always reside on the host and are mounted from there into the unit's file system namespace.

If DynamicUser= is used, the logic for CacheDirectory=, LogsDirectory= and StateDirectory= is slightly altered: the directories are created below /var/cache/private, /var/log/private and /var/lib/private, respectively, which are host directories made inaccessible to unprivileged users, which ensures that access to these directories cannot be gained through dynamic user ID recycling. Symbolic links are created to hide this difference in behaviour. Both from perspective of the host and from inside the unit, the relevant directories hence always appear directly below /var/cache, /var/log and /var/lib.

Use RuntimeDirectory= to manage one or more runtime directories for the unit and bind their lifetime to the daemon runtime. This is particularly useful for unprivileged daemons that cannot create runtime directories in /run/ due to lack of privileges, and to make sure the runtime directory is cleaned up automatically after use. For runtime directories that require more complex or different configuration or lifetime guarantees, please consider using tmpfiles.d(5).

RuntimeDirectory=, StateDirectory=, CacheDirectory= and LogsDirectory= optionally support a second parameter, separated by ":". The second parameter will be interpreted as a destination path that will be created as a symlink to the directory. The symlinks will be created after any BindPaths= or TemporaryFileSystem= options have been set up, to make ephemeral symlinking possible. The same source can have multiple symlinks, by using the same first parameter, but a different second parameter.

RuntimeDirectoryMode=, StateDirectoryMode=, CacheDirectoryMode=, LogsDirectoryMode=, ConfigurationDirectoryMode=
Specifies the access mode of the directories specified in RuntimeDirectory=, StateDirectory=, CacheDirectory=, LogsDirectory=, or ConfigurationDirectory=, respectively, as an octal number. Defaults to 0755. See "Permissions" in path_resolution(7) for a discussion of the meaning of permission bits.

RuntimeDirectoryPreserve=
Takes a boolean argument or restart. If set to no (the default), the directories specified in RuntimeDirectory= are always removed when the service stops. If set to restart the directories are preserved when the service is both automatically and manually restarted. Here, the automatic restart means the operation specified in Restart=, and manual restart means the one triggered by systemctl restart foo.service. If set to yes, then the directories are not removed when the service is stopped. Note that since the runtime directory /run/ is a mount point of "tmpfs", then for system services the directories specified in RuntimeDirectory= are removed when the system is rebooted.

TimeoutCleanSec=
Configures a timeout on the clean-up operation requested through systemctl clean …, see systemctl(1) for details. Takes the usual time values and defaults to infinity, i.e. by default no timeout is applied. If a timeout is configured the clean operation will be aborted forcibly when the timeout is reached, potentially leaving resources on disk.

ReadWritePaths=, ReadOnlyPaths=, InaccessiblePaths=, ExecPaths=, NoExecPaths=
Sets up a new file system namespace for executed processes. These options may be used to limit access a process has to the file system. Each setting takes a space-separated list of paths relative to the host's root directory (i.e. the system running the service manager). Note that if paths contain symlinks, they are resolved relative to the root directory set with RootDirectory=/RootImage=.

Paths listed in ReadWritePaths= are accessible from within the namespace with the same access modes as from outside of it. Paths listed in ReadOnlyPaths= are accessible for reading only, writing will be refused even if the usual file access controls would permit this. Nest ReadWritePaths= inside of ReadOnlyPaths= in order to provide writable subdirectories within read-only directories. Use ReadWritePaths= in order to allow-list specific paths for write access if ProtectSystem=strict is used.

Paths listed in InaccessiblePaths= will be made inaccessible for processes inside the namespace along with everything below them in the file system hierarchy. This may be more restrictive than desired, because it is not possible to nest ReadWritePaths=, ReadOnlyPaths=, BindPaths=, or BindReadOnlyPaths= inside it. For a more flexible option, see TemporaryFileSystem=.

Content in paths listed in NoExecPaths= are not executable even if the usual file access controls would permit this. Nest ExecPaths= inside of NoExecPaths= in order to provide executable content within non-executable directories.

Non-directory paths may be specified as well. These options may be specified more than once, in which case all paths listed will have limited access from within the namespace. If the empty string is assigned to this option, the specific list is reset, and all prior assignments have no effect.

Paths in ReadWritePaths=, ReadOnlyPaths=, InaccessiblePaths=, ExecPaths= and NoExecPaths= may be prefixed with "-", in which case they will be ignored when they do not exist. If prefixed with "+" the paths are taken relative to the root directory of the unit, as configured with RootDirectory=/RootImage=, instead of relative to the root directory of the host (see above). When combining "-" and "+" on the same path make sure to specify "-" first, and "+" second.

Note that these settings will disconnect propagation of mounts from the unit's processes to the host. This means that this setting may not be used for services which shall be able to install mount points in the main mount namespace. For ReadWritePaths= and ReadOnlyPaths=, propagation in the other direction is not affected, i.e. mounts created on the host generally appear in the unit processes' namespace, and mounts removed on the host also disappear there too. In particular, note that mount propagation from host to unit will result in unmodified mounts to be created in the unit's namespace, i.e. writable mounts appearing on the host will be writable in the unit's namespace too, even when propagated below a path marked with ReadOnlyPaths=! Restricting access with these options hence does not extend to submounts of a directory that are created later on. This means the lock-down offered by that setting is not complete, and does not offer full protection.

Note that the effect of these settings may be undone by privileged processes. In order to set up an effective sandboxed environment for a unit it is thus recommended to combine these settings with either CapabilityBoundingSet=~CAP_SYS_ADMIN or SystemCallFilter=~@mount.

Simple allow-list example using these directives:

[Service]
ReadOnlyPaths=/
ReadWritePaths=/var /run
InaccessiblePaths=-/lost+found
NoExecPaths=/
ExecPaths=/usr/sbin/my_daemon /usr/lib /usr/lib64
These options are only available for system services, or for services running in per-user instances of the service manager when PrivateUsers= is enabled.

TemporaryFileSystem=
Takes a space-separated list of mount points for temporary file systems (tmpfs). If set, a new file system namespace is set up for executed processes, and a temporary file system is mounted on each mount point. This option may be specified more than once, in which case temporary file systems are mounted on all listed mount points. If the empty string is assigned to this option, the list is reset, and all prior assignments have no effect. Each mount point may optionally be suffixed with a colon (":") and mount options such as "size=10%" or "ro". By default, each temporary file system is mounted with "nodev,strictatime,mode=0755". These can be disabled by explicitly specifying the corresponding mount options, e.g., "dev" or "nostrictatime".

This is useful to hide files or directories not relevant to the processes invoked by the unit, while necessary files or directories can be still accessed by combining with BindPaths= or BindReadOnlyPaths=:

Example: if a unit has the following,

TemporaryFileSystem=/var:ro
BindReadOnlyPaths=/var/lib/systemd
then the invoked processes by the unit cannot see any files or directories under /var/ except for /var/lib/systemd or its contents.

This option is only available for system services, or for services running in per-user instances of the service manager when PrivateUsers= is enabled.

PrivateTmp=
Takes a boolean argument. If true, sets up a new file system namespace for the executed processes and mounts private /tmp/ and /var/tmp/ directories inside it that are not shared by processes outside of the namespace. This is useful to secure access to temporary files of the process, but makes sharing between processes via /tmp/ or /var/tmp/ impossible. If true, all temporary files created by a service in these directories will be removed after the service is stopped. Defaults to false. It is possible to run two or more units within the same private /tmp/ and /var/tmp/ namespace by using the JoinsNamespaceOf= directive, see systemd.unit(5) for details. This setting is implied if DynamicUser= is set. For this setting, the same restrictions regarding mount propagation and privileges apply as for ReadOnlyPaths= and related calls, see above. Enabling this setting has the side effect of adding Requires= and After= dependencies on all mount units necessary to access /tmp/ and /var/tmp/. Moreover an implicitly After= ordering on systemd-tmpfiles-setup.service(8) is added.

Note that the implementation of this setting might be impossible (for example if mount namespaces are not available), and the unit should be written in a way that does not solely rely on this setting for security.

This option is only available for system services, or for services running in per-user instances of the service manager when PrivateUsers= is enabled.

PrivateDevices=
Takes a boolean argument. If true, sets up a new /dev/ mount for the executed processes and only adds API pseudo devices such as /dev/null, /dev/zero or /dev/random (as well as the pseudo TTY subsystem) to it, but no physical devices such as /dev/sda, system memory /dev/mem, system ports /dev/port and others. This is useful to turn off physical device access by the executed process. Defaults to false.

Enabling this option will install a system call filter to block low-level I/O system calls that are grouped in the @raw-io set, remove CAP_MKNOD and CAP_SYS_RAWIO from the capability bounding set for the unit, and set DevicePolicy=closed (see systemd.resource-control(5) for details). Note that using this setting will disconnect propagation of mounts from the service to the host (propagation in the opposite direction continues to work). This means that this setting may not be used for services which shall be able to install mount points in the main mount namespace. The new /dev/ will be mounted read-only and 'noexec'. The latter may break old programs which try to set up executable memory by using mmap(2) of /dev/zero instead of using MAP_ANON. For this setting the same restrictions regarding mount propagation and privileges apply as for ReadOnlyPaths= and related calls, see above. If turned on and if running in user mode, or in system mode, but without the CAP_SYS_ADMIN capability (e.g. setting User=), NoNewPrivileges=yes is implied.

Note that the implementation of this setting might be impossible (for example if mount namespaces are not available), and the unit should be written in a way that does not solely rely on this setting for security.

This option is only available for system services, or for services running in per-user instances of the service manager when PrivateUsers= is enabled.

When access to some but not all devices must be possible, the DeviceAllow= setting might be used instead. See systemd.resource-control(5).

PrivateNetwork=
Takes a boolean argument. If true, sets up a new network namespace for the executed processes and configures only the loopback network device "lo" inside it. No other network devices will be available to the executed process. This is useful to turn off network access by the executed process. Defaults to false. It is possible to run two or more units within the same private network namespace by using the JoinsNamespaceOf= directive, see systemd.unit(5) for details. Note that this option will disconnect all socket families from the host, including AF_NETLINK and AF_UNIX. Effectively, for AF_NETLINK this means that device configuration events received from systemd-udevd.service(8) are not delivered to the unit's processes. And for AF_UNIX this has the effect that AF_UNIX sockets in the abstract socket namespace of the host will become unavailable to the unit's processes (however, those located in the file system will continue to be accessible).

Note that the implementation of this setting might be impossible (for example if network namespaces are not available), and the unit should be written in a way that does not solely rely on this setting for security.

When this option is used on a socket unit any sockets bound on behalf of this unit will be bound within a private network namespace. This may be combined with JoinsNamespaceOf= to listen on sockets inside of network namespaces of other services.

This option is only available for system services, or for services running in per-user instances of the service manager when PrivateUsers= is enabled.

NetworkNamespacePath=
Takes an absolute file system path refererring to a Linux network namespace pseudo-file (i.e. a file like /proc/$PID/ns/net or a bind mount or symlink to one). When set the invoked processes are added to the network namespace referenced by that path. The path has to point to a valid namespace file at the moment the processes are forked off. If this option is used PrivateNetwork= has no effect. If this option is used together with JoinsNamespaceOf= then it only has an effect if this unit is started before any of the listed units that have PrivateNetwork= or NetworkNamespacePath= configured, as otherwise the network namespace of those units is reused.

When this option is used on a socket unit any sockets bound on behalf of this unit will be bound within the specified network namespace.

This option is only available for system services, or for services running in per-user instances of the service manager when PrivateUsers= is enabled.

PrivateIPC=
Takes a boolean argument. If true, sets up a new IPC namespace for the executed processes. Each IPC namespace has its own set of System V IPC identifiers and its own POSIX message queue file system. This is useful to avoid name clash of IPC identifiers. Defaults to false. It is possible to run two or more units within the same private IPC namespace by using the JoinsNamespaceOf= directive, see systemd.unit(5) for details.

Note that IPC namespacing does not have an effect on AF_UNIX sockets, which are the most common form of IPC used on Linux. Instead, AF_UNIX sockets in the file system are subject to mount namespacing, and those in the abstract namespace are subject to network namespacing. IPC namespacing only has an effect on SysV IPC (which is mostly legacy) as well as POSIX message queues (for which AF_UNIX/SOCK_SEQPACKET sockets are typically a better replacement). IPC namespacing also has no effect on POSIX shared memory (which is subject to mount namespacing) either. See ipc_namespaces(7) for the details.

Note that the implementation of this setting might be impossible (for example if IPC namespaces are not available), and the unit should be written in a way that does not solely rely on this setting for security.

This option is only available for system services, or for services running in per-user instances of the service manager when PrivateUsers= is enabled.

IPCNamespacePath=
Takes an absolute file system path refererring to a Linux IPC namespace pseudo-file (i.e. a file like /proc/$PID/ns/ipc or a bind mount or symlink to one). When set the invoked processes are added to the network namespace referenced by that path. The path has to point to a valid namespace file at the moment the processes are forked off. If this option is used PrivateIPC= has no effect. If this option is used together with JoinsNamespaceOf= then it only has an effect if this unit is started before any of the listed units that have PrivateIPC= or IPCNamespacePath= configured, as otherwise the network namespace of those units is reused.

This option is only available for system services, or for services running in per-user instances of the service manager when PrivateUsers= is enabled.

PrivateUsers=
Takes a boolean argument. If true, sets up a new user namespace for the executed processes and configures a minimal user and group mapping, that maps the "root" user and group as well as the unit's own user and group to themselves and everything else to the "nobody" user and group. This is useful to securely detach the user and group databases used by the unit from the rest of the system, and thus to create an effective sandbox environment. All files, directories, processes, IPC objects and other resources owned by users/groups not equaling "root" or the unit's own will stay visible from within the unit but appear owned by the "nobody" user and group. If this mode is enabled, all unit processes are run without privileges in the host user namespace (regardless if the unit's own user/group is "root" or not). Specifically this means that the process will have zero process capabilities on the host's user namespace, but full capabilities within the service's user namespace. Settings such as CapabilityBoundingSet= will affect only the latter, and there's no way to acquire additional capabilities in the host's user namespace. Defaults to off.

When this setting is set up by a per-user instance of the service manager, the mapping of the "root" user and group to itself is omitted (unless the user manager is root). Additionally, in the per-user instance manager case, the user namespace will be set up before most other namespaces. This means that combining PrivateUsers=true with other namespaces will enable use of features not normally supported by the per-user instances of the service manager.

This setting is particularly useful in conjunction with RootDirectory=/RootImage=, as the need to synchronize the user and group databases in the root directory and on the host is reduced, as the only users and groups who need to be matched are "root", "nobody" and the unit's own user and group.

Note that the implementation of this setting might be impossible (for example if user namespaces are not available), and the unit should be written in a way that does not solely rely on this setting for security.

ProtectHostname=
Takes a boolean argument. When set, sets up a new UTS namespace for the executed processes. In addition, changing hostname or domainname is prevented. Defaults to off.

Note that the implementation of this setting might be impossible (for example if UTS namespaces are not available), and the unit should be written in a way that does not solely rely on this setting for security.

Note that when this option is enabled for a service hostname changes no longer propagate from the system into the service, it is hence not suitable for services that need to take notice of system hostname changes dynamically.

If this setting is on, but the unit doesn't have the CAP_SYS_ADMIN capability (e.g. services for which User= is set), NoNewPrivileges=yes is implied.

This option is only available for system services, or for services running in per-user instances of the service manager when PrivateUsers= is enabled.

ProtectClock=
Takes a boolean argument. If set, writes to the hardware clock or system clock will be denied. It is recommended to turn this on for most services that do not need modify the clock. Defaults to off. Enabling this option removes CAP_SYS_TIME and CAP_WAKE_ALARM from the capability bounding set for this unit, installs a system call filter to block calls that can set the clock, and DeviceAllow=char-rtc r is implied. This ensures /dev/rtc0, /dev/rtc1, etc. are made read-only to the service. See systemd.resource-control(5) for the details about DeviceAllow=. If this setting is on, but the unit doesn't have the CAP_SYS_ADMIN capability (e.g. services for which User= is set), NoNewPrivileges=yes is implied.

This option is only available for system services, or for services running in per-user instances of the service manager when PrivateUsers= is enabled.

ProtectKernelTunables=
Takes a boolean argument. If true, kernel variables accessible through /proc/sys/, /sys/, /proc/sysrq-trigger, /proc/latency_stats, /proc/acpi, /proc/timer_stats, /proc/fs and /proc/irq will be made read-only to all processes of the unit. Usually, tunable kernel variables should be initialized only at boot-time, for example with the sysctl.d(5) mechanism. Few services need to write to these at runtime; it is hence recommended to turn this on for most services. For this setting the same restrictions regarding mount propagation and privileges apply as for ReadOnlyPaths= and related calls, see above. Defaults to off. If this setting is on, but the unit doesn't have the CAP_SYS_ADMIN capability (e.g. services for which User= is set), NoNewPrivileges=yes is implied. Note that this option does not prevent indirect changes to kernel tunables effected by IPC calls to other processes. However, InaccessiblePaths= may be used to make relevant IPC file system objects inaccessible. If ProtectKernelTunables= is set, MountAPIVFS=yes is implied.

This option is only available for system services, or for services running in per-user instances of the service manager when PrivateUsers= is enabled.

ProtectKernelModules=
Takes a boolean argument. If true, explicit module loading will be denied. This allows module load and unload operations to be turned off on modular kernels. It is recommended to turn this on for most services that do not need special file systems or extra kernel modules to work. Defaults to off. Enabling this option removes CAP_SYS_MODULE from the capability bounding set for the unit, and installs a system call filter to block module system calls, also /usr/lib/modules is made inaccessible. For this setting the same restrictions regarding mount propagation and privileges apply as for ReadOnlyPaths= and related calls, see above. Note that limited automatic module loading due to user configuration or kernel mapping tables might still happen as side effect of requested user operations, both privileged and unprivileged. To disable module auto-load feature please see sysctl.d(5) kernel.modules_disabled mechanism and /proc/sys/kernel/modules_disabled documentation. If this setting is on, but the unit doesn't have the CAP_SYS_ADMIN capability (e.g. services for which User= is set), NoNewPrivileges=yes is implied.

This option is only available for system services, or for services running in per-user instances of the service manager when PrivateUsers= is enabled.

ProtectKernelLogs=
Takes a boolean argument. If true, access to the kernel log ring buffer will be denied. It is recommended to turn this on for most services that do not need to read from or write to the kernel log ring buffer. Enabling this option removes CAP_SYSLOG from the capability bounding set for this unit, and installs a system call filter to block the syslog(2) system call (not to be confused with the libc API syslog(3) for userspace logging). The kernel exposes its log buffer to userspace via /dev/kmsg and /proc/kmsg. If enabled, these are made inaccessible to all the processes in the unit. If this setting is on, but the unit doesn't have the CAP_SYS_ADMIN capability (e.g. services for which User= is set), NoNewPrivileges=yes is implied.

This option is only available for system services, or for services running in per-user instances of the service manager when PrivateUsers= is enabled.

ProtectControlGroups=
Takes a boolean argument. If true, the Linux Control Groups (cgroups(7)) hierarchies accessible through /sys/fs/cgroup/ will be made read-only to all processes of the unit. Except for container managers no services should require write access to the control groups hierarchies; it is hence recommended to turn this on for most services. For this setting the same restrictions regarding mount propagation and privileges apply as for ReadOnlyPaths= and related calls, see above. Defaults to off. If ProtectControlGroups= is set, MountAPIVFS=yes is implied.

This option is only available for system services and is not supported for services running in per-user instances of the service manager.

RestrictAddressFamilies=
Restricts the set of socket address families accessible to the processes of this unit. Takes "none", or a space-separated list of address family names to allow-list, such as AF_UNIX, AF_INET or AF_INET6. When "none" is specified, then all address families will be denied. When prefixed with "~" the listed address families will be applied as deny list, otherwise as allow list. Note that this restricts access to the socket(2) system call only. Sockets passed into the process by other means (for example, by using socket activation with socket units, see systemd.socket(5)) are unaffected. Also, sockets created with socketpair() (which creates connected AF_UNIX sockets only) are unaffected. Note that this option has no effect on 32-bit x86, s390, s390x, mips, mips-le, ppc, ppc-le, ppc64, ppc64-le and is ignored (but works correctly on other ABIs, including x86-64). Note that on systems supporting multiple ABIs (such as x86/x86-64) it is recommended to turn off alternative ABIs for services, so that they cannot be used to circumvent the restrictions of this option. Specifically, it is recommended to combine this option with SystemCallArchitectures=native or similar. If running in user mode, or in system mode, but without the CAP_SYS_ADMIN capability (e.g. setting User=), NoNewPrivileges=yes is implied. By default, no restrictions apply, all address families are accessible to processes. If assigned the empty string, any previous address family restriction changes are undone. This setting does not affect commands prefixed with "+".

Use this option to limit exposure of processes to remote access, in particular via exotic and sensitive network protocols, such as AF_PACKET. Note that in most cases, the local AF_UNIX address family should be included in the configured allow list as it is frequently used for local communication, including for syslog(2) logging.

RestrictFileSystems=
Restricts the set of filesystems processes of this unit can open files on. Takes a space-separated list of filesystem names. Any filesystem listed is made accessible to the unit's processes, access to filesystem types not listed is prohibited (allow-listing). If the first character of the list is "~", the effect is inverted: access to the filesystems listed is prohibited (deny-listing). If the empty string is assigned, access to filesystems is not restricted.

If you specify both types of this option (i.e. allow-listing and deny-listing), the first encountered will take precedence and will dictate the default action (allow access to the filesystem or deny it). Then the next occurrences of this option will add or delete the listed filesystems from the set of the restricted filesystems, depending on its type and the default action.

Example: if a unit has the following,

RestrictFileSystems=ext4 tmpfs
RestrictFileSystems=ext2 ext4
then access to ext4, tmpfs, and ext2 is allowed and access to other filesystems is denied.

Example: if a unit has the following,

RestrictFileSystems=ext4 tmpfs
RestrictFileSystems=~ext4
then only access tmpfs is allowed.

Example: if a unit has the following,

RestrictFileSystems=~ext4 tmpfs
RestrictFileSystems=ext4
then only access to tmpfs is denied.

As the number of possible filesystems is large, predefined sets of filesystems are provided. A set starts with "@" character, followed by name of the set.

Table 3. Currently predefined filesystem sets

Set	Description
@basic-api	Basic filesystem API.
@auxiliary-api	Auxiliary filesystem API.
@common-block	Common block device filesystems.
@historical-block	Historical block device filesystems.
@network	Well-known network filesystems.
@privileged-api	Privileged filesystem API.
@temporary	Temporary filesystems: tmpfs, ramfs.
@known	All known filesystems defined by the kernel. This list is defined statically in systemd based on a kernel version that was available when this systemd version was released. It will become progressively more out-of-date as the kernel is updated.

Use systemd-analyze(1)'s filesystems command to retrieve a list of filesystems defined on the local system.

Note that this setting might not be supported on some systems (for example if the LSM eBPF hook is not enabled in the underlying kernel or if not using the unified control group hierarchy). In that case this setting has no effect.

This option cannot be bypassed by prefixing "+" to the executable path in the service unit, as it applies to the whole control group.

RestrictNamespaces=
Restricts access to Linux namespace functionality for the processes of this unit. For details about Linux namespaces, see namespaces(7). Either takes a boolean argument, or a space-separated list of namespace type identifiers. If false (the default), no restrictions on namespace creation and switching are made. If true, access to any kind of namespacing is prohibited. Otherwise, a space-separated list of namespace type identifiers must be specified, consisting of any combination of: cgroup, ipc, net, mnt, pid, user and uts. Any namespace type listed is made accessible to the unit's processes, access to namespace types not listed is prohibited (allow-listing). By prepending the list with a single tilde character ("~") the effect may be inverted: only the listed namespace types will be made inaccessible, all unlisted ones are permitted (deny-listing). If the empty string is assigned, the default namespace restrictions are applied, which is equivalent to false. This option may appear more than once, in which case the namespace types are merged by OR, or by AND if the lines are prefixed with "~" (see examples below). Internally, this setting limits access to the unshare(2), clone(2) and setns(2) system calls, taking the specified flags parameters into account. Note that — if this option is used — in addition to restricting creation and switching of the specified types of namespaces (or all of them, if true) access to the setns() system call with a zero flags parameter is prohibited. This setting is only supported on x86, x86-64, mips, mips-le, mips64, mips64-le, mips64-n32, mips64-le-n32, ppc64, ppc64-le, s390 and s390x, and enforces no restrictions on other architectures. If running in user mode, or in system mode, but without the CAP_SYS_ADMIN capability (e.g. setting User=), NoNewPrivileges=yes is implied.

Example: if a unit has the following,

RestrictNamespaces=cgroup ipc
RestrictNamespaces=cgroup net
then cgroup, ipc, and net are set. If the second line is prefixed with "~", e.g.,

RestrictNamespaces=cgroup ipc
RestrictNamespaces=~cgroup net
then, only ipc is set.

LockPersonality=
Takes a boolean argument. If set, locks down the personality(2) system call so that the kernel execution domain may not be changed from the default or the personality selected with Personality= directive. This may be useful to improve security, because odd personality emulations may be poorly tested and source of vulnerabilities. If running in user mode, or in system mode, but without the CAP_SYS_ADMIN capability (e.g. setting User=), NoNewPrivileges=yes is implied.

MemoryDenyWriteExecute=
Takes a boolean argument. If set, attempts to create memory mappings that are writable and executable at the same time, or to change existing memory mappings to become executable, or mapping shared memory segments as executable, are prohibited. Specifically, a system call filter is added that rejects mmap(2) system calls with both PROT_EXEC and PROT_WRITE set, mprotect(2) or pkey_mprotect(2) system calls with PROT_EXEC set and shmat(2) system calls with SHM_EXEC set. Note that this option is incompatible with programs and libraries that generate program code dynamically at runtime, including JIT execution engines, executable stacks, and code "trampoline" feature of various C compilers. This option improves service security, as it makes harder for software exploits to change running code dynamically. However, the protection can be circumvented, if the service can write to a filesystem, which is not mounted with noexec (such as /dev/shm), or it can use memfd_create(). This can be prevented by making such file systems inaccessible to the service (e.g. InaccessiblePaths=/dev/shm) and installing further system call filters (SystemCallFilter=~memfd_create). Note that this feature is fully available on x86-64, and partially on x86. Specifically, the shmat() protection is not available on x86. Note that on systems supporting multiple ABIs (such as x86/x86-64) it is recommended to turn off alternative ABIs for services, so that they cannot be used to circumvent the restrictions of this option. Specifically, it is recommended to combine this option with SystemCallArchitectures=native or similar. If running in user mode, or in system mode, but without the CAP_SYS_ADMIN capability (e.g. setting User=), NoNewPrivileges=yes is implied.

RestrictRealtime=
Takes a boolean argument. If set, any attempts to enable realtime scheduling in a process of the unit are refused. This restricts access to realtime task scheduling policies such as SCHED_FIFO, SCHED_RR or SCHED_DEADLINE. See sched(7) for details about these scheduling policies. If running in user mode, or in system mode, but without the CAP_SYS_ADMIN capability (e.g. setting User=), NoNewPrivileges=yes is implied. Realtime scheduling policies may be used to monopolize CPU time for longer periods of time, and may hence be used to lock up or otherwise trigger Denial-of-Service situations on the system. It is hence recommended to restrict access to realtime scheduling to the few programs that actually require them. Defaults to off.

RestrictSUIDSGID=
Takes a boolean argument. If set, any attempts to set the set-user-ID (SUID) or set-group-ID (SGID) bits on files or directories will be denied (for details on these bits see inode(7)). If running in user mode, or in system mode, but without the CAP_SYS_ADMIN capability (e.g. setting User=), NoNewPrivileges=yes is implied. As the SUID/SGID bits are mechanisms to elevate privileges, and allow users to acquire the identity of other users, it is recommended to restrict creation of SUID/SGID files to the few programs that actually require them. Note that this restricts marking of any type of file system object with these bits, including both regular files and directories (where the SGID is a different meaning than for files, see documentation). This option is implied if DynamicUser= is enabled. Defaults to off.

RemoveIPC=
Takes a boolean parameter. If set, all System V and POSIX IPC objects owned by the user and group the processes of this unit are run as are removed when the unit is stopped. This setting only has an effect if at least one of User=, Group= and DynamicUser= are used. It has no effect on IPC objects owned by the root user. Specifically, this removes System V semaphores, as well as System V and POSIX shared memory segments and message queues. If multiple units use the same user or group the IPC objects are removed when the last of these units is stopped. This setting is implied if DynamicUser= is set.

This option is only available for system services and is not supported for services running in per-user instances of the service manager.

PrivateMounts=
Takes a boolean parameter. If set, the processes of this unit will be run in their own private file system (mount) namespace with all mount propagation from the processes towards the host's main file system namespace turned off. This means any file system mount points established or removed by the unit's processes will be private to them and not be visible to the host. However, file system mount points established or removed on the host will be propagated to the unit's processes. See mount_namespaces(7) for details on file system namespaces. Defaults to off.

When turned on, this executes three operations for each invoked process: a new CLONE_NEWNS namespace is created, after which all existing mounts are remounted to MS_SLAVE to disable propagation from the unit's processes to the host (but leaving propagation in the opposite direction in effect). Finally, the mounts are remounted again to the propagation mode configured with MountFlags=, see below.

File system namespaces are set up individually for each process forked off by the service manager. Mounts established in the namespace of the process created by ExecStartPre= will hence be cleaned up automatically as soon as that process exits and will not be available to subsequent processes forked off for ExecStart= (and similar applies to the various other commands configured for units). Similarly, JoinsNamespaceOf= does not permit sharing kernel mount namespaces between units, it only enables sharing of the /tmp/ and /var/tmp/ directories.

Other file system namespace unit settings — PrivateMounts=, PrivateTmp=, PrivateDevices=, ProtectSystem=, ProtectHome=, ReadOnlyPaths=, InaccessiblePaths=, ReadWritePaths=, … — also enable file system namespacing in a fashion equivalent to this option. Hence it is primarily useful to explicitly request this behaviour if none of the other settings are used.

This option is only available for system services, or for services running in per-user instances of the service manager when PrivateUsers= is enabled.

MountFlags=
Takes a mount propagation setting: shared, slave or private, which controls whether file system mount points in the file system namespaces set up for this unit's processes will receive or propagate mounts and unmounts from other file system namespaces. See mount(2) for details on mount propagation, and the three propagation flags in particular.

This setting only controls the final propagation setting in effect on all mount points of the file system namespace created for each process of this unit. Other file system namespacing unit settings (see the discussion in PrivateMounts= above) will implicitly disable mount and unmount propagation from the unit's processes towards the host by changing the propagation setting of all mount points in the unit's file system namespace to slave first. Setting this option to shared does not reestablish propagation in that case.

If not set – but file system namespaces are enabled through another file system namespace unit setting – shared mount propagation is used, but — as mentioned — as slave is applied first, propagation from the unit's processes to the host is still turned off.

It is not recommended to use private mount propagation for units, as this means temporary mounts (such as removable media) of the host will stay mounted and thus indefinitely busy in forked off processes, as unmount propagation events won't be received by the file system namespace of the unit.

Usually, it is best to leave this setting unmodified, and use higher level file system namespacing options instead, in particular PrivateMounts=, see above.

This option is only available for system services, or for services running in per-user instances of the service manager when PrivateUsers= is enabled.
