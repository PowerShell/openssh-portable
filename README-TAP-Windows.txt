
Experimental tunnel management has been added on Windows. It relies on
TAP-Windows V9 driver, avilable here:

 https://build.openvpn.net/downloads/releases/tap-windows-9.23.3-I601-Win10.exe

At the moment (2024/09/23) this patch has been tested only on Windows10-19045
and TAP-Windows driver 9.23.3.601. Most of the tests used client mode
(ssh.exe). Server mode (sshd.exe) has only been tested superficially.

Since TAP driver only supports level-2 tunnel, option "Tunnel=ethernet" must
be provided by "-o" command line option or by configuration file.

A notable difference between Linux TAP and Windows TAP is that on Windows
there is no dynamic TAP device instance creation. This is why we need to
statically create a number of TAP adapter instances by installing TAP driver
for the desired number of times. Each adapter created this way must be
renamed manually, the names must begin with a common prefix ("SSH Tunnel" by
default). SSH will search a free adapter into the set of adapters whose name
begins with the prefix. The number of adapters created in this way is the number
of simultaneous sessions that can be opened. For clients (ssh.exe) one
single instance is usually enough, but for servers (sshd.exe) a largest number
of reserved adapters is required. The name prefix SSH looks for can be
configured by setting the new option "TunnelOptions". At the moment, only
ASCII characters are allowed, although Windows uses WCHAR for adapter names
(property "FriendlyName").

It is advised to specify "-w any" in command line, and let the program
choose a free adapter. Although it is possible to specify a particular tunnel
device number (the "IfIndex" adapter's property), it isn't handy to get it,
since Windows puts al kind of adapters (TAP, ethernet...) togather, and
enumeration is not intuitive. A way to get it is the powershell command
"Get-NetAdapter".

SSH only establishes the L2 tunnel, it is on the user (both on the client and the
server side) to configure the TAP device (IP addresses, gateway, routes..).

