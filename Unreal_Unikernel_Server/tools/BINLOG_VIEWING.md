# Viewing `.binlog` files

The endpoint `.binlog` files are **not MSBuild Structured Log files**. They are raw UDP packet captures in a small custom format named `U5BL`.

That means tools like **MSBuild Structured Log Viewer** will not open them.

## Built-in C++ dumper

After building, use:

```powershell
.\build\Release\ue574_binlog_dump.exe .\ue574-real-client.binlog --summary
```

Full hex + ASCII dump:

```powershell
.\build\Release\ue574_binlog_dump.exe .\ue574-real-client.binlog
```

Save to text:

```powershell
.\build\Release\ue574_binlog_dump.exe .\ue574-real-client.binlog > ue574-real-client.dump.txt
```

## Python dumper

No compile needed:

```powershell
python .\tools\dump_u5bl_binlog.py .\ue574-real-client.binlog --summary
python .\tools\dump_u5bl_binlog.py .\ue574-real-client.binlog > ue574-real-client.dump.txt
```

## Record format

Each record is:

```text
magic "U5BL"
uint16 version = 1
uint8 direction: 1 = rx, 2 = tx
uint8 reserved
uint64 unix_seconds
IPv4 address, network byte order
UDP port, network byte order
uint32 payload_length
payload bytes
```
