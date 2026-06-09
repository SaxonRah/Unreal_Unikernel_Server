# Local Build:
```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/ue5relay 7777
```

# Run under NanoS/ops:
```
ops run ./build/ue5relay -p 7777/udp
```

# Note:
The important limitation: this is not wire compatible with UE5 yet. It is the harness we need before adding the real UE5 bitstream format. The temporary protocol is deliberately obvious:

```
client: "UEHS" 0x01
server: "UEHS" 0x81 <cookie>

client: "UEHS" 0x02 <cookie>
server: "UEHS" 0x82

client: "UECTL" 0x01
server: "UECTL" 0x82

client: "UECTL" 0x03
server: "UECTL" 0x84 ...
```