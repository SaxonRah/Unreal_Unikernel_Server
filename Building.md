# It now builds two binaries:
```
ue574_endpoint
ue574_temp_client
```

# Build:
```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

# Run server:
```
./build/ue574_endpoint --port 7777 --binlog packets.binlog
```

# Run temporary test client:
```
./build/ue574_temp_client 127.0.0.1 7777
```
# Expected result:
```
temporary flow complete
```

# Run with NanoS/ops:
```
ops run ./build/ue574_endpoint -p 7777/udp
```

# The important file is:
```
src/ue57_protocol.cpp
```
That is where the real UE5.7.4 wire compatibility goes. I deliberately separated the temporary harness from the future UE implementation so we can replace the fake UEHS / UECTL packets without rewriting the UDP server, session tracking, logging, NanoS path, or cookie machinery.