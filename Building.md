# Building
I compiled and tested it locally. The probe successfully performs: `Initial -> Challenge -> Response -> Ack`

# Build:
```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

# Run server:
```
./build/ue574_endpoint --port 7777 --binlog packets.binlog
```

# Run UE-shaped handshake probe:
```
./build/ue574_probe_client 127.0.0.1 7777
```

# Run with NanoS/ops:
```
ops run ./build/ue574_endpoint -p 7777/udp
```

The important caveat: this should now get us much closer to a real UE5.7.4 client’s first handshake, but the post-Ack control-channel layer is still not implemented.