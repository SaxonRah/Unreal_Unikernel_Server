# Run with experimental replies:
```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/ue574_endpoint --port 7777 --binlog ue574-real-client.binlog --experimental-control-replies
```

# Then from UE5.7.4:
```
open 127.0.0.1:7777
```