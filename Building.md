# Bulding

You need to build on Linux for NanoS, however you can also build on Windows for testing before NanoS deployment.

## Linux:
```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/ue574_endpoint --port 7777 --experimental-control-replies
```

## For NanoS/ops, you still want the Linux ELF:
```
ops run ./build/ue574_endpoint -p 7777/udp
```

## Windows / Visual Studio:
```
cmake -S . -B build -G "Visual Studio 17 2022"
cmake --build build --config Release -j
.\build\Release\ue574_endpoint.exe --port 7777 --experimental-control-replies
```

## Test client on Windows:
```
.\build\Release\ue574_probe_client.exe 127.0.0.1 7777
```