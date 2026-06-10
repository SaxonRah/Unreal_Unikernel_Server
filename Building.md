# Bulding

You need to build on Linux for NanoS, however you can also build on Windows for testing before NanoS deployment.

# Linux:
```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/ue574_endpoint --port 7777 --experimental-control-replies
```

## For NanoS/ops, you still want the Linux ELF:
```
ops run ./build/ue574_endpoint -p 7777/udp
```

# Windows / Visual Studio:

Add this to Editor Preferences -> Level Editor -> Play -> Additional Launch Options
```
127.0.0.1:7777 -log -abslog="G:\UE5\Unreal_UniKernal_Server\Unreal_Unikernel_Server\ue_client_net_verbose.log" -LogCmds="LogNet VeryVerbose,LogNetTraffic VeryVerbose,LogNetPackageMap VeryVerbose,LogRep Verbose,LogNetPartialBunch VeryVerbose"
```
Make sure to replace the path with your local path.


### Build with:
```
cmake -S . -B build -G "Visual Studio 17 2022"
cmake --build build --config Release -j
```

### Run server with:
This is the current in progress testing command
```
.\build\Release\ue574_endpoint.exe --port 7777 --binlog ue574-real-client-v48_string_ch1.binlog --experimental-control-replies --level-name /Game/NanoS_Testing --game-name /Game/NanoS_GMBP.NanoS_GMBP_C --player-controller-class /Game/NanoS_PlayerController.NanoS_PlayerController_C --post-welcome-ack-every 8 --post-join-empty-actor-probe --post-join-actor-channel 1 --post-join-actor-name-mode string --post-join-actor-payload-mode serialize-newactor-pc-cdo
```

Then run a standalone from editor play button. The Level blueprint will run `open 127.0.0.1:7777` after loading in and after one second.

You will get a verbose log from the standalone game in the path you provided in the addition launch options.

You will also get a .binlog file in project dir, you can make this readable by
```
python .\tools\dump_u5bl_binlog.py .\ue574-real-client-v48_string_ch1.binlog > ue574-real-client.dump.txt
```
or
```
.\build\Release\ue574_binlog_dump.exe .\ue574-real-client-v48_string_ch1.binlog --summary
```

## Test client on Windows:
```
.\build\Release\ue574_probe_client.exe 127.0.0.1 7777
```
