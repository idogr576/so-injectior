# SO Injector
This Project implements a simple Shared-Object injector in linux,
using the `ptrace` mechanism.

# Build
All of the following are allowed:
```bash
make
make debug
make clean
```

# Run
Use the example provided.
- In one session execute `./example/remote`, the injector will attach to that process.
- In another session run the compiled injector:
```bash
sudo ./injector $(pgrep remote) $(realpath example/libinjected.so)
```
Keep in mind the `sudo` is necessary for the injector to work.
