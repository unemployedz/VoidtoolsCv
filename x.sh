#!/bin/bash
set -e
cd "$(dirname "$0")"

sudo apt update
sudo apt install -y g++-mingw-w64-x86-64-posix git python3-pip
pip install pycryptodome

cat > test.cpp <<'EOF'
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        MessageBoxA(nullptr, "payload mapped", "test", MB_OK);
    }
    return TRUE;
}
EOF

x86_64-w64-mingw32-g++ -shared -O2 -o test.dll test.cpp -lgdi32 -luser32 -Wl,--subsystem,windows

if [ ! -d donut ]; then
  git clone https://github.com/TheWover/donut
fi
cd donut
make -f Makefile.mingw
cd ..

./donut/donut -i test.dll -o payload.bin -e 3 -b 2 -a 2

ls -la payload.bin
echo
echo "done. now run: git add payload.bin && git commit -m payload && git push"
