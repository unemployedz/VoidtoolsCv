#!/bin/bash
set -e
cd "$(dirname "$0")"
ROOT="$(pwd)"

echo "== toolchain =="
sudo apt update
sudo apt install -y g++-mingw-w64-x86-64-posix git python3-pip wine64
pip install --quiet pycryptodome

echo "== test dll =="
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
ls -la test.dll

echo "== donut =="
cd "$ROOT"
rm -rf donut
git clone https://github.com/TheWover/donut
cd "$ROOT/donut"
make -f Makefile.mingw

echo "== find donut binary =="
DONUT=""
for cand in \
    "$ROOT/donut/donut" \
    "$ROOT/donut/donut.exe" \
    "$ROOT/donut/bin/donut" \
    "$ROOT/donut/bin/donut.exe"
do
    if [ -f "$cand" ]; then
        DONUT="$cand"
        break
    fi
done

if [ -z "$DONUT" ]; then
    echo "searching for donut binary..."
    DONUT="$(find "$ROOT/donut" -maxdepth 4 -type f \( -name 'donut' -o -name 'donut.exe' \) | head -n1)"
fi

if [ -z "$DONUT" ]; then
    echo "FAIL: donut binary not found"
    ls -la "$ROOT/donut"
    exit 1
fi

echo "using donut: $DONUT"

echo "== convert =="
cd "$ROOT"
if [[ "$DONUT" == *.exe ]]; then
    WINEDEBUG=-all wine64 "$DONUT" -i test.dll -o payload.bin -e 3 -b 2 -a 2
else
    chmod +x "$DONUT" || true
    "$DONUT" -i test.dll -o payload.bin -e 3 -b 2 -a 2
fi

ls -la payload.bin
echo
echo "== done =="
echo "now run:"
echo "  git add payload.bin"
echo "  git commit -m payload"
echo "  git push"
