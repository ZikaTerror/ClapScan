@echo off
echo Installing GNU target for static compilation...
rustup target add x86_64-pc-windows-gnu

echo Building ClapScan (static binary)...
cargo build --release --target x86_64-pc-windows-gnu

echo.
echo Installing to PATH...
.\target\x86_64-pc-windows-gnu\release\clapscan.exe --install

echo.
echo Done! You can now use: clapscan --help