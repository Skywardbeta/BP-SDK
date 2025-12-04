@echo off
setlocal

REM Check if gcc is in PATH, if not try common locations
where gcc >nul 2>&1
if %errorlevel% neq 0 (
    if exist "C:\mingw64\bin\gcc.exe" set PATH=%PATH%;C:\mingw64\bin
    if exist "C:\msys64\mingw64\bin\gcc.exe" set PATH=%PATH%;C:\msys64\mingw64\bin
)

if not exist build mkdir build

echo === BP-SDK Build ===

echo [1/9] Compiling SDK Core...
gcc -I./include -Wall -Wextra -std=c11 -c src/bp_sdk.c -o build/bp_sdk.o
if %errorlevel% neq 0 goto :error

echo [2/9] Compiling Utilities...
gcc -I./include -Wall -Wextra -std=c11 -c src/bp_utils.c -o build/bp_utils.o
if %errorlevel% neq 0 goto :error

echo [3/9] Compiling CBOR...
gcc -I./include -Wall -Wextra -std=c11 -c src/bp_cbor.c -o build/bp_cbor.o
if %errorlevel% neq 0 goto :error

echo [4/9] Compiling Bundle...
gcc -I./include -Wall -Wextra -std=c11 -c src/bp_bundle.c -o build/bp_bundle.o
if %errorlevel% neq 0 goto :error

echo [5/9] Compiling TCPCL...
gcc -I./include -Wall -Wextra -std=c11 -c src/bp_tcpcl.c -o build/bp_tcpcl.o
if %errorlevel% neq 0 goto :error

echo [6/9] Compiling BPSec...
gcc -I./include -Wall -Wextra -std=c11 -c src/bp_bpsec.c -o build/bp_bpsec.o
if %errorlevel% neq 0 goto :error

echo [7/9] Compiling Fragmentation...
gcc -I./include -Wall -Wextra -std=c11 -c src/bp_fragment.c -o build/bp_fragment.o
if %errorlevel% neq 0 goto :error

echo [8/9] Compiling Storage...
gcc -I./include -Wall -Wextra -std=c11 -c src/bp_storage.c -o build/bp_storage.o
if %errorlevel% neq 0 goto :error

echo [9/9] Compiling Admin...
gcc -I./include -Wall -Wextra -std=c11 -c src/bp_admin.c -o build/bp_admin.o
if %errorlevel% neq 0 goto :error

echo Compiling POSIX Backend...
gcc -I./include -Wall -Wextra -std=c11 -c src/backend/bp_backend_posix.c -o build/bp_backend_posix.o
if %errorlevel% neq 0 goto :error

echo Compiling BP-Socket Backend...
gcc -I./include -Wall -Wextra -std=c11 -c src/backend/bp_backend_bpsocket.c -o build/bp_backend_bpsocket.o
if %errorlevel% neq 0 goto :error

echo Creating Library...
ar rcs build/libbp_sdk.a build/bp_sdk.o build/bp_utils.o build/bp_cbor.o build/bp_bundle.o build/bp_tcpcl.o build/bp_bpsec.o build/bp_fragment.o build/bp_storage.o build/bp_admin.o build/bp_backend_posix.o build/bp_backend_bpsocket.o
if %errorlevel% neq 0 goto :error

echo.
echo === Build successful: build/libbp_sdk.a ===
exit /b 0

:error
echo.
echo === Build failed! ===
echo Make sure gcc is installed and in your PATH.
exit /b 1
