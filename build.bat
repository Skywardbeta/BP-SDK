@echo off
setlocal enabledelayedexpansion

REM Windows convenience build script. The Makefile is the source of truth.
REM PATH expansion is intentionally kept outside parenthesised IF blocks so
REM that special characters inside %PATH% (NVIDIA tooling, "Program Files",
REM unbalanced parens) cannot break command parsing.

call :ensure_gcc
if errorlevel 1 goto :error

if not exist build mkdir build

set "CFLAGS=-I./include -Wall -Wextra -std=c11 -O2"
set "LDFLAGS=-lws2_32 -lbcrypt"

set "LIB_SRCS=bp_sdk bp_utils bp_cbor bp_bundle bp_tcpcl bp_admin bp_storage bp_fragment bp_stream bp_bpsec bp_bpsec_keys bp_bpsec_policy bp_crypto_backend bp_key_provider bp_session"
set "BACKEND_SRCS=bp_backend_posix bp_backend_bpsocket"

echo === Compiling library ===
for %%s in (%LIB_SRCS%) do call :compile "src/%%s.c" "build/%%s.o" || goto :error
for %%s in (%BACKEND_SRCS%) do call :compile "src/backend/%%s.c" "build/%%s.o" || goto :error

echo === Linking library ===
set "OBJS="
for %%s in (%LIB_SRCS% %BACKEND_SRCS%) do set "OBJS=!OBJS! build/%%s.o"
ar rcs build/libbp_sdk.a %OBJS%
if errorlevel 1 goto :error

set "TESTS=test_phase1 test_phase2 test_phase3a test_concurrency test_bpsec_primitives test_session"
echo.
echo === Building tests ===
for %%t in (%TESTS%) do call :linkbin "tests/%%t.c" "build/%%t.exe"

set "EXAMPLES=hello_send sender receiver secure_send"
echo.
echo === Building examples ===
for %%e in (%EXAMPLES%) do call :linkbin "examples/%%e.c" "build/%%e.exe"

echo.
echo === Build successful: build\libbp_sdk.a ===
exit /b 0

:ensure_gcc
where gcc >nul 2>&1
if not errorlevel 1 exit /b 0
if exist "C:\mingw64\bin\gcc.exe" set "PATH=%PATH%;C:\mingw64\bin"
if exist "C:\msys64\mingw64\bin\gcc.exe" set "PATH=%PATH%;C:\msys64\mingw64\bin"
where gcc >nul 2>&1
exit /b %errorlevel%

:compile
echo   %~1
gcc %CFLAGS% -c %1 -o %2
exit /b %errorlevel%

:linkbin
if not exist %1 exit /b 0
echo   %~1
gcc %CFLAGS% %1 -L./build -lbp_sdk %LDFLAGS% -o %2
if errorlevel 1 echo   warning: %~1 failed to build
exit /b 0

:error
echo.
echo === Build failed ===
echo Make sure gcc (MinGW-w64) is installed and on PATH.
exit /b 1
