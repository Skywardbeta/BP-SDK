@echo off
setlocal enabledelayedexpansion

REM Windows convenience build script. The Makefile is the source of truth.
REM Public API headers are in include/bp_sdk/; module sources + private headers
REM live under src/ (core, bundle, transport, session, bpsec, adapters/{ion,
REM ud3tn}). All of these are on the include path. PATH expansion is kept
REM outside parenthesised IF blocks so special characters in %PATH% cannot
REM break command parsing.

call :ensure_gcc
if errorlevel 1 goto :error

if not exist build mkdir build

set "INC=-Iinclude/bp_sdk -Isrc/core -Isrc/bundle -Isrc/transport -Isrc/session -Isrc/bpsec -Isrc/adapters -Isrc/adapters/ion -Isrc/adapters/ud3tn -Itests"
set "CFLAGS=%INC% -Wall -Wextra -std=c11 -O2"
set "LDFLAGS=-lws2_32 -lbcrypt"

set "LIB_SRCS=src\core\bp_sdk src\core\bp_utils src\core\bp_cbor src\bundle\bp_bundle src\bundle\bp_admin src\bundle\bp_fragment src\bundle\bp_stream src\transport\bp_tcpcl src\transport\bp_storage src\transport\bp_backend_posix src\transport\bp_backend_bpsocket src\session\bp_session src\session\bp_security_intent src\bpsec\bp_bpsec src\bpsec\bp_bpsec_keys src\bpsec\bp_bpsec_policy src\bpsec\bp_crypto_backend src\bpsec\bp_key_provider src\adapters\bp_adapter src\adapters\ion\bp_adapter_ion src\adapters\ion\bp_ion_policy src\adapters\ud3tn\bp_adapter_ud3tn src\adapters\ud3tn\bp_aap"

echo === Compiling library ===
for %%s in (%LIB_SRCS%) do call :compile "%%s.c" "build\%%~ns.o" || goto :error

echo === Linking library ===
set "OBJS="
for %%s in (%LIB_SRCS%) do set "OBJS=!OBJS! build/%%~ns.o"
ar rcs build/libbp_sdk.a %OBJS%
if errorlevel 1 goto :error

set "TESTS=tests\integration\test_phase1 tests\integration\test_phase2 tests\integration\test_phase3a tests\integration\test_concurrency tests\bpsec\test_bpsec_primitives tests\session\test_session tests\session\test_intent tests\adapters\test_facade tests\adapters\ion\test_ion_policy tests\adapters\ud3tn\test_aap tests\adapters\ud3tn\test_ud3tn_adapter"
echo.
echo === Building tests ===
for %%t in (%TESTS%) do call :linkbin "%%t.c" "build\%%~nt.exe"

set "EXAMPLES=hello_send sender receiver secure_send secure_intent secure_link"
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
