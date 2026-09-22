@echo off
REM Full OS-DoH-client experiment: capture + block generator.
REM Run from an elevated (Administrator) Command Prompt, from Z:\
REM Usage: run_full_experiment.bat [blocks] [block_seconds] [gap_seconds] [resolver_ip]
REM   resolver_ip must match the IP set under Settings > Network > DNS (default 1.1.1.1 Cloudflare)

setlocal
set BLOCKS=%1
if "%BLOCKS%"=="" set BLOCKS=8
set BSEC=%2
if "%BSEC%"=="" set BSEC=150
set GAP=%3
if "%GAP%"=="" set GAP=80
set RESOLVER=%4
if "%RESOLVER%"=="" set RESOLVER=1.1.1.1

for /f "delims=" %%I in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd_HHmmss"') do set STAMP=%%I

set ETL=C:\doh_capture_%STAMP%.etl
set PCAPNG=Z:\doh_capture_%STAMP%.pcapng

echo Timestamp: %STAMP%
echo ETL: %ETL%
echo PCAPNG target: %PCAPNG%

echo === Configuring pktmon filter (TCP 443 to/from %RESOLVER%) ===
pktmon filter remove >nul 2>&1
pktmon filter add -i %RESOLVER% -p 443

echo === Starting capture: %ETL% ===
pktmon start --capture --pkt-size 0 -f "%ETL%"

timeout /t 3 /nobreak >nul

echo === Running block generator: %BLOCKS% x2 blocks, %BSEC%s each, %GAP%s gap ===
python os_doh_experiment_windows.py --blocks %BLOCKS% --block-seconds %BSEC% --gap-seconds %GAP% --out Z:\

echo === Stopping capture ===
timeout /t 5 /nobreak >nul
pktmon stop

echo === Converting to pcapng: %PCAPNG% ===
pktmon pcapng "%ETL%" -o "%PCAPNG%"

echo === Done. Files in Z:\ ===
dir /b Z:\*.pcapng Z:\blocks_*.json
echo Capture: %PCAPNG%
endlocal
