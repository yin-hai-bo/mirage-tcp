@echo off
set CONTAINER_NAME=mirage-tcp-dev

docker rm -f %CONTAINER_NAME% >nul 2>nul

if "%~1"=="" (
  for %%I in ("%~dp0..") do docker run --rm -it ^
    --name %CONTAINER_NAME% ^
    --cap-add=NET_ADMIN ^
    --device /dev/net/tun ^
    -v "%%~fI:/root/mirage-tcp" ^
    -w /root/mirage-tcp ^
    mirage-tcp-dev
) else (
  for %%I in ("%~dp0..") do docker run --rm -it ^
    --name %CONTAINER_NAME% ^
    --cap-add=NET_ADMIN ^
    --device /dev/net/tun ^
    -v "%%~fI:/root/mirage-tcp" ^
    -w /root/mirage-tcp ^
    "%~1"
)
