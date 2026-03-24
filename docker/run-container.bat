@echo off
if "%~1"=="" (
  for %%I in ("%~dp0..") do docker run --rm -it ^
    --cap-add=NET_ADMIN ^
    -v "%%~fI:/root/mirage-tcp" ^
    -w /root/mirage-tcp ^
    mirage-tcp-dev
) else (
  for %%I in ("%~dp0..") do docker run --rm -it ^
    --cap-add=NET_ADMIN ^
    -v "%%~fI:/root/mirage-tcp" ^
    -w /root/mirage-tcp ^
    "%~1"
)
