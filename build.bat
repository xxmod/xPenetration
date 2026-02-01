@echo off
echo Building xPenetration...

:: 创建输出目录
if not exist "bin" mkdir bin

:: 从 .env 文件读取版本号
set VERSION=dev
for /f "tokens=1,2 delims==" %%a in (.env) do (
    if "%%a"=="version" set VERSION=%%b
)
echo Version: %VERSION%

:: 设置 ldflags
set LDFLAGS=-X main.version=%VERSION%

:: 编译服务端（不含 ACME）
echo Building server (no ACME)...
go build -ldflags "%LDFLAGS%" -o bin/xpen-server.exe ./cmd/server
if %errorlevel% neq 0 (
    echo Failed to build server
    exit /b 1
)

:: 编译带 ACME 的服务端
echo Building server with ACME...
go build -tags acme -ldflags "%LDFLAGS%" -o bin/xpen-server-with-acme.exe ./cmd/server
if %errorlevel% neq 0 (
    echo Failed to build server with ACME
    exit /b 1
)

:: 编译客户端
echo Building client...
go build -ldflags "%LDFLAGS%" -o bin/xpen-client.exe ./cmd/client
if %errorlevel% neq 0 (
    echo Failed to build client
    exit /b 1
)

echo.
echo Build completed successfully!
echo Output:
echo   bin/xpen-server.exe
echo   bin/xpen-server-with-acme.exe
echo   bin/xpen-client.exe
