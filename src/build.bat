@echo off
rem ============================================================
rem  build.bat - 用 MSVC + OpenSSL 编译本实验的 C 程序
rem  用法: build.bat aes_lab.c -Fe:..\bin\aes_lab.exe
rem  说明: 不调用 vcvars64.bat（它会调用 reg.exe，在受限环境下可能被拦截），
rem        这里直接设定 INCLUDE / LIB / PATH 所需的最小集合。
rem ============================================================
setlocal
set MSVC=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.39.33519
set SDK=C:\Program Files (x86)\Windows Kits\10
set OSSL=D:\Anaconda3\Anaconda3\Library
set INCLUDE=%MSVC%\include;%SDK%\Include\10.0.22621.0\ucrt;%SDK%\Include\10.0.22621.0\um;%SDK%\Include\10.0.22621.0\shared;%OSSL%\include
set LIB=%MSVC%\lib\x64;%SDK%\Lib\10.0.22621.0\ucrt\x64;%SDK%\Lib\10.0.22621.0\um\x64;%OSSL%\lib
set PATH=%MSVC%\bin\Hostx64\x64;%PATH%
"%MSVC%\bin\Hostx64\x64\cl.exe" -nologo -utf-8 -O2 -MD -D_CRT_SECURE_NO_WARNINGS %* -link libcrypto.lib
