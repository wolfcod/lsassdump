# lsassdump

This project merges the following project:
- Spawning a process via `RtlCreateProcessReflection` - The original POC is available on [GitHub](https://gist.github.com/GeneralTesler/68903f7eb00f047d32a4d6c55da5a05c)  
- NanoDumpWriteDump (extracted from NanoDump project)

If you want to change the output file, change the path specified in `src/main.cpp` in CreateFile api.  
The `MiniDumpWriteDump` API has been replaced with `NanoDumpWriteDump` from NanoDump project.

## How to build
For building you can use
    - msbuild
    - cmake
    - Visual C++ via command line

To build a minimal file (VS 2022 ~16Kb) you need to use the Release profile (x64).

- From Visual Studio choose x64 | release  
- From x64 Developer Prompt: `MSBuild dumplsass.sln -t:Rebuild -p:Configuration=Release`
- Via CMake: `cmake -S . -B build/ -D CMAKE_BUILD_TYPE=Release && cmake --build build --config Release`

## NanoDump

NanoDump documentation is available at https://www.coresecurity.com/core-labs/articles/nanodump-red-team-approach-minidumps  
Source code is available [here](https://github.com/fortra/nanodump/).  

To avoid to include all nanodump features, I just merged into nanodump all functions/definitions used by `NanoDumpWriteDump`.

