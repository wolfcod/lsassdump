# dumplsass

dumplsass duplicating the process via `RtlCreateProcessReflection` api.

The original POC is available on [GitHub](https://gist.github.com/GeneralTesler/68903f7eb00f047d32a4d6c55da5a05c)  

The `MiniDumpWriteDump` API has been replaced with `NanoDumpWriteDump` from NanoDump project.

For building you can use
    - msbuild
    - cmake
    - Visual C++ via command line

## NanoDump

NanoDump documentation is available at https://www.coresecurity.com/core-labs/articles/nanodump-red-team-approach-minidumps
Source code is available [here](https://github.com/fortra/nanodump/).

To avoid to include all nanodump features, I just merged into nanodump all functions/definitions used by `NanoDumpWriteDump`.

