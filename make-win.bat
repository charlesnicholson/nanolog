cl.exe /std:c++20 /W4 /WX /EHsc /D_CRT_SECURE_NO_WARNINGS /DNANOLOG_HOST_TOOL=1 ^
    nanolog.c ^
    unclog/args.cc ^
    unclog/elf.cc ^
    unclog/emit.cc ^
    unclog/thumb2.cc ^
    unclog/thumb2_inst.cc ^
    unclog/unclog.cc
    /link /out:unclog.exe || exit /b 1
