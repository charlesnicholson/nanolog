rem @echo off
cl.exe /nologo /std:c17 /W4 /WX /Osy /EHsc /GL /c nanolog.c || exit /b 1

cl.exe /nologo /std:c++20 /W4 /WX /Osy /GL /EHsc /MP /c ^
    /D_CRT_SECURE_NO_WARNINGS ^
    unclog/elf.cc ^
    unclog/emit.cc ^
    unclog/thumb2.cc ^
    unclog/thumb2_inst.cc || exit /b 1

lib.exe /out:libunclog.lib *.o

dir

cl.exe /nologo /std:c++20 /W4 /WX /Osy /GL /EHsc /MP ^
    /D_CRT_SECURE_NO_WARNINGS ^
    unclog/args.cc ^
    unclog/unclog.cc ^
    nanolog.obj ^
    libunclog.lib ^
    /link /out:unclog.exe || exit /b 1

cl.exe /nologo /std:c++20 /W4 /WX /Osy /GL /EHsc /MP ^
    /D_CRT_SECURE_NO_WARNINGS ^
    tests/unittest_main.cc ^
    tests/test_nanolog.cc ^
    nanolog.obj ^
    libunclog.lib ^
    /link /out:nanolog_unittests.exe || exit /b 1

nanolog_unittests.exe || exit /b 1
