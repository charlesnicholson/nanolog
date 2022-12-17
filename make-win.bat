@echo off
cl.exe /nologo /std:c17 /W4 /WX /Osy /EHsc /GL /c nanolog.c || exit /b 1

cl.exe /nologo /std:c++20 /W4 /WX /Osy /GL /EHsc /MP ^
    /D_CRT_SECURE_NO_WARNINGS ^
    unclog/args.cc ^
    unclog/elf.cc ^
    unclog/emit.cc ^
    unclog/thumb2.cc ^
    unclog/thumb2_inst.cc ^
    unclog/unclog.cc ^
    nanolog.obj ^
    /link /out:unclog.exe || exit /b 1

cl.exe /nologo /std:c++20 /W4 /WX /Osy /GL /EHsc /MP ^
    /D_CRT_SECURE_NO_WARNINGS ^
    tests/unittest_main.cc ^
    tests/test_nanolog.cc ^
    nanolog.obj ^
    /link /out:nanolog_unittests.exe || exit /b 1

nanolog_unittests.exe || exit /b 1
