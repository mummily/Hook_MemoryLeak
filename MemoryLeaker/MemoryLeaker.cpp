// MemoryLeaker.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <crtdbg.h>
#include <corecrt_malloc.h>
#include <iostream>
#include "AA.h"



int main()
{
    int *p = new int;
    AA aa;
    aa.func1();
    aa.func2();
    getchar();
    return 0;
}

