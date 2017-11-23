// stdafx.cpp : source file that includes just the standard includes
// ConsoleApplication1.pch will be the pre-compiled header
// stdafx.obj will contain the pre-compiled type information

#include "stdafx.h"

// TODO: reference any additional headers you need in STDAFX.H
// and not in this file


// link the bcrypt library.
// this is the same as adding bcrypt.lib into your project settings file
#pragma comment (lib, "bcrypt")
// for hex string to bin conversion
#pragma comment (lib, "crypt32")