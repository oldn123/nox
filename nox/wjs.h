
// wjs.h : main header file for the PROJECT_NAME application
//

#pragma once

#ifndef __AFXWIN_H__
	#error "include 'stdafx.h' before including this file for PCH"
#endif

#include "resource.h"		// main symbols


// CwjsApp:
// See wjs.cpp for the implementation of this class
//

class CwjsApp : public CWinApp
{
public:
	CwjsApp();

	static DWORD DoInject();
	static BOOL RemoteEject();
// Overrides
public:
	virtual BOOL InitInstance();
	
// Implementation

	DECLARE_MESSAGE_MAP()
	virtual int ExitInstance();
};

extern CwjsApp theApp;