
// wjsDlg.cpp : implementation file
//

#include "stdafx.h"
#include "wjs.h"
#include "wjsDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CAboutDlg dialog used for App About

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// Dialog Data
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CwjsDlg dialog




CwjsDlg::CwjsDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CwjsDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CwjsDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CwjsDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDOK, &CwjsDlg::OnBnClickedOk)
	ON_WM_TIMER()
	ON_WM_DESTROY()
	ON_WM_HOTKEY()
END_MESSAGE_MAP()


// CwjsDlg message handlers

BOOL CwjsDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	//SetTimer(1,1000,0);
	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon


	 
	// TODO: Add extra initialization here

	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CwjsDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CwjsDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CwjsDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

extern DWORD DoInject();

void CwjsDlg::OnBnClickedOk()
{
	DoInject();
}


void CwjsDlg::OnTimer(UINT_PTR nIDEvent)
{
	// TODO: Add your message handler code here and/or call default
	CRect rcWnd;
	GetWindowRect(&rcWnd);
	if (rcWnd.left < 0 || rcWnd.top < 0 || rcWnd.bottom > 1020 || rcWnd.right > 1950)
	{
		PostMessage(WM_CLOSE);
	}

	CDialogEx::OnTimer(nIDEvent);
}


void CwjsDlg::OnDestroy()
{
	CDialogEx::OnDestroy();

// 	if (dwId)
// 	{
// 		HANDLE h = OpenProcess(PROCESS_ALL_ACCESS,false, dwId);
// 		
// 		if (pWnd)
// 		{
// 			pWnd->PostMessage(WM_CLOSE);
// 		}
// 		
// 		TerminateProcess(h, 0);
// 	}
	// TODO: Add your message handler code here
}


void CwjsDlg::OnHotKey(UINT nHotKeyId, UINT nKey1, UINT nKey2)
{
	// TODO: Add your message handler code here and/or call default
	
	CDialogEx::OnHotKey(nHotKeyId, nKey1, nKey2);
}
