#include "pch.h"
#include "pluginmain.h"
#include "Signature.h"
#include "SignatureDialog.h"
#include "Util.h"
#include <CommCtrl.h>
#include <sstream>
#include <iomanip>
#include <deque>
#include "CDistorm.h"
#include "resource.h"

namespace
{
	static bool ExecDistorm(duint start, duint end, std::deque<CDistorm>& items)
	{
		if (start >= end) {
			return false;
		}

		duint ptr = start;
		while (ptr < end) {
			items.push_back(CDistorm(ptr));
			size_t size = items.back().Size();
			if (size == 0) {
				items.clear();
				return false;
			}

			ptr += size;
		}

		return true;
	}
}



namespace Signature::Dialog
{
	static HWND s_hDialog = nullptr;
	static std::deque<CDistorm> s_dItems;

	bool GetTargetLabel(std::string& label)
	{
		//
		// 選択中のラベル名を取得
		//
		HWND hCombo = GetDlgItem(s_hDialog, IDC_COMBO);
		SendMessage(hCombo, CB_GETCURSEL, 0, 0);

		char buffer[MAX_LABEL_SIZE];
		if (GetDlgItemText(s_hDialog, IDC_COMBO, buffer, sizeof(buffer)) == 0) {
			return false;
		}

		label = buffer;
		return true;
	}


	static void UpdateSignature()
	{
		//
		// 選択中のラベル名を取得
		//
		std::string label;
		if (!GetTargetLabel(label)) {
			return;
		}

		//
		// シグネチャ生成
		//
		HWND hList = GetDlgItem(s_hDialog, IDC_LIST);
		std::ostringstream oss;
		std::string dump;
		for (int i = 0; i < s_dItems.size(); ++i) {
			const CDistorm& elem = s_dItems[i];

			bool wildcard = ListView_GetCheckState(hList, i);
			if (!elem.GetDump(dump, wildcard)) {
				continue;
			}
			if (label.size() > 0) {
				std::string str;
				if (Util::GetLabel(elem.CodeOffset(), str) && str == label) {
					label.clear();
					oss << "*";
					oss << dump;
					continue;
				}
				else if (elem.ContainsLabel(str) && str == label) {
					auto space_pos = dump.find_first_of(' ');
					if (space_pos != std::string::npos) {
						label.clear();
						oss << dump.substr(0, space_pos + 1);
						oss << "*";
						oss << dump.substr(space_pos + 1, dump.size());
					}
					//label.clear();
					//size_t len = dump.size() - elem.ValueSize() * 2;
					//oss << dump.substr(0, len);
					//oss << "*";
					//oss << dump.substr(len, dump.size());
					continue;
				}
			}
			oss << dump;
		}
		std::string signature = oss.str();
		oss.str("");

		//
		// ２文字ずつ区切って出力する
		//
		char prev = 0;
		for (char c : signature) {
			if (c == '*') {
				oss << c;
				continue;
			}
			if (c != '?' && !std::isxdigit(c)) {
				continue;
			}
			if (prev) {
				oss << prev << c << " ";
				prev = 0;
			}
			else {
				prev = c;
			}
		}
		signature = oss.str();

		// 末尾スペースを除去
		if (!signature.empty() && signature.back() == ' ') {
			signature.pop_back();
		}
		if (!signature.empty() && signature.front() == '*') {
			signature = signature.substr(1, signature.size());
		}

		SetDlgItemText(s_hDialog, IDC_EDIT, signature.c_str());
	}


	static void UpdateListItem(int idx)
	{
		HWND hList = GetDlgItem(s_hDialog, IDC_LIST);

		bool wildcard = ListView_GetCheckState(hList, idx);
		const CDistorm& distorm = s_dItems[idx];

		LV_ITEM item;
		memset(&item, 0, sizeof(LV_ITEM));

		item.mask = LVIF_TEXT;
		item.iItem = idx;

		std::string dump;
		if (distorm.GetDump(dump, wildcard)) {
			item.pszText = const_cast<LPSTR>(dump.c_str());
			item.iSubItem = 1;
			ListView_SetItem(hList, &item);
		}

		UpdateSignature();
	}


	static void InitPullDown()
	{
		HWND hCombo = GetDlgItem(s_hDialog, IDC_COMBO);

		for (auto& elem : s_dItems) {
			// プルダウンリストにラベルを追加
			std::string label;
			if (Util::GetLabel(elem.CodeOffset(), label) || elem.ContainsLabel(label)) {
				if (CB_ERR == SendMessage(hCombo, CB_FINDSTRINGEXACT, -1, (LPARAM)label.c_str())) {
					SendMessage(hCombo, CB_ADDSTRING, 0, (LPARAM)label.c_str());
				}
			}
		}
		SendMessage(hCombo, CB_SETCURSEL, 0, 0);
	}


	static void InitDialog(HWND hwndDlg)
	{
		HWND hList = GetDlgItem(hwndDlg, IDC_LIST);

		//
		// ダイアログ内で使用するコモンコントロールを初期化
		//
		INITCOMMONCONTROLSEX data;
		data.dwSize = sizeof(INITCOMMONCONTROLSEX);
		data.dwICC = ICC_LISTVIEW_CLASSES;
		InitCommonControlsEx(&data);


		//
		// リストビューの初期化
		//
		DWORD dwStyle = ListView_GetExtendedListViewStyle(hList);
		dwStyle |= LVS_EX_CHECKBOXES | LVS_EX_GRIDLINES;
		ListView_SetExtendedListViewStyle(hList, dwStyle);

		LVCOLUMN col;
		col.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
		col.fmt = LVCFMT_LEFT;
		col.cx = 36;
		col.pszText = TEXT(" ");
		col.iSubItem = 0;
		ListView_InsertColumn(hList, 0, &col);

		col.cx = 256;
		col.pszText = TEXT("-- Dump --");
		col.iSubItem = 1;
		ListView_InsertColumn(hList, 1, &col);

		col.cx = 512;
		col.pszText = TEXT("-- Disassembly --");
		col.iSubItem = 2;
		ListView_InsertColumn(hList, 2, &col);

		col.cx = 512;
		col.pszText = TEXT("-- Label --");
		col.iSubItem = 3;
		ListView_InsertColumn(hList, 3, &col);

		//
		// リストビューに空欄を確保
		//
		LV_ITEM item;
		memset(&item, 0, sizeof(LV_ITEM));
		item.mask = LVIF_TEXT;
		item.pszText = "";
		item.iItem = 0;
		item.iSubItem = 0;
		for (int i = 0; i < s_dItems.size(); ++i) {
			ListView_InsertItem(hList, &item);
		}

		//
		// 空欄を埋める
		//
		int idx = 0;
		for (auto& elem : s_dItems) {
			item.iItem = idx;

			bool wildcard = elem.ContainsAddress();
			std::string dump;
			if (elem.GetDump(dump, wildcard)) {
				item.pszText = const_cast<LPSTR>(dump.c_str());
				item.iSubItem = 1;
				ListView_SetItem(hList, &item);
				ListView_SetCheckState(hList, idx, wildcard);
			}

			item.pszText = const_cast<LPSTR>(elem.str().c_str());
			item.iSubItem = 2;
			ListView_SetItem(hList, &item);

			std::string label;
			if (Util::GetLabel(elem.CodeOffset(), label) || elem.ContainsLabel(label)) {
				item.pszText = const_cast<LPSTR>(label.c_str());
				item.iSubItem = 3;
				ListView_SetItem(hList, &item);
			}

			idx++;
		}
	}


	static bool GetSignature(std::string& pattern)
	{
		HWND hEdit = GetDlgItem(s_hDialog, IDC_EDIT);

		int buffsize = GetWindowTextLength(hEdit);
		if (buffsize == 0) {
			return false;
		}
		buffsize++;

		char* buffer = (char*)BridgeAlloc(buffsize);
		memset(buffer, 0, buffsize);
		int size = GetWindowText(hEdit, buffer, buffsize);
		if (size > 0) {
			pattern = buffer;
		}
		BridgeFree(buffer);
		return size > 0;
	}


	static bool Find(const std::string& signature, std::vector<duint>& result, size_t max = 0)
	{
		size_t idx = 0;
		std::string pattern;
		if (!Signature::MakePatternFromSignature(signature, pattern, idx)) {
			_plugin_logprint("signature is empty\n");
			return false;
		}
		if (pattern.size() == 0) {
			_plugin_logprint("pattern is empty\n");
			return false;
		}

		duint addr;
		duint size;
		if (!Util::GetMainModuleCodeInfo(addr, size)) {
			_plugin_logprint("maybe fatal error\n");
			return false;
		}

		result = Util::FindMemAll(addr, size, pattern.c_str(), max);
		return true;
	}

	static void OnScanButton()
	{
		size_t max = 10;
		std::vector<duint> result;

		std::string pattern;
		if (!GetSignature(pattern)) {
			return;
		}
		if (!Find(pattern, result, max)) {
			return;
		}

		if (result.size() == 0) {
			_plugin_logprint("not found\n");
		}
		if (result.size() == 1) {
			_plugin_logprint("1 occurrence found\n");
			EnableWindow(GetDlgItem(s_hDialog, IDC_OK), true);
		}
		else if (result.size() >= max) {
			_plugin_logprint("10+ occurrence found\n");
		}
		else {
			_plugin_logprintf("%d occurrences found\n", result.size());
		}

		//
		// Output a result to Reference View にチェックが入っていれば、結果を出力する
		//
		if (BST_CHECKED == SendMessage(GetDlgItem(s_hDialog, IDC_CHECK), BM_GETCHECK, 0, 0)) {
			GuiReferenceInitialize("Scan result");
			GuiReferenceAddColumn(16, GuiTranslateText("Address"));
			GuiReferenceAddColumn(60, GuiTranslateText("Disassembly"));
			GuiReferenceSetRowCount(result.size());
			GuiReferenceSetProgress(0);

			char temp[32];
			DISASM_INSTR inst;
			duint idx = 0;
			for (duint p : result) {
				sprintf_s(temp, "%p", (PVOID)p);
				GuiReferenceSetCellContent(idx, 0, temp);

				DbgDisasmAt(p, &inst);
				GuiReferenceSetCellContent(idx, 1, inst.instruction);
				++idx;
			}

			GuiReferenceSetProgress(100);
			GuiUpdateAllViews();
		}
	}


	static void OnOKButton()
	{
		std::vector<duint> result;

		std::string label;
		if (!GetTargetLabel(label)) {
			return;
		}
		std::string pattern;
		if (!GetSignature(pattern)) {
			return;
		}
		if (!Signature::Find(pattern, result)) {
			_plugin_logprint("invalid signature");
			return;
		}
		if (result.size() != 1) {
			_plugin_logprint("cannot create signature: pattern not found");
			return;
		}
		
		std::string resultLabel;
		if (!Util::GetLabel(result.front(), resultLabel)) {
			return;
		}
		if (resultLabel != label) {
			return;
		}

		Signature::Set(label, pattern);

		Destroy();

		return;
	}

	
	static void OnCancelButton()
	{
		Destroy();
	}


	static INT_PTR CALLBACK DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
	{
		static bool bIniting = true;

		switch (uMsg) {
		case WM_INITDIALOG:
		{
			bIniting = true;


			InitDialog(hwndDlg);

			bIniting = false;
		}
		break;

		case WM_CLOSE:
		{
			Destroy();
		}
		break;

		case WM_COMMAND:
		{
			switch (LOWORD(wParam)) {
			case IDC_COMBO:
				if (HIWORD(wParam) == CBN_SELCHANGE) {
					UpdateSignature();
				}
				break;

			case IDC_EDIT:
				if (HIWORD(wParam) == EN_UPDATE) {
					EnableWindow(GetDlgItem(hwndDlg, IDC_OK), false);
				}
				break;

			case IDC_OK:
				OnOKButton();
				break;

			case IDC_CANCEL:
				OnCancelButton();
				break;

			case IDC_SCAN:
				OnScanButton();
				break;
			}
		}
		break;

		case WM_NOTIFY:
		{
			if (!bIniting) {
				LPNMHDR hdr = (LPNMHDR)lParam;
				switch (hdr->idFrom) {
				case IDC_LIST:
				{
					LPNMLISTVIEW pData = (LPNMLISTVIEW)lParam;
					if (pData->hdr.code == LVN_ITEMCHANGED && pData->iSubItem == 0) {
						int idx = pData->iItem;
						UpdateListItem(idx);
					}
				}
				break;
				}
			}
		}
		break;
		}

		return FALSE;
	}


	bool IsOpen()
	{
		return s_hDialog != nullptr;
	}


	void Destroy()
	{
		if (IsOpen()) {
			HWND hwnd = s_hDialog;
			s_hDialog = nullptr;
			s_dItems.clear();
			DestroyWindow(hwnd);
		}
	}


	void Create()
	{
		if (!DbgIsDebugging())
		{
			_plugin_logprintf("No process is being debugged!\n");
			return;
		}
		if (IsOpen()) {
			_plugin_logprintf("Dialog is already opened!\n");
			return;
		}

		SELECTIONDATA sel = { 0, 0 };
		if (!GuiSelectionGet(GUI_DISASSEMBLY, &sel)) {
			return;
		}
		if (sel.end - sel.start > 4096) {
			return;
		}

		s_dItems.clear();
		ExecDistorm(sel.start, sel.end + 1, s_dItems);
		if (s_dItems.size() == 0) {
			return;
		}

		int numLabels = 0;
		for (auto& elem : s_dItems) {
			std::string label;
			if (Util::GetLabel(elem.CodeOffset(), label) || elem.ContainsLabel(label)) {
				numLabels++;
			}
		}
		if (numLabels == 0) {
			Script::Gui::Message("Labels not found in the selection.");
			return;
		}


		s_hDialog = CreateDialog(g_dllHandle, MAKEINTRESOURCE(IDD_SIGNATURE), GuiGetWindowHandle(), DialogProc);


		if (!s_hDialog)
		{
			_plugin_logprintf("Failed to create signature dialog\n");
			return;
		}

		InitPullDown();
		UpdateSignature();

		ShowWindow(s_hDialog, SW_SHOW);
	}
}