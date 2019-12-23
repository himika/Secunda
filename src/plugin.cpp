#include "pch.h"
#include "plugin.h"
#include "Util.h"
#include "Signature.h"
#include "SignatureDialog.h"
#include "SignatureFile.h"
#include "MSRTTI.h"

enum {
	PLUGIN_MENU_OPEN,
	PLUGIN_MENU_SAVE,
	PLUGIN_MEMU_SHOW_SIGNATURES,
	PLUGIN_MEMU_CREATE_SIGNATURE,
	PLUGIN_MEMU_REMOVE_SIGNATURE,
	PLUGIN_MEMU_ANALYSE_RTTI
};


static void MakeSignature()
{
	SELECTIONDATA sel = { 0, 0 };
	if (!GuiSelectionGet(GUI_DISASSEMBLY, &sel)) {
		return;
	}

	Signature::Dialog::Create();
}


static void RemoveSignature()
{
	SELECTIONDATA sel = { 0, 0 };
	if (GuiSelectionGet(GUI_DISASSEMBLY, &sel)) {
		std::string label = Util::GetLabel(sel.start);
		if (label.size() > 0) {
			Signature::Remove(label);
		}
	}
}


static void MenuEntryCallback(CBTYPE Type, PLUG_CB_MENUENTRY* Info)
{
	if (!DbgIsDebugging()) {
		return;
	}

	switch (Info->hEntry)
	{
	case PLUGIN_MENU_OPEN:
		Util::OpenSelectionDialog("Open a signature file", "Signatures (*.json)\0*.json\0\0", false, Signature::File::Open);
		break;
	case PLUGIN_MENU_SAVE:
		if (Signature::Size()) {
			Util::OpenSelectionDialog("Open a signature file", "Signatures (*.json)\0*.json\0\0", true, Signature::File::Save);
		}
		break;
	case PLUGIN_MEMU_SHOW_SIGNATURES:
		Signature::Show();
		break;
	case PLUGIN_MEMU_CREATE_SIGNATURE:
		MakeSignature();
		break;
	case PLUGIN_MEMU_REMOVE_SIGNATURE:
		RemoveSignature();
		break;
	case PLUGIN_MEMU_ANALYSE_RTTI:
		MSRTTI::Analyse();
		break;
	default:
		break;
	}

	GuiUpdateAllViews();
}


static void MenuPrepareCallback(CBTYPE Type, PLUG_CB_MENUPREPARE* Info)
{
	if (Info->hMenu != GUI_DISASM_MENU) {
		return;
	}

	bool bDialogOpen = Signature::Dialog::IsOpen();
	bool bSelectionInFunction = false;
	bool bSelectionOnLabel = false;
	bool bLabelHasSignature = false;

	SELECTIONDATA sel = { 0, 0 };
	if (GuiSelectionGet(GUI_DISASSEMBLY, &sel)) {
		bSelectionInFunction = DbgFunctionGet(sel.start, nullptr, nullptr);

		std::string label;
		if (Util::GetLabel(sel.start, label)) {
			bSelectionOnLabel = true;
			bLabelHasSignature = Signature::Get(label);
		}
	}

	_plugin_menuentrysetvisible(pluginHandle, PLUGIN_MEMU_CREATE_SIGNATURE, !bDialogOpen);
	_plugin_menuentrysetvisible(pluginHandle, PLUGIN_MEMU_REMOVE_SIGNATURE, bSelectionOnLabel && bLabelHasSignature);
}


namespace Plugin
{

	//Initialize your plugin data here.
	bool Init(PLUG_INITSTRUCT* initStruct)
	{
		_plugin_registercallback(pluginHandle, CB_MENUENTRY, (CBPLUGIN)MenuEntryCallback);
		_plugin_registercallback(pluginHandle, CB_MENUPREPARE, (CBPLUGIN)MenuPrepareCallback);

		return true; //Return false to cancel loading the plugin.
	}

	//Deinitialize your plugin data here.
	void Stop()
	{
		if (Signature::Dialog::IsOpen()) {
			Signature::Dialog::Destroy();
		}

		_plugin_menuclear(hMenu);
		_plugin_menuclear(hMenuDisasm);

		_plugin_unregistercallback(pluginHandle, CB_MENUENTRY);
		_plugin_unregistercallback(pluginHandle, CB_MENUPREPARE);
	}

	//Do GUI/Menu related things here.
	void Setup()
	{
		_plugin_menuaddentry(hMenu, PLUGIN_MENU_OPEN, "&Open signature file");
		_plugin_menuaddentry(hMenu, PLUGIN_MENU_SAVE, "&Save signature file");
		_plugin_menuaddentry(hMenu, PLUGIN_MEMU_SHOW_SIGNATURES, "&Show Signatures");
		//_plugin_menuentrysetvisible(pluginHandle, PLUGIN_MENU_SAVE, false);
		_plugin_menuaddseparator(hMenu);
		_plugin_menuaddentry(hMenu, PLUGIN_MEMU_ANALYSE_RTTI, "&Analyse RTTI");

		_plugin_menuaddentry(hMenuDisasm, PLUGIN_MEMU_CREATE_SIGNATURE, "&Create signature");
		_plugin_menuaddentry(hMenuDisasm, PLUGIN_MEMU_REMOVE_SIGNATURE, "&Remove signature");
	}
}
