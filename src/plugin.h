#pragma once

#include "pluginmain.h"

//plugin data
#define PLUGIN_NAME "SECUNDA MOON"
#define PLUGIN_VERSION 1

//functions
namespace Plugin
{
	bool Init(PLUG_INITSTRUCT* initStruct);
	void Stop();
	void Setup();
}
