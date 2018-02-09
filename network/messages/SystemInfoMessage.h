#pragma once

#include <string>
#include <sstream>
#include "BaseMessage.h"

using namespace std;

class SystemInfoMessage : public BaseMessage
{
public:
	SystemInfoMessage() : BaseMessage("sys_info")
	{
		// TODO to be defined
	}

protected:
	string serializePayload() const override
	{
		return "";
	}

};

