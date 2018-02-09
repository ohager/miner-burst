#pragma once

#include <string>
#include <sstream>
#include "BaseMessage.h"

using namespace std;

class PoolInfoMessage : public BaseMessage
{
public:
	PoolInfoMessage() : BaseMessage("pool_info")
	{
		// TODO: to be defined
	}

protected:
	string serializePayload() const override
	{
		return "";
	}

};

