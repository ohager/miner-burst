#pragma once

#include <string>
#include <sstream>
#include "BaseMessage.h"

using namespace std;

class MiningConfigMessage : public BaseMessage
{
public:
	MiningConfigMessage() : BaseMessage("miner_cfg")
	{
		// TODO: to be defined
	}

protected:
	string serializePayload() const override
	{
		return "";
	}
};

