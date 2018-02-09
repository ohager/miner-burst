#pragma once

#include <string>
#include <sstream>
#include "BaseMessage.h"

using namespace std;

class HeartbeatMessage : public BaseMessage
{
public:
	HeartbeatMessage(unsigned long iteration) : BaseMessage("heartbeat"), _iteration(iteration)
	{
	}

protected:
	string serializePayload() const override
	{
		stringstream ss;
		ss << R"("iteration":)" << _iteration;
		return ss.str();
	}

private:

	unsigned long _iteration;
};

