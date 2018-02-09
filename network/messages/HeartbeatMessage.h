#pragma once

#include <string>
#include <sstream>
#include "BaseMessage.h"

using namespace std;

class HeartbeatMessage : public BaseMessage
{
public:
	HeartbeatMessage() : BaseMessage("heartbeat")
	{
		++_iteration;
	}

	const unsigned long& iteration() const
	{
		return _iteration;
	}

protected:
	string serializePayload() const override
	{
		stringstream ss;
		ss << R"("iteration":)" << _iteration;
		return ss.str();
	}

private:
	static unsigned long _iteration;
};

unsigned long HeartbeatMessage::_iteration= 0;

