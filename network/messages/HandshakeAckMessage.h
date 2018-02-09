#pragma once
#include "BaseMessage.h"

class HandshakeAckMessage : public BaseMessage
{
public:
	HandshakeAckMessage() : BaseMessage("handshake_ack"){}

	~HandshakeAckMessage()= default;

protected:
	std::string serializePayload() const override
	{
		return "";
	}
};


