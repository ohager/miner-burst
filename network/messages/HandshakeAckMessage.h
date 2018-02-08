#pragma once
#include "BaseMessage.h"

class HandshakeAckMessage : public BaseMessage
{
public:
	HandshakeAckMessage() : BaseMessage(64){}

	~HandshakeAckMessage()= default;

protected:
	const char * serializeImpl() const override
	{
		return R"({"type":"handshake_ack"})";
	}

	void deserialize(const char*) override
	{
		throw std::exception("Not implemented");
	};
};


