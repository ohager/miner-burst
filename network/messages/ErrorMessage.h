#pragma once

#include <string>
#include <sstream>
#include "BaseMessage.h"

class ErrorMessage : public BaseMessage
{
public:
	ErrorMessage() : BaseMessage("error")
	{
		_error= "";
	}

	void error(const std::string& errorMsg)
	{
		_error = errorMsg;
	}

	const std::string& error() const
	{
		return _error;
	}

protected:
	std::string serializePayload() const override
	{
		return R"("message":")" + _error + "\"";
	}

private:
	std::string _error;
};

