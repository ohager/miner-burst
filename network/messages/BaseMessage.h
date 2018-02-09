#pragma once

#include <cstring>
#include <string>
#include <sstream>
#include <exception>

#define MSG_END '\f' // '/f' as required by client ipc
#define MAX_BUFFER_SIZE (16 * 1024)

class BaseMessage
{
public:

	BaseMessage(const char * type)
	{
		_type = type;
		_buf = nullptr;
	}

	virtual ~BaseMessage()
	{
		delete _buf;
	};

	const char * serialize(size_t & len)
	{
		std::stringstream ss;

		std::string message = buildMessage();
		len = message.size();
		
		if (len >= MAX_BUFFER_SIZE) throw std::exception("Maximum Message Buffer Size exceeded");

		delete _buf;
		_buf = new char[len + 2];
		memset(_buf, 0, len + 2);
		memcpy(_buf, message.c_str(), len);
		_buf[len] = MSG_END;
		++len;
		return _buf;
	}

protected:
	virtual std::string serializePayload() const = 0;

private:
	std::string buildMessage() const
	{

		std::string payload = serializePayload();
		std::stringstream ss;
		// json structure
		ss << "{"
			<< R"("type":")" << _type << "\"";

		if (!payload.empty())
		{
			ss	<< R"(,"data":{)" 
					<< this->serializePayload()
				<< "}";
		}

		ss	<< "}";

		return ss.str();
	}

	std::string _type;
	char * _buf;
	unsigned _buffer_size;
};
