#pragma once

#include <cstring>
#include <exception>

#define MSG_END 0xC // '/f' as required by client ipc

class BaseMessage
{
public:

	BaseMessage(unsigned int buffer_size)
	{
		_buf = new char[buffer_size];
		_buffer_size = buffer_size;
	}

	virtual ~BaseMessage()
	{
		delete _buf;
	};

	const char * serialize(size_t & len)
	{
		const char * serialized = this->serializeImpl();
		len = strlen(serialized); 		
		if (len>=_buffer_size)
		{
			throw std::exception("Maximum buffer size exceeded");
		}

		memset(_buf, 0, _buffer_size);
		memcpy(_buf, serialized, len);
		_buf[len] = '\f';
		++len;
		return _buf;
	}


protected:
	virtual const char * serializeImpl() const = 0;

	virtual void deserialize(const char*) = 0;

private:
	char * _buf;
	unsigned _buffer_size;

};
