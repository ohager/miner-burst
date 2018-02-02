#pragma once

#include <string>

class base_message
{
public:
	base_message(unsigned int buffer_size = 100000)
	{
		_max_buffer_size = buffer_size;
	}
	virtual ~base_message() = default;
protected:
	virtual std::string serialize() = 0;

	unsigned int max_buffer_size() const { return _max_buffer_size; }
private:
	unsigned int _max_buffer_size;
};
