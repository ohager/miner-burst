#pragma once

#include "base_message.h"
#include "../../rapidjson/document.h"
#include "../../rapidjson/stringbuffer.h"
#include "../../rapidjson/writer.h"

class json_message : public base_message
{
public:
	static void add_string_member(rapidjson::Document& document, const std::string & key, const std::string& value)
	{
		rapidjson::Document::AllocatorType& a = document.GetAllocator();
		rapidjson::Value k(key.c_str(), a);
		rapidjson::Value v(value.c_str(), a);

		document.AddMember(k, v, a);

	}

	std::string serialize() override
	{
		rapidjson::Document d;
		d.SetObject();

		this->mount_json(d);

		rapidjson::StringBuffer buffer;
		rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
		d.Accept(writer);

		std::string json_str = buffer.GetString();

		if (json_str.size() >= max_buffer_size())
		{
			throw std::exception("Data size exceeds maximum packet size");
		}

		return json_str;
	}
protected:

	virtual void mount_json(rapidjson::Document& document) = 0;
};
