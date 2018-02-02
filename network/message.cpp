#include "message.h"
#include "../rapidjson/document.h"
#include "../rapidjson/writer.h"
#include <iostream>

using namespace rapidjson;

message::message()
{
}

string message::serialize()
{
	Document d;
	d.SetObject();
	Document::AllocatorType& allocator = d.GetAllocator();

	Value type;
	type.SetString(this->type().c_str(), static_cast<SizeType>(this->type().length()));

	Value data;
	data.SetString(this->data().c_str(), static_cast<SizeType>(this->data().length()));

	d.AddMember("type", type, allocator);
	d.AddMember("data", data, allocator);

	StringBuffer buffer;
	Writer<StringBuffer> writer(buffer);
	d.Accept(writer);

	return buffer.GetString();
}
