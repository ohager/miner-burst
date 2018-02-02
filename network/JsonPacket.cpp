#include "JsonPacket.h"
#include "../rapidjson/document.h"
#include "../rapidjson/writer.h"
#include <sstream>
#include <iostream>

using namespace rapidjson;

JsonPacket::JsonPacket()
{
}

string JsonPacket::serialize()
{
	stringstream ss;
	ss << "{\"type\":\"" << getType() << "\",\"data\":\"" << getData() << "\"}";
	Document d;
	d.Parse(ss.str().c_str());

	StringBuffer buffer;
	Writer<StringBuffer> writer(buffer);
	d.Accept(writer);

	return buffer.GetString();
}
