#pragma once

#include <string>
#include "protocol/json_message.h"

using namespace std;

class ipc_packet : public json_message
{
protected:
	void mount_json(rapidjson::Document& document) override;

public:
	ipc_packet();
	void type(const string& type) { _type = type;  };
	void data(const string& data) { _data = data;  };
	const string& type() { return _type; }
	const string& data() { return _data; };

private:
	string _type;
	string _data;
};
