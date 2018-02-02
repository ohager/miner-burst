#pragma once
#include <string>

using namespace std;

class JsonPacket
{
public:
	JsonPacket();
	void setType(const string& type) { _type = type;  };
	void setData(const string& data) { _data = data;  };
	const string& getType() { return _type; }
	const string& getData() { return _data; };

	virtual string serialize();

private:
	string _type;
	string _data;
};
