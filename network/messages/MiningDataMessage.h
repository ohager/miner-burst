#pragma once

#include <string>
#include <sstream>

using namespace std;

class MiningDataMessage : public BaseMessage
{
public:
	MiningDataMessage() : BaseMessage("mining_data")
	{
		_deadline= -1;
	}

	void deadline(unsigned long long dl)
	{
		_deadline = dl;
	}

	unsigned long long deadline() const
	{
		return _deadline;
	}

protected:
	string serializePayload() const override
	{
		stringstream ss;

		ss << R"("deadline":)" << _deadline;

		return ss.str();
	}

private:
	unsigned long long _deadline;
};

