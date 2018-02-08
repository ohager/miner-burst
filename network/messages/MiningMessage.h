#pragma once

#include <string>

using namespace std;

class MiningMessage
{
public:
	MiningMessage();

	void deadline(const std::string& dl)
	{
		_deadline = dl;
	}

	void networkdiff(const std::string& diff)
	{
		_networkdiff = diff;
	}

	const std::string& deadline() const
	{
		return _deadline;
	}

	const std::string& networkdiff() const
	{
		return _networkdiff;
	}

private:
	string _deadline;
	string _networkdiff;
};

