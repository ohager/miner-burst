#pragma once

#include <string>
#include "json_message.h"

using namespace std;

class mining_message : public json_message
{
public:
	mining_message();

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


protected:
	void mount_json(rapidjson::Document& document) override;

private:
	string _deadline;
	string _networkdiff;
};

