#include "mining_message.h"
#include "../../rapidjson/document.h"
#include "../../rapidjson/stringbuffer.h"
#include "../../rapidjson/writer.h"

using namespace rapidjson;

mining_message::mining_message()
= default;

void mining_message::mount_json(Document& document)
{
	add_string_member(document, "networkdiff", networkdiff());
	add_string_member(document, "deadline", deadline());

}
