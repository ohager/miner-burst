#include "ipc_packet.h"
#include "../rapidjson/document.h"
#include "../rapidjson/writer.h"

using namespace rapidjson;

void ipc_packet::mount_json(rapidjson::Document& document)
{
	add_string_member(document, "type", this->type());
	add_string_member(document, "data", this->data());
}

ipc_packet::ipc_packet()
{
}
