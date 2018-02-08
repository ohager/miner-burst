#include "server.h"
#include <iostream>
#include "../rapidjson/rapidjson.h"
#include "../rapidjson/document.h"
#include "messages/HandshakeAckMessage.h"

unsigned int Server::client_id;

Server::Server(unsigned int listen_port)
{
	// id's to assign clients for our table
	client_id = 0;

	// set up the Server Network to listen 
	network = new Network(listen_port);
}

Server::~Server(void)
{
}

void Server::update()
{
	// get new clients
	if (network->acceptNewClient(client_id))
	{
		printf("client %d has been connected to the Server\n", client_id);

		client_id++;
	}

	receiveJsonFromClients();
}

void Server::receiveJsonFromClients()
{
	char buf[MAX_PACKET_SIZE];
	for (auto iter = network->sessions.begin(); iter != network->sessions.end(); ++iter)
	{
		memset(buf, 0, sizeof(buf));
		int data_length = network->receiveData(iter->first, buf);

		if (data_length <= 0)
		{
			//no data received
			continue;
		}

		rapidjson::Document d;
		// remove non-printable char
		if (buf[data_length - 1] < ' ')
		{
			buf[data_length - 1] = 0;
		}

		d.Parse(buf);
		if (d.HasParseError())
		{
			int code = d.GetParseError();
			std::cerr << code;
		}

		if (!d.HasMember("type"))
		{
			continue;
		}

		std::string type = d["type"].GetString();

		handleMessage(type);
	}
}


void Server::sendActionPackets()
{
	// send action packet
	/*
	const unsigned int packet_size = sizeof(JsonPacket);
	char packet_data[packet_size];

	JsonPacket packet;

	packet.serializeImpl(packet_data);
	
	network->sendToAll(packet_data, packet_size);
	*/
}

void Server::handleMessage(const std::string& type)
{
	
	if (type == "handshake")
	{
		HandshakeAckMessage ack;
		size_t len;
		const char * serialized = ack.serialize(len);
		std::cout << serialized << " size: " << len;
		network->sendToAll(const_cast<char*>(serialized), len);
	}
	// do I receive something else?
}
