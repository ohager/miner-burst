#pragma once
#include "network.h"
#include "network_packet.h"

class Server
{

public:

    Server(unsigned int listen_port);
    ~Server(void);

    void update();

	void receiveFromClients();

	void sendActionPackets();

private:

   // IDs for the clients connecting for table in Network 
    static unsigned int client_id;

   // The Network object 
    Network* network;

	// data buffer
   char network_data[MAX_PACKET_SIZE];
};