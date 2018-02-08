#pragma once
#include "network.h"

class Server
{

public:

    Server(unsigned int listen_port);
    ~Server(void);

    void update();

	void receiveJsonFromClients();

	void sendActionPackets();

private:
	void handleMessage(const std::string&);

   // IDs for the clients connecting for table in Network 
    static unsigned int client_id;

   // The Network object 
    Network* network;

};
