#pragma once
#include "network.h"
#include "data/MiningData.h"

class Server
{
public:

    Server(unsigned int listen_port = DEFAULT_PORT);
    ~Server(void);

    void update(const MiningData & info);

private:
	void receiveJsonFromClients();
	void handleIncomingMessage(const std::string&);
	void updateClients(const MiningData & data) const;

   // IDs for the clients connecting for table in Network 
    static unsigned int client_id;

   // The Network object 
    Network* network;

};
