#include "server.h"

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
   if(network->acceptNewClient(client_id))
   {
        printf("client %d has been connected to the Server\n",client_id);

        client_id++;
   }

   receiveFromClients();
}

void Server::receiveFromClients()
{

    Packet packet;

	for(std::map<unsigned int, SOCKET>::iterator iter = network->sessions.begin(); iter != network->sessions.end(); iter++)
    {
        int data_length = network->receiveData(iter->first, network_data);

        if (data_length <= 0) 
        {
            //no data recieved
            continue;
        }

        unsigned int i = 0;
        while (i < static_cast<unsigned int>(data_length)) 
        {
            packet.deserialize(&(network_data[i]));
            i += sizeof(Packet);

            switch (packet.packet_type) {

                case INIT_CONNECTION:

                    printf("Server received init packet from client\n");

                    sendActionPackets();

                    break;

                case ACTION_EVENT:

                    printf("Server received action event packet from client\n");

                    sendActionPackets();

                    break;

                default:

                    printf("error in packet types\n");

                    break;
            }
        }
    }
}


void Server::sendActionPackets()
{
    // send action packet
    const unsigned int packet_size = sizeof(Packet);
    char packet_data[packet_size];

    Packet packet;
    packet.packet_type = ACTION_EVENT;

    packet.serialize(packet_data);

    network->sendToAll(packet_data,packet_size);
}