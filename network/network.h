#pragma once
#include <winsock2.h>
#include <Windows.h>
#include "network_services.h"
#include <ws2tcpip.h>
#include <map>
using namespace std; 
#pragma comment (lib, "Ws2_32.lib")

#define DEFAULT_PORT 4000 
#define MAX_PACKET_SIZE (4 * 1024)

class Network
{
public:
    Network(unsigned int port = DEFAULT_PORT);
    ~Network(void);

	// send data to all clients
    void sendToAll(char * packets, int totalSize);

	// receive incoming data
    int receiveData(unsigned int client_id, char * recvbuf);
	
	// accept new connections
    bool acceptNewClient(unsigned int & id);

	void refuseClient(unsigned int id);

    // Socket to listen for new connections
    SOCKET ListenSocket;

    // Socket to give to the clients
    SOCKET ClientSocket;

    // for error checking return values
    int iResult;

    // table to keep track of each client's socket
    std::map<unsigned int, SOCKET> sessions; 
};

