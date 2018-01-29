#ifndef SENDER_H
#define SENDER_H

#include "sender.h"


Sender::Sender()
{
	WSACleanup();
}


bool Sender::initialize(const char * ip4, int port){

	
	WSADATA wsaData;
	int iResult;

	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		std::cerr << "WSAStartup failed with error: " << iResult << std::endl;
		return false;
	}

	struct addrinfo *result = NULL, *ptr = NULL, hints;

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	iResult = getaddrinfo(NULL, std::to_string(port).c_str(), &hints, &result);
	if (iResult != 0) {
		std::cerr << "getaddrinfo failed:" << iResult << std::endl;
		WSACleanup();
		return false;
	}
	
	return true;

}

Sender::~Sender()
{
}

#endif
