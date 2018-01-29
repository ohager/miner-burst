#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <string>

#pragma comment (lib, "Ws2_32.lib")

class Sender
{
public:
	Sender();
	~Sender();
	bool initialize(const char * ipv4, int port);
};

