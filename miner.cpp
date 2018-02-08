#include "miner.h"

// Initialize static member data
const InstructionSet::InstructionSet_Internal InstructionSet::CPU_Rep;


void Log_init(void)
{
	if (!use_log) return;
	
	fp_Log = stdout;

	if (log_type == LOG_TYPE_FILE){
		std::stringstream ss;
		if (CreateDirectory(L"Logs", nullptr) == ERROR_PATH_NOT_FOUND)
		{
			wattron(win_main, COLOR_PAIR(12));
			wprintw(win_main, "CreateDirectory failed (%d)\n", GetLastError(), 0);
			wattroff(win_main, COLOR_PAIR(12));
			use_log = false;
			return;
		}
		GetLocalTime(&cur_time);
		ss << "Logs\\" << cur_time.wYear << "-" << cur_time.wMonth << "-" << cur_time.wDay << "_" << cur_time.wHour << "_" << cur_time.wMinute << "_" << cur_time.wSecond << ".log";
		std::string filename = ss.str();

		if ((fp_Log = _fsopen(filename.c_str(), "wt", _SH_DENYNO)) == NULL)
		{
			wattron(win_main, COLOR_PAIR(12));
			wprintw(win_main, "LOG: file opening error\n", 0);
			wattroff(win_main, COLOR_PAIR(12));
			use_log = false;
		}
	}

	Log(version);
}

void Log(char const *const strLog)
{
	if (use_log)
	{
		// add timestamp for a new line
		if (strLog[0] == '\n')
		{
			GetLocalTime(&cur_time);
			fprintf_s(fp_Log, "\n%02d:%02d:%02d %s", cur_time.wHour, cur_time.wMinute, cur_time.wSecond, strLog + 1);
		}
		else fprintf_s(fp_Log, "%s", strLog);
		fflush(fp_Log);
	}
}

void Log_server(char const *const strLog)
{
	size_t len_str = strlen(strLog);
	if ((len_str > 0) && use_log)
	{
		char * Msg_log = (char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, len_str * 2 + 1);
		if (Msg_log == nullptr)	ShowMemErrorExit();

		for (size_t i = 0, j = 0; i < len_str; i++, j++)
		{
			if (strLog[i] == '\r')
			{
				Msg_log[j] = '\\';
				j++;
				Msg_log[j] = 'r';
			}
			else
				if (strLog[i] == '\n')
				{
					Msg_log[j] = '\\';
					j++;
					Msg_log[j] = 'n';
				}
				else
					if (strLog[i] == '%')
					{
						Msg_log[j] = '%';
						j++;
						Msg_log[j] = '%';
					}
					else Msg_log[j] = strLog[i];
		}

		fprintf_s(fp_Log, "%s", Msg_log);
		fflush(fp_Log);
		HeapFree(hHeap, 0, Msg_log);
	}
}

void Log_llu(unsigned long long const llu_num)
{
	if (use_log)
	{
		fprintf_s(fp_Log, "%llu", llu_num);
		fflush(fp_Log);
	}
}

void Log_u(size_t const u_num)
{
	if (use_log)
	{
		fprintf_s(fp_Log, "%u", (unsigned)u_num);
		fflush(fp_Log);
	}
}

void ShowMemErrorExit(void)
{
	Log("\n!!! Error allocating memory");
	wattron(win_main, COLOR_PAIR(12));
	wprintw(win_main, "\nError allocating memory\n", 0);
	wattroff(win_main, COLOR_PAIR(12));
	wrefresh(win_main);
	system("pause");
	exit(-1);
}

int load_config(char const *const filename)
{
	FILE * pFile;

	fopen_s(&pFile, filename, "rt");

	if (pFile == nullptr)
	{
		fprintf(stderr, "\nError. file %s not found\n", filename);
		system("pause");
		exit(-1);
	}

	_fseeki64(pFile, 0, SEEK_END);
	__int64 const size = _ftelli64(pFile);
	_fseeki64(pFile, 0, SEEK_SET);
	char *json_ = (char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, size + 1);
	if (json_ == nullptr)
	{
		fprintf(stderr, "\nError allocating memory\n");
		system("pause");
		exit(-1);
	}
	fread_s(json_, size, 1, size - 1, pFile);
	fclose(pFile);

	Document document;	// Default template parameter uses UTF8 and MemoryPoolAllocator.
	if (document.Parse<0>(json_).HasParseError()){
		fprintf(stderr, "\nJSON format error (offset %u) check miner.conf\n%s\n", (unsigned)document.GetErrorOffset(), GetParseError_En(document.GetParseError())); //(offset %s  %s", (unsigned)document.GetErrorOffset(), (char*)document.GetParseError());
		system("pause");
		exit(-1);
	}

	if (document.IsObject())
	{	// Document is a JSON value represents the root of DOM. Root can be either an object or array.

		if (document.HasMember("UseLog") && (document["UseLog"].IsBool()))	use_log = document["UseLog"].GetBool();

		if (document.HasMember("LogType") && (document["LogType"].IsString()))	log_type = document["LogType"].GetString();

		if (log_type != LOG_TYPE_FILE && log_type != LOG_TYPE_STDOUT){
			fprintf(stderr, "Unknown Log Type (%s) - allowed are 'stdout' and 'file' ", log_type, 0);
			system("pause");
			exit(-1);
		}

		Log_init();

		if (document.HasMember("Mode") && document["Mode"].IsString())
		{
			Log("\nMode: ");
			if (strcmp(document["Mode"].GetString(), "solo") == 0) miner_mode = 0;
			else miner_mode = 1;
			Log_u(miner_mode);
		}

		Log("\nServer: ");
		if (document.HasMember("Server") && document["Server"].IsString())	nodeaddr = document["Server"].GetString();//strcpy_s(nodeaddr, document["Server"].GetString());
		Log(nodeaddr.c_str());

		Log("\nPort: ");
		if (document.HasMember("Port"))
		{
			if (document["Port"].IsString())	nodeport = document["Port"].GetString();
			else if (document["Port"].IsUint())	nodeport = std::to_string(document["Port"].GetUint()); //_itoa_s(document["Port"].GetUint(), nodeport, INET_ADDRSTRLEN-1, 10);
			Log(nodeport.c_str());
		}

		if (document.HasMember("Paths") && document["Paths"].IsArray()){
			const Value& Paths = document["Paths"];			// Using a reference for consecutive access is handy and faster.
			for (SizeType i = 0; i < Paths.Size(); i++)
			{
				Log("\nPath: ");
				paths_dir.push_back(Paths[i].GetString());
				Log((char*)paths_dir[i].c_str());
			}
		}

		Log("\nCacheSize: ");
		if (document.HasMember("CacheSize") && (document["CacheSize"].IsUint64())) cache_size = document["CacheSize"].GetUint64();
		Log_u(cache_size);

		Log("\nUseHDDWakeUp: ");
		if (document.HasMember("UseHDDWakeUp") && (document["UseHDDWakeUp"].IsBool())) use_wakeup = document["UseHDDWakeUp"].GetBool();
		Log_u(use_wakeup);

		Log("\nSendInterval: ");
		if (document.HasMember("SendInterval") && (document["SendInterval"].IsUint())) send_interval = (size_t)document["SendInterval"].GetUint();
		Log_u(send_interval);

		Log("\nUpdateInterval: ");
		if (document.HasMember("UpdateInterval") && (document["UpdateInterval"].IsUint())) update_interval = (size_t)document["UpdateInterval"].GetUint();
		Log_u(update_interval);

		Log("\nDebug: ");
		if (document.HasMember("Debug") && (document["Debug"].IsBool()))	use_debug = document["Debug"].GetBool();
		Log_u(use_debug);

		Log("\nUpdater address: ");
		if (document.HasMember("UpdaterAddr") && document["UpdaterAddr"].IsString()) updateraddr = document["UpdaterAddr"].GetString(); //strcpy_s(updateraddr, document["UpdaterAddr"].GetString());
		Log(updateraddr.c_str());

		Log("\nUpdater port: ");
		if (document.HasMember("UpdaterPort"))
		{
			if (document["UpdaterPort"].IsString())	updaterport = document["UpdaterPort"].GetString();
			else if (document["UpdaterPort"].IsUint())	 updaterport = std::to_string(document["UpdaterPort"].GetUint());
		}
		Log(updaterport.c_str());

		Log("\nInfo address: ");
		if (document.HasMember("InfoAddr") && document["InfoAddr"].IsString())	infoaddr = document["InfoAddr"].GetString();
		else infoaddr = updateraddr;
		Log(infoaddr.c_str());

		Log("\nInfo port: ");
		if (document.HasMember("InfoPort"))
		{
			if (document["InfoPort"].IsString())	infoport = document["InfoPort"].GetString();
			else if (document["InfoPort"].IsUint())	infoport = std::to_string(document["InfoPort"].GetUint());
		}
		else infoport = updaterport;
		Log(infoport.c_str());

		Log("\nEnableProxy: ");
		if (document.HasMember("EnableProxy") && (document["EnableProxy"].IsBool())) enable_proxy = document["EnableProxy"].GetBool();
		Log_u(enable_proxy);

		Log("\nProxyPort: ");
		if (document.HasMember("ProxyPort"))
		{
			if (document["ProxyPort"].IsString())	proxyport = document["ProxyPort"].GetString();
			else if (document["ProxyPort"].IsUint())	proxyport = std::to_string(document["ProxyPort"].GetUint());
		}
		Log(proxyport.c_str());

		Log("\nShowWinner: ");
		if (document.HasMember("ShowWinner") && (document["ShowWinner"].IsBool()))	show_winner = document["ShowWinner"].GetBool();
		Log_u(show_winner);

		Log("\nTargetDeadline: ");
		if (document.HasMember("TargetDeadline") && (document["TargetDeadline"].IsInt64()))	my_target_deadline = document["TargetDeadline"].GetUint64();
		Log_llu(my_target_deadline);

		Log("\nUseBoost: ");
		if (document.HasMember("UseBoost") && (document["UseBoost"].IsBool())) use_boost = document["UseBoost"].GetBool();
		Log_u(use_boost);

		Log("\nWinSizeX: ");
		if (document.HasMember("WinSizeX") && (document["WinSizeX"].IsUint())) win_size_x = (short)document["WinSizeX"].GetUint();
		Log_u(win_size_x);

		Log("\nWinSizeY: ");
		if (document.HasMember("WinSizeY") && (document["WinSizeY"].IsUint())) win_size_y = (short)document["WinSizeY"].GetUint();
		Log_u(win_size_y);

	}

	Log("\n=== Config loaded ===");
	HeapFree(hHeap, 0, json_);
	return 1;
}

// TODO: Extract to separate class
// Helper routines taken from http://stackoverflow.com/questions/1557400/hex-to-char-array-in-c
int xdigit(char const digit){
	int val;
	if ('0' <= digit && digit <= '9') val = digit - '0';
	else if ('a' <= digit && digit <= 'f') val = digit - 'a' + 10;
	else if ('A' <= digit && digit <= 'F') val = digit - 'A' + 10;
	else val = -1;
	return val;
}

size_t xstr2strr(char *buf, size_t const bufsize, const char *const in) {
	if (!in) return 0; // missing input string

	size_t inlen = (size_t)strlen(in);
	if (inlen % 2 != 0) inlen--; // hex string must even sized

	size_t i, j;
	for (i = 0; i < inlen; i++)
		if (xdigit(in[i]) < 0) return 0; // bad character in hex string

	if (!buf || bufsize < inlen / 2 + 1) return 0; // no buffer or too small

	for (i = 0, j = 0; i < inlen; i += 2, j++)
		buf[j] = xdigit(in[i]) * 16 + xdigit(in[i + 1]);

	buf[inlen / 2] = '\0';
	return inlen / 2 + 1;
}

void GetPass(char const *const p_strFolderPath)
{
	FILE * pFile;
	unsigned char * buffer;
	size_t len_pass;
	char * filename = (char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_PATH);
	if (filename == nullptr) ShowMemErrorExit();
	sprintf_s(filename, MAX_PATH, "%s%s", p_strFolderPath, "passphrases.txt");

	fopen_s(&pFile, filename, "rt");
	if (pFile == nullptr)
	{
		wattron(win_main, COLOR_PAIR(12));
		wprintw(win_main, "passphrases.txt not found\n", 0);
		wattroff(win_main, COLOR_PAIR(12));
		system("pause");
		exit(-1);
	}
	HeapFree(hHeap, 0, filename);
	_fseeki64(pFile, 0, SEEK_END);
	size_t const lSize = _ftelli64(pFile);
	_fseeki64(pFile, 0, SEEK_SET);

	buffer = (unsigned char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, lSize + 1);
	if (buffer == nullptr) ShowMemErrorExit();

	len_pass = fread(buffer, 1, lSize, pFile);
	fclose(pFile);

	pass = (char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, lSize * 3);
	if (pass == nullptr) ShowMemErrorExit();

	for (size_t i = 0, j = 0; i < len_pass; i++, j++)
	{
		if ((buffer[i] == '\n') || (buffer[i] == '\r') || (buffer[i] == '\t')) j--; // Пропускаем символы, переделать buffer[i] < 20
		else
			if (buffer[i] == ' ') pass[j] = '+';
			else
				if (isalnum(buffer[i]) == 0)
				{
					sprintf_s(pass + j, lSize * 3, "%%%x", (unsigned char)buffer[i]);
					j = j + 2;
				}
				else memcpy(&pass[j], &buffer[i], 1);
	}
	HeapFree(hHeap, 0, buffer);
}

size_t GetFiles(const std::string &str, std::vector <t_files> *p_files)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATAA   FindFileData;
	size_t count = 0;
	std::vector<std::string> path;
	size_t first = 0;
	size_t last = 0;

	do{
		last = str.find("+", first);
		if (last == -1) last = str.length();
		std::string str2(str.substr(first, last - first));
		if (str2.rfind("\\") < str2.length() - 1) str2 = str2 + "\\";
		path.push_back(str2);
		first = last + 1;
	} while (last != str.length());

	for (auto iter = path.begin(); iter != path.end(); ++iter)
	{
		hFile = FindFirstFileA(LPCSTR((*iter + "*").c_str()), &FindFileData);
		if (INVALID_HANDLE_VALUE != hFile)
		{
			do
			{
				if (FILE_ATTRIBUTE_DIRECTORY & FindFileData.dwFileAttributes) continue; //Skip directories
				char* ekey = strstr(FindFileData.cFileName, "_");
				if (ekey != nullptr)
				{
					char* estart = strstr(ekey + 1, "_");
					if (estart != nullptr)
					{
						char* enonces = strstr(estart + 1, "_");
						if (enonces != nullptr)
						{
							unsigned long long key, nonce, nonces, stagger;
							if (sscanf_s(FindFileData.cFileName, "%llu_%llu_%llu_%llu", &key, &nonce, &nonces, &stagger) == 4)
							{
								p_files->push_back({
									*iter,
									FindFileData.cFileName,
									(((static_cast<ULONGLONG>(FindFileData.nFileSizeHigh) << (sizeof(FindFileData.nFileSizeLow) * 8)) | FindFileData.nFileSizeLow)),
									key, nonce, nonces, stagger
								});
								count++;
							}
						}
					}
				}
			} while (FindNextFileA(hFile, &FindFileData));
			FindClose(hFile);
		}
	}
	return count;
}

size_t Get_index_acc(unsigned long long const key)
{
	EnterCriticalSection(&bestsLock);
	size_t acc_index = 0;
	for (auto it = bests.begin(); it != bests.end(); ++it)
	{
		if (it->account_id == key)
		{
			LeaveCriticalSection(&bestsLock);
			return acc_index;
		}
		acc_index++;
	}
	bests.push_back({ key, 0, 0, 0, targetDeadlineInfo });
	LeaveCriticalSection(&bestsLock);
	return bests.size() - 1;
}

void proxy_i(void)
{
	int iResult;
	size_t const buffer_size = 1000;
	char* buffer = (char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, buffer_size);
	if (buffer == nullptr) ShowMemErrorExit();
	char* tmp_buffer = (char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, buffer_size);
	if (tmp_buffer == nullptr) ShowMemErrorExit();
	char tbuffer[9];
	SOCKET ServerSocket = INVALID_SOCKET;
	SOCKET ClientSocket = INVALID_SOCKET;
	struct addrinfo *result = nullptr;
	struct addrinfo hints;

	RtlSecureZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	iResult = getaddrinfo(nullptr, proxyport.c_str(), &hints, &result);
	if (iResult != 0) {
		wattron(win_main, COLOR_PAIR(12));
		wprintw(win_main, "PROXY: getaddrinfo failed with error: %d\n", iResult, 0);
		wattroff(win_main, COLOR_PAIR(12));
	}

	ServerSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if (ServerSocket == INVALID_SOCKET) {
		wattron(win_main, COLOR_PAIR(12));
		wprintw(win_main, "PROXY: socket failed with error: %ld\n", WSAGetLastError(), 0);
		wattroff(win_main, COLOR_PAIR(12));
		freeaddrinfo(result);
	}

	iResult = ::bind(ServerSocket, result->ai_addr, (int)result->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		wattron(win_main, COLOR_PAIR(12));
		wprintw(win_main, "PROXY: bind failed with error: %d\n", WSAGetLastError(), 0);
		wattroff(win_main, COLOR_PAIR(12));
		freeaddrinfo(result);
		closesocket(ServerSocket);
	}
	freeaddrinfo(result);
	BOOL l = TRUE;
	iResult = ioctlsocket(ServerSocket, FIONBIO, (unsigned long*)&l);
	if (iResult == SOCKET_ERROR)
	{
		Log("\nProxy: ! Error ioctlsocket's: "); Log_u(WSAGetLastError());
		wattron(win_main, COLOR_PAIR(12));
		wprintw(win_main, "PROXY: ioctlsocket failed: %ld\n", WSAGetLastError(), 0);
		wattroff(win_main, COLOR_PAIR(12));
	}

	iResult = listen(ServerSocket, 8);
	if (iResult == SOCKET_ERROR) {
		wattron(win_main, COLOR_PAIR(12));
		wprintw(win_main, "PROXY: listen failed with error: %d\n", WSAGetLastError(), 0);
		wattroff(win_main, COLOR_PAIR(12));
		closesocket(ServerSocket);
	}
	Log("\nProxy thread started");

	for (; !exit_flag;)
	{
		struct sockaddr_in client_socket_address;
		int iAddrSize = sizeof(struct sockaddr_in);
		ClientSocket = accept(ServerSocket, (struct sockaddr *)&client_socket_address, (socklen_t*)&iAddrSize);

		char client_address_str[INET_ADDRSTRLEN];
		inet_ntop(hints.ai_family, &(client_socket_address.sin_addr), client_address_str, INET_ADDRSTRLEN);

		if (ClientSocket == INVALID_SOCKET)
		{
			if (WSAGetLastError() != WSAEWOULDBLOCK)
			{
				Log("\nProxy:! Error Proxy's accept: "); Log_u(WSAGetLastError());
				wattron(win_main, COLOR_PAIR(12));
				wprintw(win_main, "PROXY: can't accept. Error: %ld\n", WSAGetLastError(), 0);
				wattroff(win_main, COLOR_PAIR(12));
			}
		}
		else
		{
			RtlSecureZeroMemory(buffer, buffer_size);
			do{
				RtlSecureZeroMemory(tmp_buffer, buffer_size);
				iResult = recv(ClientSocket, tmp_buffer, (int)(buffer_size - 1), 0);
				strcat_s(buffer, buffer_size, tmp_buffer);
			} while (iResult > 0);

			Log("\nProxy get info: ");  Log_server(buffer);
			unsigned long long get_accountId = 0;
			unsigned long long get_nonce = 0;
			unsigned long long get_deadline = 0;
			unsigned long long get_totalsize = 0;
			// locate HTTP header
			char *find = strstr(buffer, "\r\n\r\n");
			if (find != nullptr)
			{
				if (strstr(buffer, "submitNonce") != nullptr)
				{

					char *startaccountId = strstr(buffer, "accountId=");
					if (startaccountId != nullptr)
					{
						startaccountId = strpbrk(startaccountId, "0123456789");
						char *endaccountId = strpbrk(startaccountId, "& }\"");

						char *startnonce = strstr(buffer, "nonce=");
						char *startdl = strstr(buffer, "deadline=");
						char *starttotalsize = strstr(buffer, "X-Capacity");
						if ((startnonce != nullptr) && (startdl != nullptr))
						{
							startnonce = strpbrk(startnonce, "0123456789");
							char *endnonce = strpbrk(startnonce, "& }\"");
							startdl = strpbrk(startdl, "0123456789");
							char *enddl = strpbrk(startdl, "& }\"");

							endaccountId[0] = 0;
							endnonce[0] = 0;
							enddl[0] = 0;

							get_accountId = _strtoui64(startaccountId, 0, 10);
							get_nonce = _strtoui64(startnonce, 0, 10);
							get_deadline = _strtoui64(startdl, 0, 10);

							if (starttotalsize != nullptr)
							{
								starttotalsize = strpbrk(starttotalsize, "0123456789");
								char *endtotalsize = strpbrk(starttotalsize, "& }\"");
								endtotalsize[0] = 0;
								get_totalsize = _strtoui64(starttotalsize, 0, 10);
								satellite_size.insert(std::pair <u_long, unsigned long long>(client_socket_address.sin_addr.S_un.S_addr, get_totalsize));
							}
							EnterCriticalSection(&sharesLock);
							shares.push_back({ client_address_str, get_accountId, get_deadline, get_nonce });
							LeaveCriticalSection(&sharesLock);

							_strtime_s(tbuffer);
							wattron(win_main, COLOR_PAIR(2));
							wprintw(win_main, "%s [%20llu]\treceived DL: %11llu {%s}\n", tbuffer, get_accountId, get_deadline / baseTarget, client_address_str, 0);
							wattroff(win_main, COLOR_PAIR(2));
							Log("Proxy: received DL "); Log_llu(get_deadline); Log(" from "); Log(client_address_str);

							//Подтверждаем
							RtlSecureZeroMemory(buffer, buffer_size);
							size_t acc = Get_index_acc(get_accountId);
							int bytes = sprintf_s(buffer, buffer_size, "HTTP/1.0 200 OK\r\nConnection: close\r\n\r\n{\"result\": \"proxy\",\"accountId\": %llu,\"deadline\": %llu,\"targetDeadline\": %llu}", get_accountId, get_deadline / baseTarget, bests[acc].targetDeadline);
							iResult = send(ClientSocket, buffer, bytes, 0);
							if (iResult == SOCKET_ERROR)
							{
								Log("\nProxy: ! Error sending to client: "); Log_u(WSAGetLastError());
								wattron(win_main, COLOR_PAIR(12));
								wprintw(win_main, "PROXY: failed sending to client: %ld\n", WSAGetLastError(), 0);
								wattroff(win_main, COLOR_PAIR(12));
							}
							else
							{
								if (use_debug)
								{
									_strtime_s(tbuffer);
									wattron(win_main, COLOR_PAIR(9));
									wprintw(win_main, "%s [%20llu]\tsent confirmation to %s\n", tbuffer, get_accountId, client_address_str, 0);
									wattroff(win_main, COLOR_PAIR(9));
								}
								Log("\nProxy: sent confirmation to "); Log(client_address_str);
							}
						}
					}
				}
				else
				{
					if (strstr(buffer, "getMiningInfo") != nullptr)
					{
						RtlSecureZeroMemory(buffer, buffer_size);
						int bytes = sprintf_s(buffer, buffer_size, "HTTP/1.0 200 OK\r\nConnection: close\r\n\r\n{\"baseTarget\":\"%llu\",\"height\":\"%llu\",\"generationSignature\":\"%s\",\"targetDeadline\":%llu}", baseTarget, height, str_signature, targetDeadlineInfo);
						iResult = send(ClientSocket, buffer, bytes, 0);
						if (iResult == SOCKET_ERROR)
						{
							Log("\nProxy: ! Error sending to client: "); Log_u(WSAGetLastError());
							wattron(win_main, COLOR_PAIR(12));
							wprintw(win_main, "PROXY: failed sending to client: %ld\n", WSAGetLastError(), 0);
							wattroff(win_main, COLOR_PAIR(12));
						}
						else
						{
							Log("\nProxy: sent update to "); Log(client_address_str);
						}
					}
					else
					{
						if ((strstr(buffer, "getBlocks") != nullptr) || (strstr(buffer, "getAccount") != nullptr) || (strstr(buffer, "getRewardRecipient") != nullptr))
						{
							; // ничего не делаем, не ошибка, пропускаем
						}
						else
						{
							find[0] = 0;
							wattron(win_main, COLOR_PAIR(15));
							wprintw(win_main, "PROXY: %s\n", buffer, 0);//You can crash the miner when the proxy is enabled and you open the address in a browser.  wprintw(win_main, "PROXY: %s\n", "Error", 0);
							wattroff(win_main, COLOR_PAIR(15));
						}
					}
				}
			}
			iResult = closesocket(ClientSocket);
		}
		std::this_thread::yield();
		std::this_thread::sleep_for(std::chrono::milliseconds(200));
	}
	HeapFree(hHeap, 0, buffer);
	HeapFree(hHeap, 0, tmp_buffer);
}

void send_i(void)
{
	Log("\nSender: started thread");
	SOCKET ConnectSocket;

	int iResult = 0;
	size_t const buffer_size = 1000;
	char* buffer = (char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, buffer_size);
	if (buffer == nullptr) ShowMemErrorExit();

	char tbuffer[9];

	struct addrinfo *result = nullptr;
	struct addrinfo hints;

	for (; !exit_flag;)
	{
		if (stopThreads == 1)
		{
			HeapFree(hHeap, 0, buffer);
			return;
		}

		for (auto iter = shares.begin(); iter != shares.end();)
		{

			//Гасим шару если она больше текущего targetDeadline, актуально для режима Proxy
			if ((iter->best / baseTarget) > bests[Get_index_acc(iter->account_id)].targetDeadline)
			{
				if (use_debug)
				{
					_strtime_s(tbuffer);
					wattron(win_main, COLOR_PAIR(4));
					wprintw(win_main, "%s [%20llu]\t%llu > %llu  discarded\n", tbuffer, iter->account_id, iter->best / baseTarget, bests[Get_index_acc(iter->account_id)].targetDeadline, 0);
					wattroff(win_main, COLOR_PAIR(4));
				}
				EnterCriticalSection(&sharesLock);
				iter = shares.erase(iter);
				LeaveCriticalSection(&sharesLock);
				continue;
			}

			RtlSecureZeroMemory(&hints, sizeof(hints));
			hints.ai_family = AF_INET;
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_protocol = IPPROTO_TCP;

			iResult = getaddrinfo(nodeaddr.c_str(), nodeport.c_str(), &hints, &result);
			if (iResult != 0) {
				if (network_quality > 0) network_quality--;
				wattron(win_main, COLOR_PAIR(12));
				wprintw(win_main, "SENDER: getaddrinfo failed with error: %d\n", iResult, 0);
				wattroff(win_main, COLOR_PAIR(12));
				continue;
			}
			ConnectSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
			if (ConnectSocket == INVALID_SOCKET) {
				if (network_quality > 0) network_quality--;
				wattron(win_main, COLOR_PAIR(12));
				wprintw(win_main, "SENDER: socket failed with error: %ld\n", WSAGetLastError(), 0);
				wattroff(win_main, COLOR_PAIR(12));
				freeaddrinfo(result);
				continue;
			}
			const unsigned t = 1000;
			setsockopt(ConnectSocket, SOL_SOCKET, SO_RCVTIMEO, (char *)&t, sizeof(unsigned));
			iResult = connect(ConnectSocket, result->ai_addr, (int)result->ai_addrlen);
			if (iResult == SOCKET_ERROR)
			{
				if (network_quality > 0) network_quality--;
				Log("\nSender:! Error Sender's connect: "); Log_u(WSAGetLastError());
				wattron(win_main, COLOR_PAIR(12));
				_strtime_s(tbuffer);
				wprintw(win_main, "%s SENDER: can't connect. Error: %ld\n", tbuffer, WSAGetLastError(), 0);
				wattroff(win_main, COLOR_PAIR(12));
				freeaddrinfo(result);
				continue;
			}
			else
			{
				freeaddrinfo(result);

				int bytes = 0;
				RtlSecureZeroMemory(buffer, buffer_size);
				if (miner_mode == 0)
				{
					bytes = sprintf_s(buffer, buffer_size, "POST /burst?requestType=submitNonce&secretPhrase=%s&nonce=%llu HTTP/1.0\r\nConnection: close\r\n\r\n", pass, iter->nonce);
				}
				if (miner_mode == 1)
				{
					unsigned long long total = total_size / 1024 / 1024 / 1024;
					for (auto It = satellite_size.begin(); It != satellite_size.end(); ++It) total = total + It->second;
					bytes = sprintf_s(buffer, buffer_size, "POST /burst?requestType=submitNonce&accountId=%llu&nonce=%llu&deadline=%llu HTTP/1.0\r\nHost: %s:%s\r\nX-Miner: Blago %s\r\nX-Capacity: %llu\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", iter->account_id, iter->nonce, iter->best, nodeaddr.c_str(), nodeport.c_str(), version, total);
				}

				// Sending to Server
				iResult = send(ConnectSocket, buffer, bytes, 0);
				if (iResult == SOCKET_ERROR)
				{
					if (network_quality > 0) network_quality--;
					Log("\nSender: ! Error deadline's sending: "); Log_u(WSAGetLastError());
					wattron(win_main, COLOR_PAIR(12));
					wprintw(win_main, "SENDER: send failed: %ld\n", WSAGetLastError(), 0);
					wattroff(win_main, COLOR_PAIR(12));
					continue;
				}
				else
				{
					unsigned long long dl = iter->best / baseTarget;
					_strtime_s(tbuffer);
					if (network_quality < 100) network_quality++;
					wattron(win_main, COLOR_PAIR(9));
					wprintw(win_main, "%s [%20llu] sent DL: %15llu %5llud %02llu:%02llu:%02llu\n", tbuffer, iter->account_id, dl, (dl) / (24 * 60 * 60), (dl % (24 * 60 * 60)) / (60 * 60), (dl % (60 * 60)) / 60, dl % 60, 0);
					wattroff(win_main, COLOR_PAIR(9));

					EnterCriticalSection(&sessionsLock);
					//sessions.push_back({ ConnectSocket, iter->account_id, dl, iter->best, iter->nonce });
					sessions.push_back({ ConnectSocket, dl, *iter });
					LeaveCriticalSection(&sessionsLock);

					bests[Get_index_acc(iter->account_id)].targetDeadline = dl;
					EnterCriticalSection(&sharesLock);
					iter = shares.erase(iter);
					LeaveCriticalSection(&sharesLock);
				}
			}
		}

		if (!sessions.empty())
		{
			EnterCriticalSection(&sessionsLock);
			for (auto iter = sessions.begin(); iter != sessions.end() && !stopThreads;)
			{
				ConnectSocket = iter->Socket;

				BOOL l = TRUE;
				iResult = ioctlsocket(ConnectSocket, FIONBIO, (unsigned long*)&l);
				if (iResult == SOCKET_ERROR)
				{
					if (network_quality > 0) network_quality--;
					Log("\nSender: ! Error ioctlsocket's: "); Log_u(WSAGetLastError());
					wattron(win_main, COLOR_PAIR(12));
					wprintw(win_main, "SENDER: ioctlsocket failed: %ld\n", WSAGetLastError(), 0);
					wattroff(win_main, COLOR_PAIR(12));
					continue;
				}
				RtlSecureZeroMemory(buffer, buffer_size);
				size_t  pos = 0;
				iResult = 0;
				do{
					iResult = recv(ConnectSocket, &buffer[pos], (int)(buffer_size - pos - 1), 0);
					if (iResult > 0) pos += (size_t)iResult;
				} while (iResult > 0);

				if (iResult == SOCKET_ERROR)
				{
					if (WSAGetLastError() != WSAEWOULDBLOCK) //разрыв соединения, молча переотправляем дедлайн
					{
						if (network_quality > 0) network_quality--;
						//wattron(win_main, COLOR_PAIR(6));
						//wprintw(win_main, "%s [%20llu] not confirmed DL %10llu\n", tbuffer, iter->body.account_id, iter->deadline, 0);
						//wattroff(win_main, COLOR_PAIR(6));
						Log("\nSender: ! Error getting confirmation for DL: "); Log_llu(iter->deadline);  Log("  code: "); Log_u(WSAGetLastError());
						iter = sessions.erase(iter);
						shares.push_back({ iter->body.file_name, iter->body.account_id, iter->body.best, iter->body.nonce });
					}
				}
				else //что-то получили от сервера
				{
					if (network_quality < 100) network_quality++;

					//получили пустую строку, переотправляем дедлайн
					if (buffer[0] == '\0')
					{
						Log("\nSender: zero-length message for DL: "); Log_llu(iter->deadline);
						shares.push_back({ iter->body.file_name, iter->body.account_id, iter->body.best, iter->body.nonce });
					}
					else //получили ответ пула
					{
						char *find = strstr(buffer, "{");
						if (find == nullptr)
						{
							find = strstr(buffer, "\r\n\r\n");
							if (find != nullptr) find = find + 4;
							else find = buffer;
						}

						unsigned long long ndeadline;
						unsigned long long naccountId = 0;
						unsigned long long ntargetDeadline = 0;
						rapidjson::Document answ;
						// burst.ninja        {"requestProcessingTime":0,"result":"success","block":216280,"deadline":304917,"deadlineString":"3 days, 12 hours, 41 mins, 57 secs","targetDeadline":304917}
						// pool.burst-team.us {"requestProcessingTime":0,"result":"success","block":227289,"deadline":867302,"deadlineString":"10 days, 55 mins, 2 secs","targetDeadline":867302}
						// proxy              {"result": "proxy","accountId": 17930413153828766298,"deadline": 1192922,"targetDeadline": 197503}
						if (!answ.Parse<0>(find).HasParseError())
						{
							if (answ.IsObject())
							{
								if (answ.HasMember("deadline")) {
									if (answ["deadline"].IsString())	ndeadline = _strtoui64(answ["deadline"].GetString(), 0, 10);
									else
										if (answ["deadline"].IsInt64()) ndeadline = answ["deadline"].GetInt64();
									Log("\nSender: confirmed deadline: "); Log_llu(ndeadline);

									if (answ.HasMember("targetDeadline")) {
										if (answ["targetDeadline"].IsString())	ntargetDeadline = _strtoui64(answ["targetDeadline"].GetString(), 0, 10);
										else
											if (answ["targetDeadline"].IsInt64()) ntargetDeadline = answ["targetDeadline"].GetInt64();
									}
									if (answ.HasMember("accountId")) {
										if (answ["accountId"].IsString())	naccountId = _strtoui64(answ["accountId"].GetString(), 0, 10);
										else
											if (answ["accountId"].IsInt64()) naccountId = answ["accountId"].GetInt64();
									}

									unsigned long long days = (ndeadline) / (24 * 60 * 60);
									unsigned hours = (ndeadline % (24 * 60 * 60)) / (60 * 60);
									unsigned min = (ndeadline % (60 * 60)) / 60;
									unsigned sec = ndeadline % 60;
									_strtime_s(tbuffer);
									wattron(win_main, COLOR_PAIR(10));
									if ((naccountId != 0) && (ntargetDeadline != 0))
									{
										EnterCriticalSection(&bestsLock);
										bests[Get_index_acc(naccountId)].targetDeadline = ntargetDeadline;
										LeaveCriticalSection(&bestsLock);
										wprintw(win_main, "%s [%20llu] confirmed DL: %10llu %5llud %02u:%02u:%02u\n", tbuffer, naccountId, ndeadline, days, hours, min, sec, 0);
										if (use_debug) wprintw(win_main, "%s [%20llu] set targetDL: %10llu\n", tbuffer, naccountId, ntargetDeadline, 0);
									}
									else wprintw(win_main, "%s [%20llu] confirmed DL: %10llu %5llud %02u:%02u:%02u\n", tbuffer, iter->body.account_id, ndeadline, days, hours, min, sec, 0);
									wattroff(win_main, COLOR_PAIR(10));
									if (ndeadline < deadline || deadline == 0)  deadline = ndeadline;

									if (ndeadline != iter->deadline)
									{
										wattron(win_main, COLOR_PAIR(6));
										wprintw(win_main, "----Fast block or corrupted file?----\nSent deadline:\t%llu\nServer's deadline:\t%llu \n----\n", iter->deadline, ndeadline, 0); //shares[i].file_name.c_str());
										wattroff(win_main, COLOR_PAIR(6));
									}
								}
								else{
									if (answ.HasMember("errorDescription")) {
										wattron(win_main, COLOR_PAIR(15));
										wprintw(win_main, "[ERROR %u] %s\n", answ["errorCode"].GetInt(), answ["errorDescription"].GetString(), 0);
										wattroff(win_main, COLOR_PAIR(15));
										wattron(win_main, COLOR_PAIR(12));
										if (answ["errorCode"].GetInt() == 1004) wprintw(win_main, "You need change reward assignment and wait 4 blocks (~16 minutes)\n"); //error 1004
										wattroff(win_main, COLOR_PAIR(12));
									}
									else {
										wattron(win_main, COLOR_PAIR(15));
										wprintw(win_main, "%s\n", find);
										wattroff(win_main, COLOR_PAIR(15));
									}
								}
							}
						}
						else
						{
							if (strstr(find, "Received share") != nullptr)
							{
								_strtime_s(tbuffer);
								deadline = bests[Get_index_acc(iter->body.account_id)].DL; //может лучше iter->deadline ?
								// if(deadline > iter->deadline) deadline = iter->deadline;
								wattron(win_main, COLOR_PAIR(10));
								wprintw(win_main, "%s [%20llu] confirmed DL   %10llu\n", tbuffer, iter->body.account_id, iter->deadline, 0);
								wattroff(win_main, COLOR_PAIR(10));
							}
							else //получили нераспознанный ответ
							{
								int minor_version;
								int status = 0;
								const char *msg;
								size_t msg_len;
								struct phr_header headers[12];
								size_t num_headers = sizeof(headers) / sizeof(headers[0]);
								phr_parse_response(buffer, strlen(buffer), &minor_version, &status, &msg, &msg_len, headers, &num_headers, 0);

								if (status != 0)
								{
									wattron(win_main, COLOR_PAIR(6));
									//wprintw(win_main, "%s [%20llu] NOT confirmed DL %10llu\n", tbuffer, iter->body.account_id, iter->deadline, 0);
									std::string error_str(msg, msg_len);
									wprintw(win_main, "Server error: %d %s\n", status, error_str.c_str());
									wattroff(win_main, COLOR_PAIR(6));
									Log("\nSender: Server error for DL: "); Log_llu(iter->deadline);
									shares.push_back({ iter->body.file_name, iter->body.account_id, iter->body.best, iter->body.nonce });
								}
								else //получили непонятно что
								{
									wattron(win_main, COLOR_PAIR(7));
									wprintw(win_main, "%s\n", buffer);
									wattroff(win_main, COLOR_PAIR(7));
								}
							}
						}
					}
					iResult = closesocket(ConnectSocket);
					Log("\nSender: Close socket. Code = "); Log_u(WSAGetLastError());
					iter = sessions.erase(iter);
				}
				if (iter != sessions.end()) ++iter;
			}
			LeaveCriticalSection(&sessionsLock);
		}
		std::this_thread::yield();
		std::this_thread::sleep_for(std::chrono::milliseconds(send_interval));
	}
	HeapFree(hHeap, 0, buffer);
	return;
}

void procscoop_m_4(unsigned long long const nonce, unsigned long long const n, char const *const data, size_t const acc, const std::string &file_name) {
	char const *cache;
	char sig0[32 + 64];
	char sig1[32 + 64];
	char sig2[32 + 64];
	char sig3[32 + 64];
	cache = data;

	memcpy(sig0, signature, 32);
	memcpy(sig1, signature, 32);
	memcpy(sig2, signature, 32);
	memcpy(sig3, signature, 32);

	char res0[32];
	char res1[32];
	char res2[32];
	char res3[32];
	unsigned posn;
	mshabal_context x, init_x;
	avx1_mshabal_init(&init_x, 256);

	for (unsigned long long v = 0; v < n; v += 4)
	{
		memcpy(&sig0[32], &cache[(v + 0) * 64], 64);
		memcpy(&sig1[32], &cache[(v + 1) * 64], 64);
		memcpy(&sig2[32], &cache[(v + 2) * 64], 64);
		memcpy(&sig3[32], &cache[(v + 3) * 64], 64);

		memcpy(&x, &init_x, sizeof(init_x)); // optimization: avx1_mshabal_init(&x, 256);
		avx1_mshabal(&x, (const unsigned char*)sig0, (const unsigned char*)sig1, (const unsigned char*)sig2, (const unsigned char*)sig3, 64 + 32);
		avx1_mshabal_close(&x, 0, 0, 0, 0, 0, res0, res1, res2, res3);

		unsigned long long *wertung = (unsigned long long*)res0;
		unsigned long long *wertung1 = (unsigned long long*)res1;
		unsigned long long *wertung2 = (unsigned long long*)res2;
		unsigned long long *wertung3 = (unsigned long long*)res3;
		posn = 0;
		if (*wertung1 < *wertung)
		{
			*wertung = *wertung1;
			posn = 1;
		}
		if (*wertung2 < *wertung)
		{
			*wertung = *wertung2;
			posn = 2;
		}
		if (*wertung3 < *wertung)
		{
			*wertung = *wertung3;
			posn = 3;
		}


		if ((*wertung / baseTarget) <= bests[acc].targetDeadline)
		{
			if (bests[acc].nonce == 0 || *wertung < bests[acc].best)
			{
				Log("\nfound deadline=");	Log_llu(*wertung / baseTarget); Log(" nonce=");	Log_llu(nonce + v + posn); Log(" for account: "); Log_llu(bests[acc].account_id); Log(" file: "); Log((char*)file_name.c_str());
				EnterCriticalSection(&bestsLock);
				bests[acc].best = *wertung;
				bests[acc].nonce = nonce + v + posn;
				bests[acc].DL = *wertung / baseTarget;
				LeaveCriticalSection(&bestsLock);
				EnterCriticalSection(&sharesLock);
				shares.push_back({ file_name, bests[acc].account_id, bests[acc].best, bests[acc].nonce });
				LeaveCriticalSection(&sharesLock);
				if (use_debug)
				{
					char tbuffer[9];
					_strtime_s(tbuffer);
					wattron(win_main, COLOR_PAIR(2));
					wprintw(win_main, "%s [%20llu] found DL:      %9llu\n", tbuffer, bests[acc].account_id, bests[acc].DL, 0);
					wattroff(win_main, COLOR_PAIR(2));
				}
			}
		}
	}
}

void procscoop_m256_8(unsigned long long const nonce, unsigned long long const n, char const *const data, size_t const acc, const std::string &file_name) {
	char const *cache;
	char sig0[32 + 64];
	char sig1[32 + 64];
	char sig2[32 + 64];
	char sig3[32 + 64];
	char sig4[32 + 64];
	char sig5[32 + 64];
	char sig6[32 + 64];
	char sig7[32 + 64];
	char res0[32];
	char res1[32];
	char res2[32];
	char res3[32];
	char res4[32];
	char res5[32];
	char res6[32];
	char res7[32];
	cache = data;
	unsigned long long v;

	memmove(sig0, signature, 32);
	memmove(sig1, signature, 32);
	memmove(sig2, signature, 32);
	memmove(sig3, signature, 32);
	memmove(sig4, signature, 32);
	memmove(sig5, signature, 32);
	memmove(sig6, signature, 32);
	memmove(sig7, signature, 32);

	mshabal256_context x, init_x;
	mshabal256_init(&init_x, 256);

	for (v = 0; v < n; v += 8) {
		memmove(&sig0[32], &cache[(v + 0) * 64], 64);
		memmove(&sig1[32], &cache[(v + 1) * 64], 64);
		memmove(&sig2[32], &cache[(v + 2) * 64], 64);
		memmove(&sig3[32], &cache[(v + 3) * 64], 64);
		memmove(&sig4[32], &cache[(v + 4) * 64], 64);
		memmove(&sig5[32], &cache[(v + 5) * 64], 64);
		memmove(&sig6[32], &cache[(v + 6) * 64], 64);
		memmove(&sig7[32], &cache[(v + 7) * 64], 64);

		memcpy(&x, &init_x, sizeof(init_x)); // optimization: mshabal256_init(&x, 256);
		mshabal256(&x, (const unsigned char*)sig0, (const unsigned char*)sig1, (const unsigned char*)sig2, (const unsigned char*)sig3, (const unsigned char*)sig4, (const unsigned char*)sig5, (const unsigned char*)sig6, (const unsigned char*)sig7, 64 + 32);
		mshabal256_close(&x, 0, 0, 0, 0, 0, 0, 0, 0, 0, res0, res1, res2, res3, res4, res5, res6, res7);

		unsigned long long *wertung = (unsigned long long*)res0;
		unsigned long long *wertung1 = (unsigned long long*)res1;
		unsigned long long *wertung2 = (unsigned long long*)res2;
		unsigned long long *wertung3 = (unsigned long long*)res3;
		unsigned long long *wertung4 = (unsigned long long*)res4;
		unsigned long long *wertung5 = (unsigned long long*)res5;
		unsigned long long *wertung6 = (unsigned long long*)res6;
		unsigned long long *wertung7 = (unsigned long long*)res7;
		unsigned posn = 0;
		if (*wertung1 < *wertung)
		{
			*wertung = *wertung1;
			posn = 1;
		}
		if (*wertung2 < *wertung)
		{
			*wertung = *wertung2;
			posn = 2;
		}
		if (*wertung3 < *wertung)
		{
			*wertung = *wertung3;
			posn = 3;
		}
		if (*wertung4 < *wertung)
		{
			*wertung = *wertung4;
			posn = 4;
		}
		if (*wertung5 < *wertung)
		{
			*wertung = *wertung5;
			posn = 5;
		}
		if (*wertung6 < *wertung)
		{
			*wertung = *wertung6;
			posn = 6;
		}
		if (*wertung7 < *wertung)
		{
			*wertung = *wertung7;
			posn = 7;
		}

		if ((*wertung / baseTarget) <= bests[acc].targetDeadline)
		{
			if (bests[acc].nonce == 0 || *wertung < bests[acc].best)
			{
				Log("\nfound deadline=");	Log_llu(*wertung / baseTarget); Log(" nonce=");	Log_llu(nonce + v + posn); Log(" for account: "); Log_llu(bests[acc].account_id); Log(" file: "); Log((char*)file_name.c_str());
				EnterCriticalSection(&bestsLock);
				bests[acc].best = *wertung;
				bests[acc].nonce = nonce + v + posn;
				bests[acc].DL = *wertung / baseTarget;
				LeaveCriticalSection(&bestsLock);
				EnterCriticalSection(&sharesLock);
				shares.push_back({ file_name, bests[acc].account_id, bests[acc].best, bests[acc].nonce });
				LeaveCriticalSection(&sharesLock);
				if (use_debug)
				{
					char tbuffer[9];
					_strtime_s(tbuffer);
					wattron(win_main, COLOR_PAIR(2));
					wprintw(win_main, "%s [%20llu] found DL:      %9llu\n", tbuffer, bests[acc].account_id, bests[acc].DL, 0);
					wattroff(win_main, COLOR_PAIR(2));
				}
			}
		}
	}
}

void procscoop_sph(const unsigned long long nonce, const unsigned long long n, char const *const data, const size_t acc, const std::string &file_name) {
	char const *cache;
	char sig[32 + 64];
	cache = data;
	char res[32];
	memcpy_s(sig, sizeof(sig), signature, sizeof(char) * 32);

	sph_shabal_context x, init_x;
	sph_shabal256_init(&init_x);
	for (unsigned long long v = 0; v < n; v++)
	{
		memcpy_s(&sig[32], sizeof(sig) - 32, &cache[v * 64], sizeof(char) * 64);

		memcpy(&x, &init_x, sizeof(init_x)); // optimization: sph_shabal256_init(&x);
		sph_shabal256(&x, (const unsigned char*)sig, 64 + 32);
		sph_shabal256_close(&x, res);

		unsigned long long *wertung = (unsigned long long*)res;

		if ((*wertung / baseTarget) <= bests[acc].targetDeadline)
		{
			if (bests[acc].nonce == 0 || *wertung < bests[acc].best)
			{
				Log("\nfound deadline=");	Log_llu(*wertung / baseTarget); Log(" nonce=");	Log_llu(nonce + v); Log(" for account: "); Log_llu(bests[acc].account_id); Log(" file: "); Log((char*)file_name.c_str());
				EnterCriticalSection(&bestsLock);
				bests[acc].best = *wertung;
				bests[acc].nonce = nonce + v;
				bests[acc].DL = *wertung / baseTarget;
				LeaveCriticalSection(&bestsLock);
				EnterCriticalSection(&sharesLock);
				shares.push_back({ file_name, bests[acc].account_id, bests[acc].best, bests[acc].nonce });
				LeaveCriticalSection(&sharesLock);
				if (use_debug)
				{
					char tbuffer[9];
					_strtime_s(tbuffer);
					wattron(win_main, COLOR_PAIR(2));
					wprintw(win_main, "%s [%20llu] found DL:      %9llu\n", tbuffer, bests[acc].account_id, bests[acc].DL, 0);
					wattroff(win_main, COLOR_PAIR(2));
				}
			}
		}
	}
}

void procscoop_asm(const unsigned long long nonce, const unsigned long long n, char const *const data, const size_t acc, const std::string &file_name) {
	char const *cache;
	char sig[32 + 64];
	cache = data;
	char res[32];
	memcpy_s(sig, sizeof(sig), signature, sizeof(char) * 32);
	asm_shabal_context x;
	for (unsigned long long v = 0; v < n; v++)
	{
		memcpy_s(&sig[32], sizeof(sig) - 32, &cache[v * 64], sizeof(char) * 64);

		asm_shabal_init(&x, 256);
		asm_shabal(&x, (const unsigned char*)sig, 64 + 32);
		asm_shabal_close(&x, 0, 0, res);

		unsigned long long *wertung = (unsigned long long*)res;

		if ((*wertung / baseTarget) <= bests[acc].targetDeadline)
		{
			if (bests[acc].nonce == 0 || *wertung < bests[acc].best)
			{
				Log("\nfound deadline=");	Log_llu(*wertung / baseTarget); Log(" nonce=");	Log_llu(nonce + v); Log(" for account: "); Log_llu(bests[acc].account_id); Log(" file: "); Log((char*)file_name.c_str());
				EnterCriticalSection(&bestsLock);
				bests[acc].best = *wertung;
				bests[acc].nonce = nonce + v;
				bests[acc].DL = *wertung / baseTarget;
				LeaveCriticalSection(&bestsLock);
				EnterCriticalSection(&sharesLock);
				shares.push_back({ file_name, bests[acc].account_id, bests[acc].best, bests[acc].nonce });
				LeaveCriticalSection(&sharesLock);
				if (use_debug)
				{
					char tbuffer[9];
					_strtime_s(tbuffer);
					wattron(win_main, COLOR_PAIR(2));
					wprintw(win_main, "%s [%20llu] found DL:      %9llu\n", tbuffer, bests[acc].account_id, bests[acc].DL, 0);
					wattroff(win_main, COLOR_PAIR(2));
				}
			}
		}
	}
}

void work_i(const size_t local_num) {

	__int64 start_work_time, end_work_time;
	__int64 start_time_read, end_time_read;
	__int64 start_time_proc;
	double sum_time_proc = 0;
	LARGE_INTEGER li;
	QueryPerformanceFrequency(&li);
	double const pcFreq = double(li.QuadPart);
	QueryPerformanceCounter((LARGE_INTEGER*)&start_work_time);

	if (use_boost)
	{
		//SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
		//SetThreadAffinityMask(GetCurrentThread(), 1 << (int)(working_threads));
		SetThreadIdealProcessor(GetCurrentThread(), (DWORD)(local_num % std::thread::hardware_concurrency()));
	}

	std::string const path_loc_str = paths_dir[local_num];
	unsigned long long files_size_per_thread = 0;

	Log("\nStart thread: ["); Log_llu(local_num); Log("]  ");	Log((char*)path_loc_str.c_str());

	std::vector<t_files> files;
	GetFiles(path_loc_str, &files);

	size_t cache_size_local;
	DWORD sectorsPerCluster;
	DWORD bytesPerSector;
	DWORD numberOfFreeClusters;
	DWORD totalNumberOfClusters;

	for (auto iter = files.begin(); iter != files.end(); ++iter)
	{
		unsigned long long key, nonce, nonces, stagger, tail;
		QueryPerformanceCounter((LARGE_INTEGER*)&start_time_read);
		key = iter->Key;
		nonce = iter->StartNonce;
		nonces = iter->Nonces;
		stagger = iter->Stagger;
		tail = 0;
		// Проверка кратности нонсов стаггеру
		if ((double)(nonces % stagger) > DBL_EPSILON)
		{
			wattron(win_main, COLOR_PAIR(12));
			wprintw(win_main, "File %s wrong stagger?\n", iter->Name.c_str(), 0);
			wattroff(win_main, COLOR_PAIR(12));
		}

		// Проверка на повреждения плота
		if (nonces != (iter->Size) / (4096 * 64))
		{
			wattron(win_main, COLOR_PAIR(12));
			wprintw(win_main, "file \"%s\" name/size mismatch\n", iter->Name.c_str(), 0);
			wattroff(win_main, COLOR_PAIR(12));
			if (nonces != stagger)
				nonces = (((iter->Size) / (4096 * 64)) / stagger) * stagger; //обрезаем плот по размеру и стаггеру
			else
				if (scoop > (iter->Size) / (stagger * 64)) //если номер скупа попадает в поврежденный смерженный плот, то пропускаем
				{
					wattron(win_main, COLOR_PAIR(12));
					wprintw(win_main, "skipped\n", 0);
					wattroff(win_main, COLOR_PAIR(12));
					continue;
				}
		}

		if (!GetDiskFreeSpaceA((iter->Path).c_str(), &sectorsPerCluster, &bytesPerSector, &numberOfFreeClusters, &totalNumberOfClusters))
		{
			wattron(win_main, COLOR_PAIR(12));
			wprintw(win_main, "GetDiskFreeSpace failed\n", 0);
			wattroff(win_main, COLOR_PAIR(12));
			continue;
		}

		// Если стаггер в плоте меньше чем размер сектора - пропускаем
		if ((stagger * 64) < bytesPerSector)
		{
			wattron(win_main, COLOR_PAIR(12));
			wprintw(win_main, "stagger (%llu) must be >= %llu\n", stagger, bytesPerSector / 64, 0);
			wattroff(win_main, COLOR_PAIR(12));
			continue;
		}

		// Если нонсов в плоте меньше чем размер сектора - пропускаем
		if ((nonces * 64) < bytesPerSector)
		{
			wattron(win_main, COLOR_PAIR(12));
			wprintw(win_main, "nonces (%llu) must be >= %llu\n", nonces, bytesPerSector / 64, 0);
			wattroff(win_main, COLOR_PAIR(12));
			continue;
		}

		// Если стаггер не выровнен по сектору - можем читать сдвигая последний стагер назад (доделать)
		if ((stagger % (bytesPerSector / 64)) != 0)
		{
			wattron(win_main, COLOR_PAIR(12));
			wprintw(win_main, "stagger (%llu) must be a multiple of %llu\n", stagger, bytesPerSector / 64, 0);
			//unsigned long long new_stagger = (stagger / (bytesPerSector / 64)) * (bytesPerSector / 64);
			//tail = stagger - new_stagger;
			//stagger = new_stagger;
			//nonces = (nonces/stagger) * stagger;
			//Нужно добавить остаток от предыдущего значения стаггера для компенсации сдвига по нонсам
			//wprintw(win_main, "stagger changed to %llu\n", stagger, 0);
			//wprintw(win_main, "nonces changed to %llu\n", nonces, 0);
			wattroff(win_main, COLOR_PAIR(12));
			//continue;
		}


		if ((stagger == nonces) && (cache_size < stagger)) cache_size_local = cache_size;  // оптимизированный плот
		else cache_size_local = stagger; // обычный плот

		// Выравниваем cache_size_local по размеру сектора
		cache_size_local = (cache_size_local / (size_t)(bytesPerSector / 64)) * (size_t)(bytesPerSector / 64);
		//wprintw(win_main, "round: %llu\n", cache_size_local);


		char *cache = (char *)VirtualAlloc(nullptr, cache_size_local * 64, MEM_COMMIT, PAGE_READWRITE);
		if (cache == nullptr) ShowMemErrorExit();

		Log("\nRead file : ");	Log((char*)iter->Name.c_str());

		//wprintw(win_main, "%S \n", str2wstr(iter->Path + iter->Name).c_str());
		HANDLE ifile = CreateFileA((iter->Path + iter->Name).c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, nullptr);
		if (ifile == INVALID_HANDLE_VALUE)
		{
			wattron(win_main, COLOR_PAIR(12));
			wprintw(win_main, "File \"%s\" error opening. code = %llu\n", iter->Name.c_str(), GetLastError(), 0);
			wattroff(win_main, COLOR_PAIR(12));
			VirtualFree(cache, 0, MEM_RELEASE);
			continue;
		}
		files_size_per_thread += iter->Size;

		unsigned long long start, bytes;
		DWORD b = 0;
		LARGE_INTEGER liDistanceToMove;

		size_t acc = Get_index_acc(key);
		for (unsigned long long n = 0; n < nonces; n += stagger)
		{
			start = n * 4096 * 64 + scoop * stagger * 64;
			for (unsigned long long i = 0; i < stagger; i += cache_size_local)
			{
				if (i + cache_size_local > stagger)
				{
					cache_size_local = stagger - i;  // остаток
#ifdef __AVX2__
					if (cache_size_local < 8)
					{
						wattron(win_main, COLOR_PAIR(12));
						wprintw(win_main, "WARNING: %llu\n", cache_size_local);
						wattroff(win_main, COLOR_PAIR(12));
					}
#else
#ifdef __AVX__
					if (cache_size_local < 4)
					{
						wattron(win_main, COLOR_PAIR(12));
						wprintw(win_main, "WARNING: %llu\n", cache_size_local);
						wattroff(win_main, COLOR_PAIR(12));
					}
#endif
#endif
				}
				bytes = 0;
				b = 0;
				liDistanceToMove.QuadPart = start + i * 64;
				if (!SetFilePointerEx(ifile, liDistanceToMove, nullptr, FILE_BEGIN))
				{
					wprintw(win_main, "error SetFilePointerEx. code = %llu\n", GetLastError(), 0);
					continue;
				}

				do {
					if (!ReadFile(ifile, &cache[bytes], (DWORD)(cache_size_local * 64), &b, NULL))
					{
						wattron(win_main, COLOR_PAIR(12));
						wprintw(win_main, "error ReadFile. code = %llu\n", GetLastError(), 0);
						wattroff(win_main, COLOR_PAIR(12));
						break;
					}
					bytes += b;
					//wprintw(win_main, "%llu   %llu\n", bytes, readsize);
				} while (bytes < cache_size_local * 64);

				if (bytes == cache_size_local * 64)
				{
					QueryPerformanceCounter((LARGE_INTEGER*)&start_time_proc);
#ifdef __AVX2__
					procscoop_m256_8(n + nonce + i, cache_size_local, cache, acc, iter->Name);// Process block AVX2
#else
#ifdef __AVX__
					procscoop_m_4(n + nonce + i, cache_size_local, cache, acc, iter->Name);// Process block AVX
#else
					procscoop_sph(n + nonce + i, cache_size_local, cache, acc, iter->Name);// Process block SSE4
#endif
#endif
					QueryPerformanceCounter(&li);
					sum_time_proc += (double)(li.QuadPart - start_time_proc);
					worker_progress[local_num].Reads_bytes += bytes;

				}
				else
				{
					wattron(win_main, COLOR_PAIR(12));
					wprintw(win_main, "Unexpected end of file %s\n", iter->Name.c_str(), 0);
					wattroff(win_main, COLOR_PAIR(12));
					break;
				}

				if (stopThreads) // New block while processing: Stop.
				{
					worker_progress[local_num].isAlive = false;
					Log("\nReading file: ");	Log((char*)iter->Name.c_str()); Log(" interrupted");
					CloseHandle(ifile);
					files.clear();
					VirtualFree(cache, 0, MEM_RELEASE);
					//if (use_boost) SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
					return;
				}
				}
			}
		QueryPerformanceCounter((LARGE_INTEGER*)&end_time_read);
		Log("\nClose file: ");	Log((char*)iter->Name.c_str()); Log(" [@ "); Log_llu((long long unsigned)((double)(end_time_read - start_time_read) * 1000 / pcFreq)); Log(" ms]");
		CloseHandle(ifile);
		VirtualFree(cache, 0, MEM_RELEASE);
		}
	worker_progress[local_num].isAlive = false;
	QueryPerformanceCounter((LARGE_INTEGER*)&end_work_time);

	//if (use_boost) SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);

	double thread_time = (double)(end_work_time - start_work_time) / pcFreq;
	if (use_debug)
	{
		char tbuffer[9];
		_strtime_s(tbuffer);
		wattron(win_main, COLOR_PAIR(7));
		wprintw(win_main, "%s Thread \"%s\" @ %.1f sec (%.1f MB/s) CPU %.2f%%\n", tbuffer, path_loc_str.c_str(), thread_time, (double)(files_size_per_thread) / thread_time / 1024 / 1024 / 4096, sum_time_proc / pcFreq * 100 / thread_time, 0);
		wattroff(win_main, COLOR_PAIR(7));
	}
	return;
	}

char* GetJSON(char const *const req) {
	const unsigned BUF_SIZE = 1024;

	char *buffer = (char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, BUF_SIZE);
	if (buffer == nullptr) ShowMemErrorExit();

	char *find = nullptr;
	unsigned long long msg_len = 0;
	int iResult = 0;
	struct addrinfo *result = nullptr;
	struct addrinfo hints;
	SOCKET WalletSocket = INVALID_SOCKET;

	char *json = nullptr;

	RtlSecureZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	iResult = getaddrinfo(infoaddr.c_str(), infoport.c_str(), &hints, &result);
	if (iResult != 0) {
		wattron(win_main, COLOR_PAIR(12));
		wprintw(win_main, "WINNER: Getaddrinfo failed with error: %d\n", iResult, 0);
		wattroff(win_main, COLOR_PAIR(12));
		Log("\nWinner: getaddrinfo error");
	}
	else
	{
		WalletSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
		if (WalletSocket == INVALID_SOCKET)
		{
			wattron(win_main, COLOR_PAIR(12));
			wprintw(win_main, "WINNER: Socket function failed with error: %ld\n", WSAGetLastError(), 0);
			wattroff(win_main, COLOR_PAIR(12));
			Log("\nWinner: Socket error: "); Log_u(WSAGetLastError());
		}
		else
		{
			unsigned t = 3000;
			setsockopt(WalletSocket, SOL_SOCKET, SO_RCVTIMEO, (char *)&t, sizeof(unsigned));
			iResult = connect(WalletSocket, result->ai_addr, (int)result->ai_addrlen);
			if (iResult == SOCKET_ERROR) {
				wattron(win_main, COLOR_PAIR(12));
				wprintw(win_main, "WINNER: Connect function failed with error: %ld\n", WSAGetLastError(), 0);
				wattroff(win_main, COLOR_PAIR(12));
				Log("\nWinner: Connect Server error "); Log_u(WSAGetLastError());
			}
			else
			{
				iResult = send(WalletSocket, req, (int)strlen(req), 0);
				if (iResult == SOCKET_ERROR)
				{
					wattron(win_main, COLOR_PAIR(12));
					wprintw(win_main, "WINNER: Send request failed: %ld\n", WSAGetLastError(), 0);
					wattroff(win_main, COLOR_PAIR(12));
					Log("\nWinner: Error sending request: "); Log_u(WSAGetLastError());
				}
				else
				{
					char *tmp_buffer;
					unsigned long long msg_len = 0;
					int iReceived_size = 0;
					while ((iReceived_size = recv(WalletSocket, buffer + msg_len, BUF_SIZE - 1, 0)) > 0)
					{
						msg_len = msg_len + iReceived_size;
						Log("\nrealloc: ");
						tmp_buffer = (char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, msg_len + BUF_SIZE);
						if (tmp_buffer == nullptr) ShowMemErrorExit();
						memcpy(tmp_buffer, buffer, msg_len);
						HeapFree(hHeap, 0, buffer);
						buffer = tmp_buffer;
						buffer[msg_len + 1] = 0;
						Log_llu(msg_len);
					}

					if (iReceived_size < 0)
					{
						wattron(win_main, COLOR_PAIR(12));
						wprintw(win_main, "WINNER: Get info failed: %ld\n", WSAGetLastError(), 0);
						wattroff(win_main, COLOR_PAIR(12));
						Log("\nWinner: Error response: "); Log_u(WSAGetLastError());
					}
					else
					{
						find = strstr(buffer, "\r\n\r\n");
						if (find != nullptr)
						{
							json = (char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, msg_len);
							if (json == nullptr) ShowMemErrorExit();
							sprintf_s(json, HeapSize(hHeap, 0, json), "%s", find + 4 * sizeof(char));
						}
					} // recv() != SOCKET_ERROR
				} //send() != SOCKET_ERROR
			} // Connect() != SOCKET_ERROR
		} // socket() != INVALID_SOCKET
		iResult = closesocket(WalletSocket);
	} // getaddrinfo() == 0
	HeapFree(hHeap, 0, buffer);
	freeaddrinfo(result);
	return json;
}

void GetBlockInfo(unsigned const num_block)
{
	char* generator = nullptr;
	char* generatorRS = nullptr;
	unsigned long long last_block_height = 0;
	char* name = nullptr;
	char* rewardRecipient = nullptr;
	char* pool_accountRS = nullptr;
	char* pool_name = nullptr;
	unsigned long long timestamp0 = 0;
	unsigned long long timestamp1 = 0;
	char tbuffer[9];
	char* json;
	// Запрос двух последних блоков из блокчейна

	char* str_req = (char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_PATH);
	if (str_req == nullptr) ShowMemErrorExit();
	sprintf_s(str_req, HeapSize(hHeap, 0, str_req), "POST /burst?requestType=getBlocks&firstIndex=%u&lastIndex=%u HTTP/1.0\r\nConnection: close\r\n\r\n", num_block, num_block + 1);
	json = GetJSON(str_req);
	//Log("\n getBlocks: ");

	if (json == nullptr)	Log("\n-! error in message from pool (getBlocks)\n");
	else
	{
		rapidjson::Document doc_block;
		if (doc_block.Parse<0>(json).HasParseError() == false)
		{
			const Value& blocks = doc_block["blocks"];
			if (blocks.IsArray())
			{
				const Value& bl_0 = blocks[SizeType(0)];
				const Value& bl_1 = blocks[SizeType(1)];
				generatorRS = (char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, strlen(bl_0["generatorRS"].GetString()) + 1);
				if (generatorRS == nullptr) ShowMemErrorExit();
				strcpy_s(generatorRS, HeapSize(hHeap, 0, generatorRS), bl_0["generatorRS"].GetString());
				generator = (char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, strlen(bl_0["generator"].GetString()) + 1);
				if (generator == nullptr) ShowMemErrorExit();
				strcpy_s(generator, HeapSize(hHeap, 0, generator), bl_0["generator"].GetString());
				last_block_height = bl_0["height"].GetUint();
				timestamp0 = bl_0["timestamp"].GetUint64();
				timestamp1 = bl_1["timestamp"].GetUint64();
			}
		}
		else Log("\n- error parsing JSON getBlocks");
	}
	HeapFree(hHeap, 0, str_req);
	if (json != nullptr) HeapFree(hHeap, 0, json);

	if ((generator != nullptr) && (generatorRS != nullptr) && (timestamp0 != 0) && (timestamp1 != 0))
		if (last_block_height == height - 1)
		{
			// Запрос данных аккаунта
			str_req = (char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_PATH);
			if (str_req == nullptr) ShowMemErrorExit();
			sprintf_s(str_req, HeapSize(hHeap, 0, str_req), "POST /burst?requestType=getAccount&account=%s HTTP/1.0\r\nConnection: close\r\n\r\n", generator);
			json = GetJSON(str_req);
			//Log("\n getAccount: ");

			if (json == nullptr)	Log("\n- error in message from pool (getAccount)\n");
			else
			{
				rapidjson::Document doc_acc;
				if (doc_acc.Parse<0>(json).HasParseError() == false)
				{
					if (doc_acc.HasMember("name"))
					{
						name = (char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, strlen(doc_acc["name"].GetString()) + 1);
						if (name == nullptr) ShowMemErrorExit();
						strcpy_s(name, HeapSize(hHeap, 0, name), doc_acc["name"].GetString());
					}
				}
				else Log("\n- error parsing JSON getAccount");
			}
			HeapFree(hHeap, 0, str_req);
			if (json != nullptr) HeapFree(hHeap, 0, json);

			// Запрос RewardAssighnment по данному аккаунту
			str_req = (char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_PATH);
			if (str_req == nullptr) ShowMemErrorExit();
			sprintf_s(str_req, HeapSize(hHeap, 0, str_req), "POST /burst?requestType=getRewardRecipient&account=%s HTTP/1.0\r\nConnection: close\r\n\r\n", generator);
			json = GetJSON(str_req);
			HeapFree(hHeap, 0, str_req);
			//Log("\n getRewardRecipient: ");

			if (json == nullptr)	Log("\n- error in message from pool (getRewardRecipient)\n");
			else
			{
				rapidjson::Document doc_reward;
				if (doc_reward.Parse<0>(json).HasParseError() == false)
				{
					if (doc_reward.HasMember("rewardRecipient"))
					{
						rewardRecipient = (char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, strlen(doc_reward["rewardRecipient"].GetString()) + 1);
						if (rewardRecipient == nullptr) ShowMemErrorExit();
						strcpy_s(rewardRecipient, HeapSize(hHeap, 0, rewardRecipient), doc_reward["rewardRecipient"].GetString());
					}
				}
				else Log("\n-! error parsing JSON getRewardRecipient");
			}

			if (json != nullptr) HeapFree(hHeap, 0, json);

			if (rewardRecipient != nullptr)
			{
				// Если rewardRecipient != generator, то майнит на пул, узнаём имя пула...
				if (strcmp(generator, rewardRecipient) != 0)
				{
					// Запрос данных аккаунта пула
					str_req = (char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_PATH);
					if (str_req == nullptr) ShowMemErrorExit();
					sprintf_s(str_req, HeapSize(hHeap, 0, str_req), "POST /burst?requestType=getAccount&account=%s HTTP/1.0\r\nConnection: close\r\n\r\n", rewardRecipient);
					json = GetJSON(str_req);
					//Log("\n getAccount: ");

					if (json == nullptr)
					{
						Log("\n- error in message from pool (pool getAccount)\n");
					}
					else
					{
						rapidjson::Document doc_pool;
						if (doc_pool.Parse<0>(json).HasParseError() == false)
						{
							pool_accountRS = (char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, strlen(doc_pool["accountRS"].GetString()) + 1);
							if (pool_accountRS == nullptr) ShowMemErrorExit();
							strcpy_s(pool_accountRS, HeapSize(hHeap, 0, pool_accountRS), doc_pool["accountRS"].GetString());
							if (doc_pool.HasMember("name"))
							{
								pool_name = (char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, strlen(doc_pool["name"].GetString()) + 1);
								if (pool_name == nullptr) ShowMemErrorExit();
								strcpy_s(pool_name, HeapSize(hHeap, 0, pool_name), doc_pool["name"].GetString());
							}
						}
						else Log("\n- error parsing JSON pool getAccount");
					}
					HeapFree(hHeap, 0, str_req);
					HeapFree(hHeap, 0, json);
				}
			}

			wattron(win_main, COLOR_PAIR(11));
			_strtime_s(tbuffer);
			if (name != nullptr) wprintw(win_main, "%s Winner: %llus by %s (%s)\n", tbuffer, timestamp0 - timestamp1, generatorRS + 6, name, 0);
			else wprintw(win_main, "%s Winner: %llus by %s\n", tbuffer, timestamp0 - timestamp1, generatorRS + 6, 0);
			if (pool_accountRS != nullptr)
			{
				if (pool_name != nullptr) wprintw(win_main, "%s Winner's pool: %s (%s)\n", tbuffer, pool_accountRS + 6, pool_name, 0);
				else wprintw(win_main, "%s Winner's pool: %s\n", tbuffer, pool_accountRS + 6, 0);
			}
			wattroff(win_main, COLOR_PAIR(11));
		}
		else
		{
			_strtime_s(tbuffer);
			wattron(win_main, COLOR_PAIR(11));
			wprintw(win_main, "%s Winner: no info yet\n", tbuffer, 0);
			wattroff(win_main, COLOR_PAIR(11));
		}
	HeapFree(hHeap, 0, generatorRS);
	HeapFree(hHeap, 0, generator);
	HeapFree(hHeap, 0, name);
	HeapFree(hHeap, 0, rewardRecipient);
	HeapFree(hHeap, 0, pool_name);
	HeapFree(hHeap, 0, pool_accountRS);
}


void pollLocal(void) {
	size_t const buffer_size = 1000;
	char *buffer = (char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, buffer_size);
	if (buffer == nullptr) ShowMemErrorExit();

	int iResult;
	struct addrinfo *result = nullptr;
	struct addrinfo hints;
	SOCKET UpdaterSocket = INVALID_SOCKET;

	RtlSecureZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	iResult = getaddrinfo(updateraddr.c_str(), updaterport.c_str(), &hints, &result);
	if (iResult != 0) {
		if (network_quality > 0) network_quality--;
		Log("\n*! GMI: getaddrinfo failed with error: "); Log_u(WSAGetLastError());
	}
	else {
		UpdaterSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
		if (UpdaterSocket == INVALID_SOCKET)
		{
			if (network_quality > 0) network_quality--;
			Log("\n*! GMI: socket function failed with error: "); Log_u(WSAGetLastError());
		}
		else {
			const unsigned t = 1000;
			setsockopt(UpdaterSocket, SOL_SOCKET, SO_RCVTIMEO, (char *)&t, sizeof(unsigned));
			//Log("\n*Connecting to Server: "); Log(updateraddr); Log(":"); Log(updaterport);
			iResult = connect(UpdaterSocket, result->ai_addr, (int)result->ai_addrlen);
			if (iResult == SOCKET_ERROR) {
				if (network_quality > 0) network_quality--;
				Log("\n*! GMI: connect function failed with error: "); Log_u(WSAGetLastError());
			}
			else {
				int bytes = sprintf_s(buffer, buffer_size, "POST /burst?requestType=getMiningInfo HTTP/1.0\r\nHost: %s:%s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", nodeaddr.c_str(), nodeport.c_str());
				iResult = send(UpdaterSocket, buffer, bytes, 0);
				if (iResult == SOCKET_ERROR)
				{
					if (network_quality > 0) network_quality--;
					Log("\n*! GMI: send request failed: "); Log_u(WSAGetLastError());
				}
				else{
					RtlSecureZeroMemory(buffer, buffer_size);
					size_t  pos = 0;
					iResult = 0;
					do{
						iResult = recv(UpdaterSocket, &buffer[pos], (int)(buffer_size - pos - 1), 0);
						if (iResult > 0) pos += (size_t)iResult;
					} while (iResult > 0);
					if (iResult == SOCKET_ERROR)
					{
						if (network_quality > 0) network_quality--;
						Log("\n*! GMI: get mining info failed:: "); Log_u(WSAGetLastError());
					}
					else {
						if (network_quality < 100) network_quality++;
						Log("\n* GMI: Received: "); Log_server(buffer);

						// locate HTTP header
						char *find = strstr(buffer, "\r\n\r\n");
						if (find == nullptr)	Log("\n*! GMI: error message from pool");
						else {
							rapidjson::Document gmi;
							if (gmi.Parse<0>(find).HasParseError()) Log("\n*! GMI: error parsing JSON message from pool");
							else {
								if (gmi.IsObject())
								{
									if (gmi.HasMember("baseTarget")) {
										if (gmi["baseTarget"].IsString())	baseTarget = _strtoui64(gmi["baseTarget"].GetString(), 0, 10);
										else
											if (gmi["baseTarget"].IsInt64()) baseTarget = gmi["baseTarget"].GetInt64();
									}

									if (gmi.HasMember("height")) {
										if (gmi["height"].IsString())	height = _strtoui64(gmi["height"].GetString(), 0, 10);
										else
											if (gmi["height"].IsInt64()) height = gmi["height"].GetInt64();
									}

									if (gmi.HasMember("generationSignature")) {
										strcpy_s(str_signature, gmi["generationSignature"].GetString());
										if (xstr2strr(signature, 33, gmi["generationSignature"].GetString()) == 0)	Log("\n*! GMI: Node response: Error decoding generationsignature\n");
									}
									if (gmi.HasMember("targetDeadline")) {
										if (gmi["targetDeadline"].IsString())	targetDeadlineInfo = _strtoui64(gmi["targetDeadline"].GetString(), 0, 10);
										else
											if (gmi["targetDeadline"].IsInt64()) targetDeadlineInfo = gmi["targetDeadline"].GetInt64();
									}
								}
							}
						}
					}
				}
			}
			iResult = closesocket(UpdaterSocket);
		}
		freeaddrinfo(result);
	}
	HeapFree(hHeap, 0, buffer);
}


void pollLocal2(void) {
	size_t const buffer_size = 1000;
	char *buffer = (char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, buffer_size);
	if (buffer == nullptr) ShowMemErrorExit();

	int iResult = 0;
	SOCKET UpdaterSocket = INVALID_SOCKET;
	SOCKADDR_STORAGE LocalAddr = { 0 };
	SOCKADDR_STORAGE RemoteAddr = { 0 };
	DWORD dwLocalAddr = sizeof(LocalAddr);
	DWORD dwRemoteAddr = sizeof(RemoteAddr);
	BOOL bSuccess;

	UpdaterSocket = socket(AF_INET, SOCK_STREAM, 0);
	timeval  timeout;
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;

	bSuccess = WSAConnectByNameA(UpdaterSocket, (LPCSTR)updateraddr.c_str(), (LPCSTR)updaterport.c_str(), &dwLocalAddr, (SOCKADDR*)&LocalAddr, &dwRemoteAddr, (SOCKADDR*)&RemoteAddr, &timeout, NULL);
	if (!bSuccess) {
		if (network_quality > 0) network_quality--;
		Log("\n*! GMI: WsaConnectByName failed with error: "); Log_u(WSAGetLastError());
		Log(updateraddr.c_str());
	}
	else {
		setsockopt(UpdaterSocket, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);

		int bytes = sprintf_s(buffer, buffer_size, "POST /burst?requestType=getMiningInfo HTTP/1.0\r\nHost: %s:%s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", nodeaddr.c_str(), nodeport.c_str());
		iResult = send(UpdaterSocket, buffer, bytes, 0);
		if (iResult == SOCKET_ERROR)
		{
			if (network_quality > 0) network_quality--;
			Log("\n*! GMI: send request failed: "); Log_u(WSAGetLastError());
		}
		else{
			RtlSecureZeroMemory(buffer, buffer_size);
			size_t  pos = 0;
			iResult = 0;
			do{
				iResult = recv(UpdaterSocket, &buffer[pos], (int)(buffer_size - pos - 1), 0);
				if (iResult > 0) pos += (size_t)iResult;
			} while (iResult > 0);
			if (iResult == SOCKET_ERROR)
			{
				if (network_quality > 0) network_quality--;
				Log("\n*! GMI: get mining info failed:: "); Log_u(WSAGetLastError());
			}
			else {
				if (network_quality < 100) network_quality++;
				Log("\n* GMI: Received: "); Log_server(buffer);

				// locate HTTP header
				char *find = strstr(buffer, "\r\n\r\n");
				if (find == nullptr)	Log("\n*! GMI: error message from pool");
				else {
					rapidjson::Document gmi;
					if (gmi.Parse<0>(find).HasParseError()) Log("\n*! GMI: error parsing JSON message from pool");
					else {
						if (gmi.IsObject())
						{
							if (gmi.HasMember("baseTarget")) {
								if (gmi["baseTarget"].IsString())	baseTarget = _strtoui64(gmi["baseTarget"].GetString(), 0, 10);
								else
									if (gmi["baseTarget"].IsInt64()) baseTarget = gmi["baseTarget"].GetInt64();
							}

							if (gmi.HasMember("height")) {
								if (gmi["height"].IsString())	height = _strtoui64(gmi["height"].GetString(), 0, 10);
								else
									if (gmi["height"].IsInt64()) height = gmi["height"].GetInt64();
							}

							if (gmi.HasMember("generationSignature")) {
								strcpy_s(str_signature, gmi["generationSignature"].GetString());
								if (xstr2strr(signature, 33, gmi["generationSignature"].GetString()) == 0)	Log("\n*! GMI: Node response: Error decoding generationsignature\n");
							}
							if (gmi.HasMember("targetDeadline")) {
								if (gmi["targetDeadline"].IsString())	targetDeadlineInfo = _strtoui64(gmi["targetDeadline"].GetString(), 0, 10);
								else
									if (gmi["targetDeadline"].IsInt64()) targetDeadlineInfo = gmi["targetDeadline"].GetInt64();
							}
						}
					}
				}
			}
		}
	}
	closesocket(UpdaterSocket);
	HeapFree(hHeap, 0, buffer);
}

void updater_i(void) {
	if (updateraddr.length() <= 3) {
		Log("\nGMI: ERROR in UpdaterAddr");
		exit(2);
	}
	Server server(4000);
	for (; !exit_flag;)	{
		server.update();
		pollLocal();
		std::this_thread::yield();
		std::this_thread::sleep_for(std::chrono::milliseconds(update_interval));
	}
}

void hostname_to_ip(char const *const  in_addr, char* out_addr)
{
	struct addrinfo *result = nullptr;
	struct addrinfo *ptr = nullptr;
	struct addrinfo hints;
	DWORD dwRetval;
	struct sockaddr_in  *sockaddr_ipv4;

	RtlSecureZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	dwRetval = getaddrinfo(in_addr, NULL, &hints, &result);
	if (dwRetval != 0) {
		Log("\n getaddrinfo failed with error: "); Log_llu(dwRetval);
		WSACleanup();
		exit(-1);
	}
	for (ptr = result; ptr != nullptr; ptr = ptr->ai_next) {

		if (ptr->ai_family == AF_INET)
		{
			sockaddr_ipv4 = (struct sockaddr_in *) ptr->ai_addr;
			char str[INET_ADDRSTRLEN];
			inet_ntop(hints.ai_family, &(sockaddr_ipv4->sin_addr), str, INET_ADDRSTRLEN);
			//strcpy(out_addr, inet_ntoa(sockaddr_ipv4->sin_addr));
			strcpy_s(out_addr, 50, str);
			Log("\nAddress: "); Log(in_addr); Log(" defined as: "); Log(out_addr);
		}
	}
	freeaddrinfo(result);
}

void GetCPUInfo(void)
{
	ULONGLONG  TotalMemoryInKilobytes = 0;

	wprintw(win_main, "CPU support: ");
	if (InstructionSet::AES())    wprintw(win_main, " AES ", 0);
	if (InstructionSet::SSE())   wprintw(win_main, " SSE ", 0);
	if (InstructionSet::SSE2())   wprintw(win_main, " SSE2 ", 0);
	if (InstructionSet::SSE3())   wprintw(win_main, " SSE3 ", 0);
	if (InstructionSet::SSE42())   wprintw(win_main, " SSE4.2 ", 0);
	if (InstructionSet::AVX())   wprintw(win_main, " AVX ", 0);
	if (InstructionSet::AVX2())  	wprintw(win_main, " AVX2 ", 0);

#ifndef __AVX__
	// Checking for AVX requires 3 things:
	// 1) CPUID indicates that the OS uses XSAVE and XRSTORE instructions (allowing saving YMM registers on context switch)
	// 2) CPUID indicates support for AVX
	// 3) XGETBV indicates the AVX registers will be saved and restored on context switch
	bool avxSupported = false;
	int cpuInfo[4];
	__cpuid(cpuInfo, 1);

	bool osUsesXSAVE_XRSTORE = cpuInfo[2] & (1 << 27) || false;
	bool cpuAVXSuport = cpuInfo[2] & (1 << 28) || false;

	if (osUsesXSAVE_XRSTORE && cpuAVXSuport)
	{
		// Check if the OS will save the YMM registers
		unsigned long long xcrFeatureMask = _xgetbv(_XCR_XFEATURE_ENABLED_MASK);
		avxSupported = (xcrFeatureMask & 0x6) == 0x6;
	}
	if (avxSupported)	wprintw(win_main, "     [recommended use: AVX]", 0);
#endif
	if (InstructionSet::AVX2()) wprintw(win_main, "     [recommended use: AVX2]", 0);
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	wprintw(win_main, "\n%s", InstructionSet::Vendor().c_str(), 0);
	wprintw(win_main, " %s  [%u cores]", InstructionSet::Brand().c_str(), sysinfo.dwNumberOfProcessors);

	if (GetPhysicallyInstalledSystemMemory(&TotalMemoryInKilobytes))
		wprintw(win_main, "\nRAM: %llu Mb", (unsigned long long)TotalMemoryInKilobytes / 1024, 0);

	wprintw(win_main, "\n", 0);
}


int main(int argc, char **argv) {

	hHeap = GetProcessHeap();
	HeapSetInformation(NULL, HeapEnableTerminationOnCorruption, NULL, 0);

	LARGE_INTEGER li;
	__int64 start_threads_time, end_threads_time, curr_time;
	QueryPerformanceFrequency(&li);
	double pcFreq = double(li.QuadPart);

	std::thread proxy;
	std::vector<std::thread> generator;

	InitializeCriticalSection(&sessionsLock);
	InitializeCriticalSection(&bestsLock);
	InitializeCriticalSection(&sharesLock);

	char tbuffer[9];
	unsigned long long bytesRead = 0;
	FILE * pFileStat;

	shares.reserve(20);
	bests.reserve(4);
	sessions.reserve(20);


	size_t const cwdsz = GetCurrentDirectoryA(0, 0);
	p_minerPath = (char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, cwdsz + 2);
	if (p_minerPath == nullptr)
	{
		fprintf(stderr, "\nError allocating memory\n");
		system("pause");
		exit(-1);
	}
	GetCurrentDirectoryA(DWORD(cwdsz), LPSTR(p_minerPath));
	strcat_s(p_minerPath, cwdsz + 2, "\\");

	char* conf_filename = (char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, MAX_PATH);
	if (conf_filename == nullptr)
	{
		fprintf(stderr, "\nError allocating memory\n");
		system("pause");
		exit(-1);
	}
	if ((argc >= 2) && (strcmp(argv[1], "-config") == 0)){
		if (strstr(argv[2], ":\\")) sprintf_s(conf_filename, MAX_PATH, "%s", argv[2]);
		else sprintf_s(conf_filename, MAX_PATH, "%s%s", p_minerPath, argv[2]);
	}
	else sprintf_s(conf_filename, MAX_PATH, "%s%s", p_minerPath, "miner.conf");

	load_config(conf_filename);
	HeapFree(hHeap, 0, conf_filename);

	Log("\nMiner path: "); Log(p_minerPath);

	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	
	COORD max_coord = GetLargestConsoleWindowSize(hConsole);
	if (win_size_x > max_coord.X) win_size_x = max_coord.X;
	if (win_size_y > max_coord.Y) win_size_y = max_coord.Y;

	COORD coord;
	coord.X = win_size_x;
	coord.Y = win_size_y;

	SMALL_RECT Rect;
	Rect.Top = 0;
	Rect.Left = 0;
	Rect.Bottom = coord.Y - 1;
	Rect.Right = coord.X - 1;

	SetConsoleScreenBufferSize(hConsole, coord);
	SetConsoleWindowInfo(hConsole, TRUE, &Rect);

	RECT wSize;
	GetWindowRect(GetConsoleWindow(), &wSize);
	MoveWindow(GetConsoleWindow(), 0, 0, wSize.right - wSize.left, wSize.bottom - wSize.top, true);
	initscr();
	raw();
	cbreak();		// не использовать буфер для getch()
	noecho();		// не отображать нажатия клавиш
	curs_set(0);	// убрать курсор
	start_color();	// будет всё цветное 			

	init_pair(2, COLOR_GREEN, COLOR_BLACK);
	init_pair(4, COLOR_RED, COLOR_BLACK);
	init_pair(6, COLOR_CYAN, COLOR_BLACK);
	init_pair(7, COLOR_WHITE, COLOR_BLACK);
	init_pair(9, 9, COLOR_BLACK);
	init_pair(10, 10, COLOR_BLACK);
	init_pair(11, 11, COLOR_BLACK);
	init_pair(12, 12, COLOR_BLACK);
	init_pair(14, 14, COLOR_BLACK);
	init_pair(15, 15, COLOR_BLACK);

	init_pair(25, 15, COLOR_BLUE);

	win_main = newwin(LINES - 2, COLS, 0, 0);

	scrollok(win_main, true);
	keypad(win_main, true);
	nodelay(win_main, true);

	WINDOW * win_progress = newwin(3, COLS, LINES - 3, 0);
	leaveok(win_progress, true);

	wattron(win_main, COLOR_PAIR(12));
	wprintw(win_main, "\nBURST miner, %s", version, 0);
	wattroff(win_main, COLOR_PAIR(12));
	wattron(win_main, COLOR_PAIR(4));
	wprintw(win_main, "\nProgramming: dcct (Linux) & Blago (Windows) & ohager (Windows Fork)\n", 0);
	wattroff(win_main, COLOR_PAIR(4));


	GetCPUInfo();

	wrefresh(win_main);
	wrefresh(win_progress);

	if (miner_mode == 0) GetPass(p_minerPath);

	Log("\nSearching servers...");
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		wprintw(win_main, "WSAStartup failed\n", 0);
		exit(-1);
	}

	char* updaterip = (char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 50);
	if (updaterip == nullptr) ShowMemErrorExit();
	char* nodeip = (char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 50);
	if (nodeip == nullptr) ShowMemErrorExit();
	wattron(win_main, COLOR_PAIR(11));

	hostname_to_ip(nodeaddr.c_str(), nodeip);
	wprintw(win_main, "Pool address    %s (ip %s:%s)\n", nodeaddr.c_str(), nodeip, nodeport.c_str(), 0);

	if (updateraddr.length() > 3) hostname_to_ip(updateraddr.c_str(), updaterip);
	wprintw(win_main, "Updater address %s (ip %s:%s)\n", updateraddr.c_str(), updaterip, updaterport.c_str(), 0);

	wattroff(win_main, COLOR_PAIR(11));
	HeapFree(hHeap, 0, updaterip);
	HeapFree(hHeap, 0, nodeip);

	RtlSecureZeroMemory(oldSignature, 33);
	RtlSecureZeroMemory(signature, 33);

	wattron(win_main, COLOR_PAIR(15));
	wprintw(win_main, "Using plots:\n", 0);
	wattroff(win_main, COLOR_PAIR(15));

	std::vector<t_files> all_files;
	total_size = 0;
	for (auto iter = paths_dir.begin(); iter != paths_dir.end(); ++iter)	{
		std::vector<t_files> files;
		GetFiles(*iter, &files);

		unsigned long long tot_size = 0;
		for (auto it = files.begin(); it != files.end(); ++it){
			tot_size += it->Size;
			all_files.push_back(*it);
		}
		wprintw(win_main, "%s\tfiles: %2Iu\t size: %4llu Gb\n", (char*)iter->c_str(), (unsigned)files.size(), tot_size / 1024 / 1024 / 1024, 0);
		total_size += tot_size;
	}
	wattron(win_main, COLOR_PAIR(15));
	wprintw(win_main, "TOTAL: %llu Gb\n", total_size / 1024 / 1024 / 1024, 0);
	wattroff(win_main, COLOR_PAIR(15));

	if (total_size == 0) {
		wattron(win_main, COLOR_PAIR(12));
		wprintw(win_main, "\n Plot files not found...please check the \"PATHS\" parameter in your config file.\n Press any key for exit...");
		wattroff(win_main, COLOR_PAIR(12));
		wrefresh(win_main);
		system("pause");
		exit(0);
	}

	// Check overlapped plots
	for (size_t cx = 0; cx < all_files.size(); cx++)	{
		for (size_t cy = cx + 1; cy < all_files.size(); cy++)		{
			if (all_files[cy].Key == all_files[cx].Key)
				if (all_files[cy].StartNonce >= all_files[cx].StartNonce) {
					if (all_files[cy].StartNonce < all_files[cx].StartNonce + all_files[cx].Nonces){
						wattron(win_main, COLOR_PAIR(12));
						wprintw(win_main, "\nWARNING: %s%s and \n%s%s are overlapped\n", all_files[cx].Path.c_str(), all_files[cx].Name.c_str(), all_files[cy].Path.c_str(), all_files[cy].Name.c_str(), 0);
						wattroff(win_main, COLOR_PAIR(12));
					}
				}
				else
					if (all_files[cy].StartNonce + all_files[cy].Nonces > all_files[cx].StartNonce){
						wattron(win_main, COLOR_PAIR(12));
						wprintw(win_main, "\nWARNING: %s%s and \n%s%s are overlapped\n", all_files[cx].Path.c_str(), all_files[cx].Name.c_str(), all_files[cy].Path.c_str(), all_files[cy].Name.c_str(), 0);
						wattroff(win_main, COLOR_PAIR(12));
					}
		}
	}

	// Run Proxy
	if (enable_proxy)
	{
		proxy = std::thread(proxy_i);
		wattron(win_main, COLOR_PAIR(25));
		wprintw(win_main, "Proxy thread started\n", 0);
		wattroff(win_main, COLOR_PAIR(25));
	}

	// Run updater;
	std::thread updater(updater_i);
	Log("\nUpdater thread started");

	Log("\nUpdate mining info");
	while (height == 0)
	{
		std::this_thread::yield();
		std::this_thread::sleep_for(std::chrono::milliseconds(2));
	};

	// Main loop
	for (; !exit_flag;)
	{
		worker.clear();
		worker_progress.clear();
		stopThreads = 0;

		char scoopgen[40];
		memmove(scoopgen, signature, 32);
		const char *mov = (char*)&height;
		scoopgen[32] = mov[7]; scoopgen[33] = mov[6]; scoopgen[34] = mov[5]; scoopgen[35] = mov[4]; scoopgen[36] = mov[3]; scoopgen[37] = mov[2]; scoopgen[38] = mov[1]; scoopgen[39] = mov[0];

		sph_shabal_context x;
		sph_shabal256_init(&x);
		sph_shabal256(&x, (const unsigned char*)(const unsigned char*)scoopgen, 40);
		char xcache[32];
		sph_shabal256_close(&x, xcache);

		scoop = (((unsigned char)xcache[31]) + 256 * (unsigned char)xcache[30]) % 4096;

		deadline = 0;

		Log("\n------------------------    New block: "); Log_llu(height);

		_strtime_s(tbuffer);
		wattron(win_main, COLOR_PAIR(25));
		wprintw(win_main, "\n%s New block %llu, baseTarget %llu, netDiff %llu Tb          \n", tbuffer, height, baseTarget, 4398046511104 / 240 / baseTarget, 0);
		wattron(win_main, COLOR_PAIR(25));
		if (miner_mode == 0)
		{
			unsigned long long sat_total_size = 0;
			for (auto It = satellite_size.begin(); It != satellite_size.end(); ++It) sat_total_size += It->second;
			wprintw(win_main, "*** Chance to find a block: %.5f%%  (%llu Gb)\n", ((double)((sat_total_size * 1024 + total_size / 1024 / 1024) * 100 * 60)*(double)baseTarget) / 1152921504606846976, sat_total_size + total_size / 1024 / 1024 / 1024, 0);
		}

		EnterCriticalSection(&sessionsLock);
		for (auto it = sessions.begin(); it != sessions.end(); ++it) closesocket(it->Socket);
		sessions.clear();
		LeaveCriticalSection(&sessionsLock);

		EnterCriticalSection(&sharesLock);
		shares.clear();
		LeaveCriticalSection(&sharesLock);

		EnterCriticalSection(&bestsLock);
		bests.clear();
		LeaveCriticalSection(&bestsLock);

		if ((targetDeadlineInfo > 0) && (targetDeadlineInfo < my_target_deadline)){
			Log("\nUpdate targetDeadline: "); Log_llu(targetDeadlineInfo);
		}
		else targetDeadlineInfo = my_target_deadline;

		// Run Sender
		std::thread sender(send_i);

		// Run Threads
		QueryPerformanceCounter((LARGE_INTEGER*)&start_threads_time);
		double threads_speed = 0;

		for (size_t i = 0; i < paths_dir.size(); i++)
		{
			worker_progress.push_back({ i, 0, true });
			worker.push_back(std::thread(work_i, i));
		}

		memmove(oldSignature, signature, 32);
		unsigned long long old_baseTarget = baseTarget;
		unsigned long long old_height = height;
		wclear(win_progress);

		// Wait until signature changed or exit
		while ((memcmp(signature, oldSignature, 32) == 0) && !exit_flag)
		{
			switch (wgetch(win_main))
			{
			case 'q':
				exit_flag = true;
				break;
			case 'r':
				wattron(win_main, COLOR_PAIR(15));
				wprintw(win_main, "Recommended size for this block: %llu Gb\n", (4398046511104 / baseTarget) * 1024 / targetDeadlineInfo);
				wattroff(win_main, COLOR_PAIR(15));
				break;
			case 'c':
				wprintw(win_main, "*** Chance to find a block: %.5f%%  (%llu Gb)\n", ((double)((total_size / 1024 / 1024) * 100 * 60)*(double)baseTarget) / 1152921504606846976, total_size / 1024 / 1024 / 1024, 0);
				break;
			}
			box(win_progress, 0, 0);
			bytesRead = 0;

			int threads_runing = 0;
			for (auto it = worker_progress.begin(); it != worker_progress.end(); ++it)
			{
				bytesRead += it->Reads_bytes;
				threads_runing += it->isAlive;
			}

			if (threads_runing)
			{
				QueryPerformanceCounter((LARGE_INTEGER*)&end_threads_time);
				threads_speed = (double)(bytesRead / (1024 * 1024)) / ((double)(end_threads_time - start_threads_time) / pcFreq);
			}
			else{

				if (use_wakeup)
				{
					QueryPerformanceCounter((LARGE_INTEGER*)&curr_time);
					if ((curr_time - end_threads_time) / pcFreq > 180)  // 3 minutes
					{
						std::vector<t_files> tmp_files;
						for (size_t i = 0; i < paths_dir.size(); i++)		GetFiles(paths_dir[i], &tmp_files);
						if (use_debug)
						{
							char tbuffer[9];
							_strtime_s(tbuffer);
							wattron(win_main, COLOR_PAIR(7));
							wprintw(win_main, "%s HDD, WAKE UP !\n", tbuffer, 0);
							wattroff(win_main, COLOR_PAIR(7));
						}
						end_threads_time = curr_time;
					}
				}
			}

			wmove(win_progress, 1, 1);
			wattron(win_progress, COLOR_PAIR(14));
			if (deadline == 0)
				wprintw(win_progress, "%3llu%% %6llu GB (%.2f MB/s). no deadline            Connection: %3u%%", (bytesRead * 4096 * 100 / total_size), (bytesRead / (256 * 1024)), threads_speed, network_quality, 0);
			else
				wprintw(win_progress, "%3llu%% %6llu GB (%.2f MB/s). Deadline =%10llu   Connection: %3u%%", (bytesRead * 4096 * 100 / total_size), (bytesRead / (256 * 1024)), threads_speed, deadline, network_quality, 0);
			wattroff(win_progress, COLOR_PAIR(14));

			wrefresh(win_main);
			wrefresh(win_progress);

			std::this_thread::yield();
			std::this_thread::sleep_for(std::chrono::milliseconds(39));
		}

		stopThreads = 1;   // Tell all threads to stop

		if (show_winner && !exit_flag)	GetBlockInfo(0);

		for (auto it = worker.begin(); it != worker.end(); ++it)
		{
			Log("\nInterrupt thread. ");
			if (it->joinable()) it->join();
		}

		Log("\nInterrupt Sender. ");
		if (sender.joinable()) sender.join();


		fopen_s(&pFileStat, "stat.csv", "a+t");
		if (pFileStat != nullptr)
		{
			fprintf(pFileStat, "%llu;%llu;%llu\n", old_height, old_baseTarget, deadline);
			fclose(pFileStat);
		}


	}

	if (pass != nullptr) HeapFree(hHeap, 0, pass);
	if (updater.joinable()) updater.join();
	Log("\nUpdater stopped");
	if (enable_proxy) proxy.join();
	delete server;
	worker.~vector();
	worker_progress.~vector();
	paths_dir.~vector();
	bests.~vector();
	shares.~vector();
	sessions.~vector();
	DeleteCriticalSection(&sessionsLock);
	DeleteCriticalSection(&sharesLock);
	DeleteCriticalSection(&bestsLock);
	HeapFree(hHeap, 0, p_minerPath);

	WSACleanup();
	Log("\nexit");
	fclose(fp_Log);
	return 0;
}
