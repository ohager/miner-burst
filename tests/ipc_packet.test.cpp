#include "CppUnitTest.h"
#include "../network/ipc_packet.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace UnitTests
{		
	TEST_CLASS(IPCPacketTest)
	{
	public:
		
		TEST_METHOD(TestIPCPacketSerialization)
		{
			ipc_packet jp;

			jp.type("testType");
			jp.data("testData");

			string result = jp.serialize();

			Assert::AreEqual(R"({"type":"testType","data":"testData"})", result.c_str());
		}

	};
}