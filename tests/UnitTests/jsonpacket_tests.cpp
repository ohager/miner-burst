#include "CppUnitTest.h"
#include "../../network/JsonPacket.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace UnitTests
{		
	TEST_CLASS(UnitTest1)
	{
	public:
		
		TEST_METHOD(TestJsonPacketSerialization)
		{
			JsonPacket jp;

			jp.setType("testType");
			jp.setData("testData");

			string result = jp.serialize();

			Assert::AreEqual(R"({"type":"testType","data":"testData"})", result.c_str());
		}

	};
}