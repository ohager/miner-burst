#include "CppUnitTest.h"
#include "../network/messages/HandshakeAckMessage.h"
#include "../network/messages/MiningDataMessage.h"
#include "../network/messages/HeartbeatMessage.h"
#include "../network/messages/ErrorMessage.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;


namespace UnitTests
{
	TEST_CLASS(MessageSerializationTest)
	{
	public:

		static std::string createClosedMessage(const std::string & inmsg)
		{
			return inmsg + "\f";
		}

		TEST_METHOD(TestSerialization_handshakeAck)
		{
			HandshakeAckMessage message;

			size_t l;
			const char * msg = message.serialize(l);
			std::string expected = createClosedMessage(R"({"type":"handshake_ack"})");
			Assert::AreEqual(expected.c_str(), msg);
			Assert::IsTrue(expected.size() == l);
		}

		TEST_METHOD(TestSerialization_heartbeat)
		{
			HeartbeatMessage firstBeat; // ++iteration
			Assert::IsTrue(firstBeat.iteration() == 1);

			HeartbeatMessage secondBeat; // ++iteration

			size_t l;
			const char * msg = secondBeat.serialize(l);
			std::string expected = createClosedMessage(R"({"type":"heartbeat","data":{"iteration":2}})");
			Assert::AreEqual(expected.c_str(), msg);
			Assert::IsTrue(expected.size() == l);

		}

		TEST_METHOD(TestSerialization_error)
		{
			ErrorMessage message("some error");

			size_t l;
			const char * msg = message.serialize(l);
			std::string expected = createClosedMessage(R"({"type":"error","data":{"message":"some error"}})");
			Assert::AreEqual(expected.c_str(), msg);
			Assert::IsTrue(expected.size() == l);
		}


		TEST_METHOD(TestSerialization_mining)
		{
			MiningDataMessage message;
			message.deadline(1000);

			size_t l;
			const char * msg = message.serialize(l);
			std::string expected = createClosedMessage(R"({"type":"mining_data","data":{"deadline":1000}})");
			Assert::AreEqual(expected.c_str(), msg);
			Assert::IsTrue(expected.size() == l);
		}

	};
}