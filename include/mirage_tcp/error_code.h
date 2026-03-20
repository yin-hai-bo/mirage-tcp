#ifndef MIRAGE_TCP_ERROR_CODE_H
#define MIRAGE_TCP_ERROR_CODE_H

namespace mirage_tcp {

using error_code_t = int;

struct ErrorCode {
    enum Value {
        Ok = 0,
        InvalidArgument = 1,
        PacketTooShort = 2,
        UnsupportedIpVersion = 3,
        InvalidIpv4HeaderLength = 4,
        InvalidIpv4TotalLength = 5,
        Ipv4FragmentUnsupported = 6,
        PacketTooLarge = 7,
        IsNotTcp = 8,
        InvalidTcpDataOffset = 9,
        TcpHeaderTooLong = 10,
        HandshakeFinalAckExpected = 11,
        HandshakeClientSequenceUnexpected = 12,
        FlowNotFound = 13,
        FlowAlreadyExists = 14,
        EstablishedAckRequired = 15,
        EstablishedAckNumberUnexpected = 16,
        EstablishedSequenceUnexpected = 17,
        CloseFinalAckExpected = 18,
        CloseAckUnexpected = 19,
        PayloadEmpty = 20,
        Ipv4OnlyOperation = 21,
        SendBeforeEstablished = 22,
        CloseBeforeEstablished = 23,
        PacketEmitFailed = 24,
        ConnectInvalidState = 25,
        WriteInvalidState = 26,
        WriteAfterClose = 27,
        CloseInvalidState = 28,
        PeerMismatch = 29,
        ClosedState = 30,
        UnhandledState = 31,
        SynAckExpected = 32,
        AckUnexpected = 33,
        PayloadOutOfOrder = 34,
        FinSequenceUnexpected = 35,
        ClosedByReset = 36,
        ClosedByPeerFin = 37,
        TimeWaitExpired = 38,
        Unsupported = 39
    };
};

}  // namespace mirage_tcp

#endif
