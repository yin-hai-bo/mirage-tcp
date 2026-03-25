#ifndef MIRAGE_TCP_ERROR_CODE_H
#define MIRAGE_TCP_ERROR_CODE_H

#ifdef __cplusplus
extern "C" {
#endif

enum {
    MTE_Ok = 0,
    MTE_InvalidArgument = 1,
    MTE_PacketTooShort = 2,
    MTE_UnsupportedIpVersion = 3,
    MTE_InvalidIpv4HeaderLength = 4,
    MTE_InvalidIpv4TotalLength = 5,
    MTE_Ipv4FragmentUnsupported = 6,
    MTE_PacketTooLarge = 7,
    MTE_IsNotTcp = 8,
    MTE_InvalidTcpDataOffset = 9,
    MTE_TcpHeaderTooLong = 10,
    MTE_HandshakeFinalAckExpected = 11,
    MTE_HandshakeClientSequenceUnexpected = 12,
    MTE_FlowNotFound = 13,
    MTE_FlowAlreadyExists = 14,
    MTE_EstablishedAckRequired = 15,
    MTE_EstablishedAckNumberUnexpected = 16,
    MTE_EstablishedSequenceUnexpected = 17,
    MTE_CloseFinalAckExpected = 18,
    MTE_CloseAckUnexpected = 19,
    MTE_PayloadEmpty = 20,
    MTE_Ipv4OnlyOperation = 21,
    MTE_SendBeforeEstablished = 22,
    MTE_CloseBeforeEstablished = 23,
    MTE_PacketEmitFailed = 24,
    MTE_ConnectInvalidState = 25,
    MTE_WriteInvalidState = 26,
    MTE_WriteAfterClose = 27,
    MTE_CloseInvalidState = 28,
    MTE_PeerMismatch = 29,
    MTE_ClosedState = 30,
    MTE_UnhandledState = 31,
    MTE_SynAckExpected = 32,
    MTE_AckUnexpected = 33,
    MTE_PayloadOutOfOrder = 34,
    MTE_FinSequenceUnexpected = 35,
    MTE_ClosedByReset = 36,
    MTE_ClosedByPeerFin = 37,
    MTE_TimeWaitExpired = 38,
    MTE_Unsupported = 39,
    MTE_OutOfMemory = 40,
};

#ifdef __cplusplus
}
#endif

#endif
