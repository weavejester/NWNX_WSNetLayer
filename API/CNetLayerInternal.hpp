#pragma once
#include "nwn_api.hpp"

#include "API/CNetLayer.hpp"
#include "API/CExoString.hpp"

#ifdef NWN_API_PROLOGUE
NWN_API_PROLOGUE(CNetLayerInternal)
#endif

typedef int BOOL;

struct CNetLayerInternal
{
    const CNetInstance m_nInstance;

    void SetPlayerConnected(uint32_t nPlayerId);
    BOOL DisconnectPlayer(uint32_t nPlayerId, uint32_t nStrRef, BOOL bSendBNDP, BOOL bCDAuthFail,
        const CExoString& reason);
    BOOL SendDirectMessage(CNetConnectionId nConnectionId, uint8_t* pData, uint32_t nMsgLength,
        uint32_t nPort);
    BOOL NonWindowMessages(CNetConnectionId nConnectionId, uint8_t* pMessage, uint32_t nSize);
    BOOL SendMessageToPlayer(uint32_t nPlayerId, uint8_t* pData, uint32_t nSize, uint32_t nFlags);
    CExoString GetPlayerAddress(uint32_t nPlayerId, BOOL bIncludePort);
    CNetPeer GetPlayerAddressData(CNetConnectionId nConnectionId);
    BOOL ConnectionIdToSlidingWindow(CNetConnectionId nConnectionId, uint32_t* nSlidingWindow);
    BOOL PlayerIdToConnectionId(uint32_t nPlayerId, CNetConnectionId* nConnectionId);
    BOOL PlayerIdToSlidingWindow(uint32_t nPlayerId, uint32_t* nSlidingWindow);

#ifdef NWN_CLASS_EXTENSION_CNetLayerInternal
    NWN_CLASS_EXTENSION_CNetLayerInternal
#endif
};

#ifdef NWN_API_EPILOGUE
NWN_API_EPILOGUE(CNetLayerInternal)
#endif
