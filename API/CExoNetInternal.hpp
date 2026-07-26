#pragma once

#include "nwn_api.hpp"
#include "API/CExoString.hpp"

#ifdef NWN_API_PROLOGUE
NWN_API_PROLOGUE(CExoNetInternal)
#endif

struct CExoNetInternal
{
    const CNetInstance m_nInstance;

    void* GetCryptoStateForConnection(CNetConnectionId nConnection);
    CExoString GetNetworkAddressString(CNetConnectionId nConnectionId, BOOL bIncludePort);

#ifdef NWN_CLASS_EXTENSION_CExoNetInternal
    NWN_CLASS_EXTENSION_CExoNetInternal
#endif
};

#ifdef NWN_API_EPILOGUE
NWN_API_EPILOGUE(CExoNetInternal)
#endif
