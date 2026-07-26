#pragma once
#include "nwn_api.hpp"

#ifdef NWN_API_PROLOGUE
NWN_API_PROLOGUE(CExoNet)
#endif

class CExoNetInternal;

// Partial stub
struct CExoNet
{
    const CNetInstance m_nInstance;
    CExoNetInternal* m_pcExoNetInternal;

#ifdef NWN_CLASS_EXTENSION_CExoNet
    NWN_CLASS_EXTENSION_CExoNet
#endif
};

#ifdef NWN_API_EPILOGUE
NWN_API_EPILOGUE(CExoNet)
#endif
