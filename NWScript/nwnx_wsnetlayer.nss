/// @addtogroup wsnetlayer WSNetLayer
/// @brief Functions to interact with WSNetLayer, which enables third-party websocket clients.
/// @{
/// @file nwnx_wsnetlayer.nss

const string NWNX_WSNetLayer = "NWNX_WSNetLayer"; ///< @private

/// @brief Checks if the player is connected through WSNetLayer.
/// @param oPlayer The player to check.
/// @return 1 if the player is connected through WSNetLayer, 0 otherwise or if not a player.
int NWNX_WSNetLayer_IsWSClient(object oPlayer);

/// @}

int NWNX_WSNetLayer_IsWSClient(object oPlayer)
{
    NWNXPushObject(oPlayer);
    return NWNXCall(NWNX_WSNetLayer, "IsWSClient");
}
