# WSNetLayer

The WSNetLayer plugin exposes the messaging layer of NWN's networking over websockets.

The actual messages can be sent and received without cryptography or other obfuscation and
are fully documented in the accompanying
(Python project)[https://github.com/niv/nwn-message.py].

This can be used to develop and play with custom clients, as long as the alternate
websocket transport is enabled (currently opt-in by building and loading this plugin).

Websockets as a transport have the advantage of being battle-tested, ubiquitous, and
addressable from PWAs and web browsers directly. Third party game engines, such as Godot,
speak it natively. The (used websocket library)[https://libwebsockets.org/] also is very
mature and widely deployed.

## Data Confidentiality

Websockets exposed to the wider internet must be guarded with TLS to ensure client traffic
confidentialty, as the base protocol as exposed here has no cryptography protection.

The plugin does not currently support loading a cert+key. You need to use a capable
reverse proxy with TLS termination (Caddy is a good choice). The plugin understands
proxy behaviour and will set the correct IP for clients, as long as X-Forwarded-For is
set correctly (most proxies do this).

_**This is really, really important: DO NOT EXPOSE THIS WEBSOCKET DIRECTLY ON THE
INTERNET. It is NOT encrypted. Your player data would be exposed to anyone that can sniff
or MITM the
connection. USE A REVERSE PROXY WITH TLS TERMINATION.**_

## Compression

The original NWN protocol has zlib compression. This adaption does not. However,
websockets have transparent, context-aware compression via the permessage-deflate feature
flag. The overwhelming majority, but not all websocket implementations, support it by
default.

The NWN protocol benefits from context-aware (dictionaried) compression, so
permessage-deflate is not obligatory, but a good idea to use when available.

When compiling this plugin against a local libwebsocket, make sure it has extensions
enabled (it will print a warning to stdout on start if not; and in that case, compression
is not available but it will still work fine).

## Auth and Capabilities

Clients connecting over websocket present as normal player connections, must authenticate
with a valid CD key and a optionally required game password. They count against the same
player limit as UDP-based connections. There is a VM script call to determine if a player
is coming in over a Websocket.

Currently, there is no capability system in place to discern diverging features between
custom clients and the official game client (beyond Device Props and the version
identifier). This should be discussed before any implementation in the wild, as it will
impact all users of this network protocol.

## Environment Variables

| Variable Name | Value  | Default       | Notes                                      |
| ------------- | :----: | ------------- | ------------------------------------------ |
| PORT          | uint16 | (same as UDP) | The TCP port the websocket will listen on. |

It is strongly recommended to use the TCP equivalent of the matching UDP port for each
running server instance.

## Supported versions

The only supported game version, right now, is 8193.37.17 (latest stable). As the hooking
into the network stack of the game server is somewhat intrusive, future versions may or
may not work without adjustments. Caution is very strongly recommended.

## Protocol

The network protocol is nearly the same as standard NWN:EE. Non-window messages start
with B; Server->Player starts with a p; Player->Server is a uppercase P. (M-frames are not
supported, as WSNetLayer and websockets do not use a sliding window.)

WSNetLayer-specific packets are prefixed with a G, instead of B or p/P. All frames are
sent binary. The text layer is reserved for future out of band use.

## License

This project is licensed under the GPLv3.

The spirit of this license choice is: if you build on this work, share it back. The NWN
ecosystem thrives on open tools, not closed ones.

Whether you're building a custom client, a bot, or a whole new server, we hope you'll
open-source your work too. And even if you can't open everything, come tell us what
you're building anyway. We'd love to hear about it.

## Get in touch

- Join the community chat: https://nwn.zulipchat.com/
- Open a new issue or discussion thread here on GitHub.
