find_package(libwebsockets)

if (libwebsockets_FOUND)
    add_plugin(WSNetLayer
        WSNetLayer.cpp
        Helpers.cpp
        ConnPool.cpp
        MessageWriter.cpp
        MessageReader.cpp
        MessageWire.cpp
    )
    target_link_libraries(WSNetLayer websockets)
    target_include_directories(WSNetLayer PUBLIC ${LIBWEBSOCKETS_INCLUDE_DIRS})
endif()
