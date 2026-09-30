cmake_minimum_required(VERSION 3.16)
project(vpnks LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
find_package(Qt6 REQUIRED COMPONENTS Widgets Network)

add_executable(vpnks
    src/main.cpp
    src/Config.cpp
    src/Runner.cpp
    src/NetInfo.cpp
    src/HelperConfig.cpp
    src/Namespace.cpp
    src/Backend.cpp
    src/FirewalldBackend.cpp
    src/IptablesBackend.cpp
    src/NftBackend.cpp
    src/UfwBackend.cpp
    src/Killswitch.cpp
    src/AppStore.cpp
    src/SettingsDialog.cpp
    src/MainWindow.cpp)
target_link_libraries(vpnks PRIVATE Qt6::Widgets Qt6::Network)
target_compile_options(vpnks PRIVATE -Wall -Wextra)

install(TARGETS vpnks RUNTIME DESTINATION bin)
install(FILES dist/vpnks.desktop DESTINATION share/applications)
install(FILES dist/vpnks.svg DESTINATION share/icons/hicolor/scalable/apps)
# System integration: fixed paths, referenced by the polkit action and the GUI.
install(PROGRAMS dist/vpnks-helper DESTINATION /usr/lib/vpnks)
install(PROGRAMS dist/90-vpnks DESTINATION /etc/NetworkManager/dispatcher.d)
install(FILES dist/helper.conf DESTINATION /etc/vpnks)
install(FILES dist/vpnks.slice DESTINATION /usr/lib/systemd/system)
install(FILES dist/org.vpnks.helper.policy DESTINATION /usr/share/polkit-1/actions)
install(FILES dist/50-vpnks.rules DESTINATION /etc/polkit-1/rules.d)

# Create the group on a direct install (skipped when staging into DESTDIR for a package).
install(CODE "
    if(NOT \"\$ENV{DESTDIR}\" STREQUAL \"\")
        message(STATUS \"DESTDIR set, not creating group '${VPNKS_GROUP}' (create it with: groupadd -r ${VPNKS_GROUP})\")
    else()
        execute_process(COMMAND getent group ${VPNKS_GROUP} RESULT_VARIABLE _vpnks_nogroup OUTPUT_QUIET)
        if(_vpnks_nogroup)
            execute_process(COMMAND groupadd -r ${VPNKS_GROUP} RESULT_VARIABLE _vpnks_err)
            if(_vpnks_err)
                message(WARNING \"could not create group '${VPNKS_GROUP}': run groupadd -r ${VPNKS_GROUP}\")
            else()
                message(STATUS \"Created system group '${VPNKS_GROUP}'\")
            endif()
        endif()
    endif()
    message(STATUS \"Add your user to the ${VPNKS_GROUP} group via: usermod -aG ${VPNKS_GROUP} \$USER (then log out and back in)\")
")
