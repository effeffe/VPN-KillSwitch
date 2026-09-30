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

# Desktop user granted passwordless use of the helper/firewall in the polkit rule.
set(VPNKS_USER "$ENV{USER}" CACHE STRING "Desktop user allowed to use vpnks without password prompts")
if(VPNKS_USER STREQUAL "" OR VPNKS_USER STREQUAL "root")
    message(WARNING "VPNKS_USER is '${VPNKS_USER}'. Configure with -DVPNKS_USER=<your login>, "
                    "otherwise every namespace action asks for the admin password.")
endif()
configure_file(dist/50-vpnks.rules.in ${CMAKE_CURRENT_BINARY_DIR}/50-vpnks.rules @ONLY)

install(TARGETS vpnks RUNTIME DESTINATION bin)
install(FILES dist/vpnks.desktop DESTINATION share/applications)
install(FILES dist/vpnks.svg DESTINATION share/icons/hicolor/scalable/apps)
# System integration: fixed paths, referenced by the polkit action and the GUI.
install(PROGRAMS dist/vpnks-helper DESTINATION /usr/lib/vpnks)
install(PROGRAMS dist/90-vpnks DESTINATION /etc/NetworkManager/dispatcher.d)
install(FILES dist/helper.conf DESTINATION /etc/vpnks)
install(FILES dist/vpnks.slice DESTINATION /usr/lib/systemd/system)
install(FILES dist/org.vpnks.helper.policy DESTINATION /usr/share/polkit-1/actions)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/50-vpnks.rules DESTINATION /etc/polkit-1/rules.d)
