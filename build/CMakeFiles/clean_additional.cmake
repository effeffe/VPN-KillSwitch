# Additional clean files
cmake_minimum_required(VERSION 3.16)

if("${CONFIG}" STREQUAL "" OR "${CONFIG}" STREQUAL "")
  file(REMOVE_RECURSE
  "CMakeFiles/vpnks_autogen.dir/AutogenUsed.txt"
  "CMakeFiles/vpnks_autogen.dir/ParseCache.txt"
  "vpnks_autogen"
  )
endif()
