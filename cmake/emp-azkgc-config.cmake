find_package(emp-ot)

find_path(ESwap_INCLUDE_DIR ESwap/ESwap.h)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(ESwap DEFAULT_MSG ESwap_INCLUDE_DIR)

find_library(ESwap_LIBRARY NAMES ESwap)

if(ESwap_FOUND)
	set(ESwap_INCLUDE_DIRS ${ESwap_INCLUDE_DIR}/include/ ${EMP-OT_INCLUDE_DIRS})
	set(ESwap_LIBRARIES ${EMP-OT_LIBRARIES} ${ESwap_LIBRARY}$)
endif()
