cmake_minimum_required (VERSION 2.8)

project (fakedrm)

include (FindPkgConfig)
include (CheckCSourceCompiles)

pkg_check_modules (LIBDRM REQUIRED libdrm)

include_directories (
	${LIBDRM_INCLUDE_DIRS}
)

add_definitions(-D__USE_GNU=1)
add_definitions(-D_GNU_SOURCE=1)
set (CMAKE_C_FLAGS "-Werror -Wall -fvisibility=hidden ${CMAKE_C_FLAGS}")

add_library(fakedrm SHARED
	exynos.c
	msm.c
	file.c
	file.h
	gem.c
	gem.h
	kms.c
	kms.h
	library.c
	utils.c
	utils.h
	xf86drmHash.c
)

target_link_libraries(fakedrm pthread rt)
