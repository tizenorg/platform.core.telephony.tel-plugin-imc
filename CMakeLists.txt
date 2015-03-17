CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(imc-plugin C)

#INCLUDE(FindPkgConfig)

SET(PREFIX ${CMAKE_INSTALL_PREFIX})
SET(EXEC_PREFIX "\${prefix}")
SET(LIBDIR ${LIB_INSTALL_DIR})
SET(INCLUDEDIR "\${prefix}/include")

# Set required packages
INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs REQUIRED glib-2.0 tcore dlog db-util libxml-2.0 vconf)

FOREACH(flag ${pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include
					/usr/include/libxml2
					)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS} -Werror -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -Wdeclaration-after-statement -Wmissing-declarations -Wredundant-decls -Wcast-align")

ADD_DEFINITIONS("-DFEATURE_TLOG_DEBUG")
ADD_DEFINITIONS("-DTCORE_LOG_TAG=\"IMC\"")

MESSAGE(${CMAKE_C_FLAGS})
MESSAGE(${CMAKE_EXE_LINKER_FLAGS})

SET(SRCS
	src/desc_imc.c
	src/imc_modem.c
	src/imc_common.c
	src/imc_network.c
	src/imc_sim.c
	src/imc_sat.c
	src/imc_call.c
	src/imc_ss.c
	src/imc_ps.c
	src/imc_sms.c
	src/imc_phonebook.c
	src/imc_sap.c
	src/imc_gps.c
	src/nvm/nvm.c
)



# library build
ADD_LIBRARY(imc-plugin SHARED ${SRCS})
TARGET_LINK_LIBRARIES(imc-plugin ${pkgs_LDFLAGS})
SET_TARGET_PROPERTIES(imc-plugin PROPERTIES PREFIX "" OUTPUT_NAME imc-plugin)


# install
INSTALL(TARGETS imc-plugin
	LIBRARY DESTINATION ${LIB_INSTALL_DIR}/telephony/plugins/modems)

INSTALL(FILES ${CMAKE_SOURCE_DIR}/res/wiki_mcc_mnc_oper_list.sql DESTINATION /tmp RENAME mcc_mnc_oper_list.sql)
INSTALL(FILES ${CMAKE_SOURCE_DIR}/LICENSE DESTINATION /usr/share/license RENAME tel-plugin-imc)

