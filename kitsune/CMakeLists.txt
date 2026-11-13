# CMakeLists.txt
#
# Kitsune - a QML interface on top of the Wireshark engine,
# designed for training and education.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

# Kitsune targets the current Qt 6 LTS. It builds with Qt 6.4 and
# later; features from newer releases are enabled at run time.
find_package(Qt6 6.4 REQUIRED COMPONENTS Core Gui Qml Quick QuickControls2)
if(Qt6_VERSION VERSION_LESS 6.5)
	message(STATUS "Kitsune: building with Qt ${Qt6_VERSION}; Qt 6.5 or later is recommended")
endif()

set(CMAKE_AUTOMOC ON)

# qmlcachegen in Qt 6.4 compiles singleton lookups into a loop that
# never ends; skip ahead-of-time QML compilation there.
set(KITSUNE_QML_CACHEGEN_OPTION)
if(Qt6_VERSION VERSION_LESS 6.5)
	set(KITSUNE_QML_CACHEGEN_OPTION NO_CACHEGEN)
endif()

if(Qt6_VERSION VERSION_GREATER_EQUAL 6.5)
	qt_standard_project_setup(REQUIRES 6.5)
endif()

set(KITSUNE_SRC
	main.cpp
	engine/captureengine.cpp
	engine/captureengine.h
	engine/kitsunesettings.cpp
	engine/kitsunesettings.h
	models/packetlistmodel.cpp
	models/packetlistmodel.h
	${CMAKE_SOURCE_DIR}/app/wireshark_flavor.c
)

qt_add_executable(kitsune ${KITSUNE_SRC})

set(KITSUNE_QML
	qml/Main.qml
	qml/Theme.qml
	qml/Icon.qml
	qml/TopBar.qml
	qml/SideBar.qml
	qml/NavButton.qml
	qml/FileInfoBar.qml
	qml/PacketListView.qml
	qml/CaptureStatusPanel.qml
	qml/PlaceholderView.qml
	qml/ThemeSwitcher.qml
	qml/WelcomeView.qml
)
# Serve the files next to the module's qmldir so that they see each
# other, and the Theme singleton, on every Qt 6 version.
foreach(qml_file ${KITSUNE_QML})
	get_filename_component(qml_name ${qml_file} NAME)
	set_source_files_properties(${qml_file} PROPERTIES QT_RESOURCE_ALIAS ${qml_name})
endforeach()
set_source_files_properties(qml/Theme.qml PROPERTIES QT_QML_SINGLETON_TYPE TRUE)

qt_add_qml_module(kitsune
	URI Kitsune
	VERSION 1.0
	RESOURCE_PREFIX /qt/qml
	${KITSUNE_QML_CACHEGEN_OPTION}
	QML_FILES ${KITSUNE_QML}
)

target_include_directories(kitsune PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_SOURCE_DIR}
	${CMAKE_BINARY_DIR}
)

target_link_libraries(kitsune PRIVATE
	Qt6::Core
	Qt6::Gui
	Qt6::Qml
	Qt6::Quick
	Qt6::QuickControls2
	ui
	wiretap
	epan
	wsutil
)

# Wireshark's C headers are not written for C++'s stricter warnings.
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
	target_compile_options(kitsune PRIVATE -Wno-error)
endif()

set_target_properties(kitsune PROPERTIES
	WIN32_EXECUTABLE ON
	MACOSX_BUNDLE ON
	RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/run
)

install(TARGETS kitsune
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
	BUNDLE DESTINATION .
)
