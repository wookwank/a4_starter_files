# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION ${CMAKE_VERSION}) # this file comes with cmake

# If CMAKE_DISABLE_SOURCE_CHANGES is set to true and the source directory is an
# existing directory in our source tree, calling file(MAKE_DIRECTORY) on it
# would cause a fatal error, even though it would be a no-op.
if(NOT EXISTS "/Users/dannykim/Desktop/UMich/Fall 2024/EECS 489/a4_starter_files/build/_deps/websocketspp-src")
  file(MAKE_DIRECTORY "/Users/dannykim/Desktop/UMich/Fall 2024/EECS 489/a4_starter_files/build/_deps/websocketspp-src")
endif()
file(MAKE_DIRECTORY
  "/Users/dannykim/Desktop/UMich/Fall 2024/EECS 489/a4_starter_files/build/_deps/websocketspp-build"
  "/Users/dannykim/Desktop/UMich/Fall 2024/EECS 489/a4_starter_files/build/_deps/websocketspp-subbuild/websocketspp-populate-prefix"
  "/Users/dannykim/Desktop/UMich/Fall 2024/EECS 489/a4_starter_files/build/_deps/websocketspp-subbuild/websocketspp-populate-prefix/tmp"
  "/Users/dannykim/Desktop/UMich/Fall 2024/EECS 489/a4_starter_files/build/_deps/websocketspp-subbuild/websocketspp-populate-prefix/src/websocketspp-populate-stamp"
  "/Users/dannykim/Desktop/UMich/Fall 2024/EECS 489/a4_starter_files/build/_deps/websocketspp-subbuild/websocketspp-populate-prefix/src"
  "/Users/dannykim/Desktop/UMich/Fall 2024/EECS 489/a4_starter_files/build/_deps/websocketspp-subbuild/websocketspp-populate-prefix/src/websocketspp-populate-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/Users/dannykim/Desktop/UMich/Fall 2024/EECS 489/a4_starter_files/build/_deps/websocketspp-subbuild/websocketspp-populate-prefix/src/websocketspp-populate-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/Users/dannykim/Desktop/UMich/Fall 2024/EECS 489/a4_starter_files/build/_deps/websocketspp-subbuild/websocketspp-populate-prefix/src/websocketspp-populate-stamp${cfgdir}") # cfgdir has leading slash
endif()
