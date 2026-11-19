cmake_minimum_required(VERSION 3.16)
project(HoneyPatch LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)  # clangd 등 IDE 인덱싱용
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()
add_compile_options(-Wall -Wextra)

# ---------------------------------------------------------------------------
# 모듈별 정적 라이브러리. 의존 방향:
#   common  <-  http / detect / hpfork / decoy  <-  app  <-  main
# http·detect·hpfork·decoy 는 서로를 참조하지 않는다 (common/types.h 로만 연결).
# ---------------------------------------------------------------------------
add_library(hp_common STATIC src/common/logger.cpp)
target_include_directories(hp_common PUBLIC src)

add_library(hp_http STATIC src/http/http_parser.cpp src/http/http_server.cpp)
target_link_libraries(hp_http PUBLIC hp_common)

add_library(hp_detect STATIC src/detect/detector.cpp)
target_link_libraries(hp_detect PUBLIC hp_common)

add_library(hp_fork STATIC src/hpfork/hp_fork.cpp)
target_link_libraries(hp_fork PUBLIC hp_common)

add_library(hp_decoy STATIC src/decoy/redaction.cpp src/decoy/decoy_response.cpp)
target_link_libraries(hp_decoy PUBLIC hp_common)

add_library(hp_app STATIC src/app/app.cpp)
target_link_libraries(hp_app PUBLIC hp_detect hp_fork hp_decoy)

add_executable(honeypatch_server src/main.cpp)
target_link_libraries(honeypatch_server PRIVATE hp_app hp_http)

# ---------------------------------------------------------------------------
# 테스트: 단위 테스트(C++) + 고정 검증 사례 3종(Python, 3개 모드)
# ---------------------------------------------------------------------------
enable_testing()
add_executable(unit_tests tests/unit_tests.cpp)
target_link_libraries(unit_tests PRIVATE hp_http hp_detect hp_decoy)
add_test(NAME unit COMMAND unit_tests)

find_package(Python3 COMPONENTS Interpreter)
if(Python3_FOUND)
  add_test(NAME cases
           COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tests/run_cases.py
                   --bin $<TARGET_FILE:honeypatch_server>
                   --root ${PROJECT_SOURCE_DIR}/www
                   --out ${PROJECT_BINARY_DIR}/results)
endif()
