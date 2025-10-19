/*

  Fuzzberg - a fuzzer for Iceberg and other file-format readers
  --------------------------------------------------------------

  Copyright 2025 [Firebolt Analytics, Inc.]. All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

#pragma once

extern "C" {
#include <radamsa.h>
}
#include <fcntl.h>
#include <sys/mman.h>
#include <wait.h>

#include <csignal>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <optional>
#include <random>
#include <string>

#include "HTTPHandler.h"

// Base class for file format fuzzers

namespace fuzzberg {

struct corpus_stat {
  size_t size;
  char *corpus = nullptr;
};

using query_set = std::vector<std::string>;
using corpus_buffer = std::vector<corpus_stat>;

class FileFuzzerBase : public HTTPHandler {
public:
  FileFuzzerBase() = default;
  ~FileFuzzerBase() = default;

  // Extra metadata for corpus loading (required for Iceberg fuzzer)
  struct corpus_info {
    std::string format;
    std::optional<std::string> s3_bucket = std::nullopt;
  } _corpus_info;

  size_t execs = 0;            // number of queries executed
  size_t crash_input_size = 0; // size of the input that caused crash

  corpus_stat load_corpus(const std::filesystem::path &input_corpus_path);
  void write_crash(char *crash_string, size_t crash_size,
                   std::string &crash_dir);

  // Radamsa mutation buffer size
  static constexpr size_t RADAMSA_BUFFER_SIZE =
      1024 * 1024; // 1 MB buffer (we define this inside Database.h too as the
                   // crash writing function needs it)

protected:
  // Override this in child format-fuzzers
  virtual int8_t Fuzz(std::vector<std::string> &queries, std::string &db_url,
                      corpus_buffer &input_corpus, char *&radamsa_buffer,
                      size_t &execs, CURL *curl) {
    return 0;
  }

  void write_radamsa_mutation(char *&buffer, FILE *&mutated_file_ptr,
                              size_t length);
  uint32_t seed_generator();
};
} // namespace fuzzberg