/*

  Fuzzberg - a fuzzer for Iceberg and other file-format database readers
  ----------------------------------------------------------------------

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

#include <FileFormats/csv.h>
#include <FileFormats/iceberg.h>
#include <FileFormats/parquet.h>
#include <time.h>
#include <wait.h>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <random>
#include <string>
#include <vector>

// Base class for target databases

namespace fuzzberg {

class DatabaseHandler {
 public:
  DatabaseHandler() = default;
  ~DatabaseHandler() = default;

#define RADAMSA_BUFFER_SIZE 1024 * 10  // 10 KB buffer for Radamsa mutations

  // Buffers and corpus
  char* radamsa_output = new char[RADAMSA_BUFFER_SIZE];  // allocate buffer for Radamsa mutations
  corpus_buffer metadata_corpus;                         // corpus for Iceberg fuzzer
  corpus_buffer manifest_corpus;
  corpus_buffer input_corpus;  // corpus for other format fuzzers (CSV, Parquet)

  // Database and fuzzing state
  size_t crash_size = 0;             // size of the crash file
  size_t execs = 0;                  // number of queries executed
  std::vector<std::string> queries;  // queries to execute

  // Target process and connection
  CURL* curl = nullptr;
  pid_t target_pid;  // child pid

  // Configuration
  std::string file_format;               // file-format to fuzz
  std::vector<char*> execv_args;         // args to launch target binary
  std::string db_url;                    // database URL
  std::string fuzzer_mutation_path;      // path to dir to write file mutations
  std::optional<std::string> s3_bucket;  // S3 bucket (optional, only for Iceberg fuzzing)
  std::string _auth_token;  // Auth token for the database server (might make std::optional later)

  // Abstract interfaces
  virtual pid_t ForkTarget() = 0;  // launches target db (override in derived classes)
  virtual int8_t fuzz() = 0;       // calls a file-format fuzzer (override in derived classes)

  // Load seed corpus
  inline void _load_corpus(std::string& corpus_dir) {
    FileFuzzerBase fuzzer_base;
    fuzzer_base._corpus_info = {this->file_format, this->s3_bucket};

    for (const auto& entry : std::filesystem::recursive_directory_iterator(corpus_dir)) {
      if (entry.is_regular_file()) {
        if (this->file_format != "iceberg") {
          auto return_stat = fuzzer_base.load_corpus(entry.path());
          // check for empty corpus entries
          if (return_stat.corpus != nullptr && return_stat.size != 0) {
            this->input_corpus.emplace_back(return_stat);
          } else
            continue;
        }
        // Iceberg corpus loading
        else {
          if (entry.path().extension() == ".json") {  // JSON corpus for metadata layer fuzzing
            auto return_stat = fuzzer_base.load_corpus(entry.path());
            // check for empty corpus entries
            if (return_stat.corpus != nullptr && return_stat.size != 0) {
              this->metadata_corpus.emplace_back(return_stat);
            } else
              continue;
          } else {
            if (entry.path().extension() == ".avro") {  // Avro corpus for manifest-list fuzzing
              auto return_stat = fuzzer_base.load_corpus(entry.path());
              // check for empty corpus entries
              if (return_stat.corpus != nullptr && return_stat.size != 0) {
                this->manifest_corpus.emplace_back(return_stat);
              } else
                continue;
            }
          }
        }
      }
    }
  }

  inline void _write_crash(char* crash_string, std::string& crash_dir) {
    FileFuzzerBase fuzzer_base;
    return fuzzer_base.write_crash(crash_string, this->crash_size, crash_dir);
  }

  inline void cleanup() {
    delete[] radamsa_output;
    radamsa_output = nullptr;
    curl_easy_cleanup(curl);
    curl = nullptr;
    if (file_format == "iceberg") {
      for (auto& corpus_stat : metadata_corpus) {
        delete[] corpus_stat.corpus;
        corpus_stat.corpus = nullptr;
      }
      for (auto& corpus_stat : manifest_corpus) {
        delete[] corpus_stat.corpus;
        corpus_stat.corpus = nullptr;
      }
    }

    else {
      for (auto& corpus_stat : input_corpus) {
        delete[] corpus_stat.corpus;
        corpus_stat.corpus = nullptr;
      }
    }
  }
};

}  // namespace fuzzberg
