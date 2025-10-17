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

#include "firebolt-core.h"

namespace fuzzberg {

pid_t FireboltCore::ForkTarget() {
  pid_t pid = fork();
  if (pid < 0) {
    perror("fork failed");
    exit(1);
  } else if (pid == 0) { // Child process
    execv(execv_args[0], execv_args.data());
    perror("execv failed");
    exit(1);
  }

  // Parent
  FileFuzzerBase fuzzer_base;
  auto init_code = fuzzer_base.curlinit(db_url); // Test connection to target
  if (init_code != CURLE_OK) {
    std::cerr << "\nConnection to local server failed, fuzzer exiting..\n"
              << std::endl;
    exit(1);
  } else {
    this->curl = curl_easy_init(); // re-use CURL handle to speed up fuzzing
    std::cout << "Start fuzzing...\n";
    this->target_pid = pid; // set child PID in fuzzer
  }
  return target_pid;
}

int8_t FireboltCore::fuzz() {
  // CSV Fuzzer
  if (file_format == "csv") {
    CSVFuzzer csv_fuzzer(this->target_pid, this->fuzzer_mutation_path);
    auto status =
        csv_fuzzer.Fuzz(this->queries, this->db_url, this->input_corpus,
                        this->radamsa_output, this->execs, this->curl);
    if (status == -1) {
      return -1;
    }
  }
  // Parquet Fuzzer
  else if (file_format == "parquet") {
    ParquetFuzzer parquet_fuzzer(this->target_pid, this->fuzzer_mutation_path);
    auto status =
        parquet_fuzzer.Fuzz(this->queries, this->db_url, this->input_corpus,
                            this->radamsa_output, execs, this->curl);
    if (status == -1) {
      crash_size = parquet_fuzzer.crash_input_size;
      return -1;
    }
  }
  // Iceberg Fuzzer
  else if (file_format == "iceberg") {
    IcebergFuzzer iceberg_fuzzer(this->target_pid, this->fuzzer_mutation_path);

    // For Iceberg fuzzing, we start the loop here as there is sequential
    // fuzzing logic involved
    while (1) {
      auto status = iceberg_fuzzer.fuzz_metadata_random(
          this->queries, this->db_url, this->radamsa_output, this->execs,
          this->curl, this->metadata_corpus);
      if (status == -1) {
        return -1;
      }
      status = iceberg_fuzzer.fuzz_metadata_structured(
          this->queries, this->db_url, this->radamsa_output, this->execs,
          this->curl);
      if (status == -1) {
        return -1;
      }
      status = iceberg_fuzzer.fuzz_manifest_list_structured(
          this->queries, this->db_url, this->metadata_corpus,
          this->radamsa_output, this->execs, this->curl);
      if (status == -1) {
        return -1;
      }
    }
  } else {
    std::cerr << "Unsupported file format: " << file_format
              << ". Supported formats are: csv, parquet, iceberg." << std::endl;
  }

  return 0;
}
} // namespace fuzzberg
