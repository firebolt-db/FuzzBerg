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

#include "FileFuzzerBase.h"

namespace fuzzberg {

// Generate a random seed
uint32_t FileFuzzerBase::seed_generator() {
  uint32_t init_seed;
  std::mt19937 gen;
  std::FILE *f = std::fopen("/dev/urandom", "rb");
  if (f) {
    if (fread(&init_seed, 1, 4, f) == 4) {
      gen.seed(init_seed);

    } else {
      // Seeding without /dev/random
      gen.seed(static_cast<uint32_t>(time(NULL)) ^ getpid() ^ clock());
    }
    std::fclose(f);
  } else {
    gen.seed(static_cast<uint32_t>(time(NULL)) ^ getpid() ^ clock());
  }

  uint32_t seed = gen();
  return seed;
}

void FileFuzzerBase::write_crash(char *crash_string, size_t crash_size,
                                 std::string &crash_dir) {
  std::filesystem::directory_entry _crash_dir(crash_dir);

  if (!_crash_dir.exists()) {
    std::filesystem::create_directories(crash_dir);
  }
  if (_crash_dir.is_directory()) {
    std::string crash_file = _crash_dir.path().string() + "crash.txt";
    FILE *crash_fp = std::fopen(crash_file.c_str(), "w");
    if (crash_fp) {
      if (std::fwrite(crash_string, 1, crash_size, crash_fp) == crash_size) {
        std::cout << "Crash data written successfully to: " << crash_file
                  << "\n";
      }
      std::fclose(crash_fp);
    } else {
      FILE *tmp_crash = std::fopen("/tmp/crash.txt", "w");
      if (tmp_crash) {
        if (std::fwrite(crash_string, 1, crash_size, tmp_crash) == crash_size) {
          std::cout << "Crash data written successfully to: "
                    << "/tmp/crash.txt" << "\n";
        } else {
          std::cout
              << "Could not write to crash file, writing to STDOUT for repro";
          std::fwrite(crash_string, 1, crash_size, stdout);
        }
        std::fclose(tmp_crash);
      }
    }
  }
}

void FileFuzzerBase::write_radamsa_mutation(char *&buffer,
                                            FILE *&mutated_file_ptr,
                                            size_t length) {
  // we check for valid mutated_file_ptr in main()
  ftruncate(fileno(mutated_file_ptr),
            0); 
  rewind(mutated_file_ptr);

  if (std::fwrite(buffer, 1, length, mutated_file_ptr) == length) {
    if (std::fflush(mutated_file_ptr) != 0) {
      std::cerr << "fflush" << std::endl;
      exit(1);
    }
  } else {
    std::cout << "\nMutated data could not be written, please check if "
                 "filepath exists\n"
              << std::endl;
    exit(1);
  }
}

corpus_stat FileFuzzerBase::load_corpus(const std::filesystem::path &path) {
  size_t size = std::filesystem::file_size(path.string());

  char *input = new char[size];

  std::FILE *input_corp = std::fopen(path.string().c_str(), "r");
  if (!input_corp) {
    std::cerr << "Failed to open corpus file: " << path.string() << std::endl;
    delete[] input;
    exit(1);
  }
  size_t read_bytes = std::fread(input, 1, size, input_corp);
  std::fclose(input_corp);

  if (read_bytes != size) {
    std::cerr << "Failed to read entire corpus file: " << path.string()
              << std::endl;
    delete[] input;
    exit(1);
  }

  /* For fuzzing Iceberg Metadata: modify necessary fields here
  to avoid repeated parsing in hot paths during fuzzing */

  if (this->_corpus_info.format.compare("iceberg") == 0 &&
      path.extension() == ".json") {
    nlohmann::json metadata_json;
    // *input is non-null terminated, so specify exact length to read in
    // nlohmann::json::parse
    metadata_json = nlohmann::json::parse(input, input + size, nullptr, false);

    if (metadata_json.is_discarded() ||
        !(metadata_json.contains("current-snapshot-id"))) {
      std::cerr << "Parsing failed, moving to the next corpus" << "\n"
                << std::endl;
      delete[] input;
      return (corpus_stat{0, nullptr});
    }

    // Start modifying the JSON object
    metadata_json["location"] = *this->_corpus_info.s3_bucket;
    if (metadata_json.contains("metadata-log")) {
      metadata_json.erase("metadata-log");
    }
    if (metadata_json.contains("snapshot-log")) {
      metadata_json.erase("snapshot-log");
    }
    for (auto &snap : metadata_json["snapshots"]) {
      if (snap.is_object()) {
        snap["manifest-list"] =
            std::string("s3://" + *this->_corpus_info.s3_bucket +
                        "/metadata/manifest_list.avro");
      }
    }

    std::string dumped_json =
        metadata_json.dump(-1,    // no prettifying
                           ' ',   // indent char (unused)
                           false, // ensure_ascii false
                           nlohmann::json::error_handler_t::replace);

    char *updated_metadata = new char[dumped_json.size() + 1];
    memcpy(updated_metadata, dumped_json.data(), dumped_json.size());
    updated_metadata[dumped_json.size()] = '\0'; // Add null terminator
    return (corpus_stat{dumped_json.size(), updated_metadata});
  }

  corpus_stat stat = {size, input};
  return stat;
}

} // namespace fuzzberg
