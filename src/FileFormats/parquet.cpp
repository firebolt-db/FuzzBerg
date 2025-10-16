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

// Fuzz Parquet as follows:
// 1. Retain the Parquet file format (header, footer, file metadata..)
// 2. Mutate only the data pages using Radamsa
// 3. Re-generate a valid Parquet file format with mutated data pages

#include "parquet.h"

namespace fuzzberg {
ParquetFuzzer::ParquetFuzzer(pid_t target_pid, std::string& fuzzer_mutation_path) {
  std::cout << "Entered Parquet fuzzer: " << fuzzer_mutation_path << std::endl;

  mutated_file_ptr = std::fopen((fuzzer_mutation_path + "/fuzz.parquet").c_str(), "wb");

  if (!mutated_file_ptr) {
    std::cerr << "Could not create or open file for writing mutations: " << fuzzer_mutation_path
              << std::endl;
    perror("fopen");
    kill(target_pid, SIGKILL);
    exit(1);
  }
  radamsa_init();
}

int8_t ParquetFuzzer::Fuzz(std::vector<std::string>& queries, std::string& db_url,
                           corpus_buffer& input_corpus, char*& radamsa_buffer, size_t& execs,
                           CURL* curl) {
  auto seed = seed_generator();
  srand(seed);

  char* data_pages = nullptr;
  char* footer_length_field = nullptr;
  char* file_metadata_start = nullptr;
  char* page_start = nullptr;
  uint32_t meta_size = 0;

  while (1) {
  rand:
    uint64_t rand_ = rand() % input_corpus.size();

    // Retain Parquet file format (excluding pages) in mutations to generate more fuzz coverage
    // (https://github.com/apache/parquet-format/tree/master?tab=readme-ov-file#file-format)

    if (input_corpus[rand_].size < 12) {  // 4 * 2 magic bytes + 4 bytes of metadata size field
      std::cout << "Selected corpus is too small to contain valid Parquet data.\n" << std::endl;
      goto rand;  // Pick a new random corpus
    }

    // Page header metadata starts after the first 4 magic bytes
    page_start = input_corpus[rand_].corpus + 4;

    // Locate footer length field (4 bytes before the last 4 magic bytes)
    footer_length_field = input_corpus[rand_].corpus + input_corpus[rand_].size - 8;

    // Read 4 bytes (little endian) from footer length to get file metadata size
    meta_size = 0;
    meta_size |= static_cast<unsigned char>(footer_length_field[0]);
    meta_size |= static_cast<unsigned char>(footer_length_field[1]) << 8;
    meta_size |= static_cast<unsigned char>(footer_length_field[2]) << 16;
    meta_size |= static_cast<unsigned char>(footer_length_field[3]) << 24;

    // check for invalid file metadata sizes to avoid bad allocations
    // 1. metadata size should be positive
    // 2. metadata size should be < total file size - 12 (4 * 2 magic bytes + 4 bytes of metadata
    // size field)
    // 3. RADAMSA_BUFFER_SIZE should be > metadata size + 12
    if (meta_size <= 0 || meta_size > input_corpus[rand_].size - 12 ||
        meta_size > (RADAMSA_BUFFER_SIZE - 12)) {
      // std::cout << "Invalid metadata size: " << meta_size << "\n" << std::endl;
      goto rand;  // Pick a new random corpus
    }

    // Start address of file metadata
    file_metadata_start = footer_length_field - meta_size;
    // one last boundary check, although meta_size has been validated above
    if (file_metadata_start < input_corpus[rand_].corpus + 4) {
      // std::cout << "Metadata start is before data pages\n" << std::endl;
      goto rand;  // Pick a new random corpus
    }

    // There should be at least 1 byte of page data that we can mutate
    if (file_metadata_start - page_start > 0) {
      data_pages = new char[file_metadata_start - page_start];
      if (!data_pages) {
        std::cout << "Memory allocation failed\n" << std::endl;
        goto rand;  // Pick a new random corpus
      }
    } else {
      // std::cerr << "Data page size is not positive" << std::endl;
      goto rand;  // Pick a new random corpus
    }

    std::memcpy(
        data_pages, page_start,
        file_metadata_start - page_start);  // copy only the data pages into buffer for mutation

    // We trust Radamsa to keep output_size <= RADAMSA_BUFFER_SIZE - (meta_size + 12)
    auto output_size =
        radamsa(reinterpret_cast<uint8_t*>(data_pages), file_metadata_start - page_start,
                reinterpret_cast<uint8_t*>(radamsa_buffer) + 4,
                RADAMSA_BUFFER_SIZE - (meta_size + 12), seed);

    // recreate Parquet format with radamsa_output
    memcpy(radamsa_buffer, "PAR1", 4);
    memcpy(radamsa_buffer + 4 + output_size, file_metadata_start, meta_size);
    memcpy(radamsa_buffer + 4 + output_size + meta_size, footer_length_field, 4);
    memcpy(radamsa_buffer + 4 + output_size + meta_size + 4, "PAR1", 4);

    write_radamsa_mutation(radamsa_buffer, mutated_file_ptr, 4 + output_size + meta_size + 4 + 4);

    // send query
    for (auto const& query : queries) {
      execs++;
      std::cout << "\nQuery : " << query << "\n" << std::endl;
      if (send_query(curl, query, db_url, "") != 1) {
        crash_input_size = 4 + output_size + meta_size + 4 + 4;  // save size of the mutated file
        delete[] data_pages;
        data_pages = nullptr;
        return -1;  // return -1 if query exec fails
      } else
        continue;
    }
    delete[] data_pages;
  }

  return 0;
}
}  // namespace fuzzberg
