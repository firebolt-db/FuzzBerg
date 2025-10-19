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

#include "csv.h"

namespace fuzzberg {
CSVFuzzer::CSVFuzzer(pid_t target_pid, std::string fuzzer_mutation_path) {
  std::cout << "Entered CSV fuzzer: " << std::endl;
  mutated_file_ptr =
      std::fopen((fuzzer_mutation_path + "/fuzz.csv").c_str(), "wb");

  if (!mutated_file_ptr) {
    std::cerr << "Could not create or open file for writing mutations: "
              << fuzzer_mutation_path << std::endl;
    perror("fopen");
    kill(target_pid, SIGKILL);
    exit(1);
  }

  radamsa_init();
}

int8_t CSVFuzzer::Fuzz(std::vector<std::string> &queries, std::string &db_url,
                       corpus_buffer &input_corpus, char *&radamsa_buffer,
                       size_t &execs, CURL *curl) {
  srand(seed_generator()); // seeding rand()

  while (1) {
    size_t rand_ = rand() % input_corpus.size();
    auto output_size = radamsa(
        reinterpret_cast<uint8_t *>(input_corpus[rand_].corpus),
        input_corpus[rand_].size, reinterpret_cast<uint8_t *>(radamsa_buffer),
        RADAMSA_BUFFER_SIZE, seed_generator());

    write_radamsa_mutation(radamsa_buffer, mutated_file_ptr, output_size);

    // send query
    for (auto const &query : queries) {
      execs++;
      std::cout << "\nQuery : " << query << "\n" << std::endl;
      auto ret_code = send_query(curl, query, db_url, "");
      if (ret_code != CURLE_OK) {
        if (ret_code == CURLE_OPERATION_TIMEDOUT){
          std::cerr << "Target timed out, kill child and stop fuzzing"
                    << std::endl;
          kill(this->_target_pid, SIGKILL);
          exit(1);
        }
        // save size of the crash file
        crash_input_size = output_size;
        return -1;
      } else
        continue;
    }
    // clear the buffer for next iteration
    memset(radamsa_buffer, 0, output_size);
  }
  return 0;
}
} // namespace fuzzberg
