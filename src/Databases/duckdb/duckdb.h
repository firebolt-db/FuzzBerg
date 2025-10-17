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
#include <Databases/Database.h>
#include <sys/time.h>
#include <unistd.h>

#include <string>

namespace fuzzberg {
class DuckDB : public DatabaseHandler {
public:
  DuckDB() = default;
  ~DuckDB() = default;

  pid_t ForkTarget() override;
  int8_t fuzz() override;
};

} // namespace fuzzberg
