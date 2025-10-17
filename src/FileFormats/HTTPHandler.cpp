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

#include "HTTPHandler.h"

namespace fuzzberg {

bool HTTPHandler::send_query(CURL *curl, const std::string &query,
                             const std::string &db_url,
                             const std::string &auth_token) {
  char *errbuf = new char[CURL_ERROR_SIZE];
  CURLcode ret;
  curl_off_t post_size = query.length();
  if (!auth_token.empty()) {
    struct curl_slist *list = NULL;
    std::string header_prefix = "F-Authorization: Bearer ";
    std::string auth_header = header_prefix + auth_token;
    list = curl_slist_append(list, auth_header.c_str());
    curl_easy_setopt(curl, CURLOPT_BUFFERSIZE, 102400L);
    curl_easy_setopt(curl, CURLOPT_URL, db_url.c_str());
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, query.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, post_size);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 50L);
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, HTTPHandler::resp);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, NULL);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
    ret = curl_easy_perform(curl);
    if (ret != CURLE_OK) {
      std::cerr << "\nCurl returned error: " << errbuf << "\n" << std::endl;
      curl_slist_free_all(list);
      curl_easy_cleanup(curl);
      return 0;
    }
  } else {
    curl_easy_setopt(curl, CURLOPT_BUFFERSIZE, 102400L);
    curl_easy_setopt(curl, CURLOPT_URL, db_url.c_str());
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, query.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, post_size);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 50L);
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, HTTPHandler::resp);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, NULL);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
    ret = curl_easy_perform(curl);
    if (ret != CURLE_OK) {
      std::cerr << "\nCurl returned error: " << errbuf << "\n" << std::endl;
      curl_easy_cleanup(curl);
      return 0;
    }
  }
  return 1;
}

CURLcode HTTPHandler::curlinit(const std::string &db_url) {
  std::cout << "\nChecking connection to server...\n\n" << std::endl;
  sleep(8);
  CURL *curl_init = curl_easy_init();
  if (curl_init) {
    CURLcode ret;
    curl_easy_setopt(curl_init, CURLOPT_URL, db_url.c_str());
    curl_easy_setopt(curl_init, CURLOPT_CONNECT_ONLY, 1L);
    ret = curl_easy_perform(curl_init);
    if (ret == CURLE_OK) {
      std::cout << "\nConnected..." << std::endl;
      send_query(curl_init, "create database if not exists local_dev_db",
                 db_url, "");
      curl_easy_cleanup(curl_init);
    } else {
      std::cout << "\nDB server not starting, exiting..\n" << std::endl;
    }
    return ret;
  } else {
    std::cout << "\nCurl init failed, exiting..\n" << std::endl;
    exit(1);
  }
}

size_t HTTPHandler::resp(char *ptr, size_t size, size_t resp_size,
                         void *userdata) {
  (void)userdata; // Unused parameter
  (void)size;     // Unused parameter
  char *resp = new char[resp_size + 1];
  std::memcpy(resp, static_cast<const void *>(ptr), resp_size);
  resp[resp_size] = '\0';
  std::cout << "Response: " << resp << std::endl;
  delete[] resp;
  return resp_size;
}

} // namespace fuzzberg
