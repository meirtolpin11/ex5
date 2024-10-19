//
// Created by Mher Tolpin on 27/09/2024.
//

#ifndef UTILS_H
#define UTILS_H

#include <vector>
#include <string>

std::vector<char> string_to_vector(const std::string& str);

std::string vector_to_string(const std::vector<char> &vec);

std::string remove_new_lines(const std::string& input);

#endif //UTILS_H