//
// Created by Mher Tolpin on 27/09/2024.
//

#include "utils.h"

#include <vector>
#include <string>

std::vector<char> string_to_vector(const std::string& str) {
    return {str.begin(), str.end()};
}

std::string vector_to_string(const std::vector<char> &vec) {
    return {vec.begin(), vec.end()};
}

std::string remove_new_lines(const std::string& input) {
    std::string output = input;
    output.erase(std::remove_if(output.begin(), output.end(), [](char c) {
        return c == '\n' || c == '\r'; // Remove both LF and CR
    }), output.end());
    return output;
}