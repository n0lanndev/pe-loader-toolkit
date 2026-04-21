#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <stdexcept>
#include <cstdint>

constexpr uint8_t XOR_KEY = 0x5A;

std::vector<uint8_t> loadFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open())
        throw std::runtime_error("Impossible d'ouvrir le fichier.");

    std::streamsize size = file.tellg();
    if (size <= 0)
        throw std::runtime_error("Fichier vide ou invalide.");

    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(static_cast<size_t>(size));
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size))
        throw std::runtime_error("Erreur lors de la lecture du fichier.");

    return buffer;
}

void xorEncrypt(std::vector<uint8_t>& data) {
    for (auto& byte : data) {
        byte ^= XOR_KEY;
    }
}

void generateHeader(const std::vector<uint8_t>& data, const std::string& outputFile) {
    std::ofstream file(outputFile);
    if (!file.is_open())
        throw std::runtime_error("Impossible de créer le fichier de sortie.");

    file << "#pragma once\n\n";
    file << "#include <cstdint>\n\n";
    file << "inline constexpr std::size_t payload_size = " << data.size() << ";\n\n";
    file << "inline constexpr std::uint8_t payload[] = {\n    ";

    file << std::hex << std::setfill('0');

    for (size_t i = 0; i < data.size(); ++i) {
        file << "0x" << std::setw(2) << static_cast<int>(data[i]) << ",";

        if ((i + 1) % 16 == 0)
            file << "\n    ";
        else
            file << " ";
    }

    file << std::dec << "\n};\n";
}

int main(int argc, char* argv[]) {
    try {
        if (argc < 3) {
            std::cerr << "Usage: packer <input_file> <output_header>\n";
            return 1;
        }

        std::string inputFile = argv[1];
        std::string outputFile = argv[2];

        auto data = loadFile(inputFile);
        xorEncrypt(data);
        generateHeader(data, outputFile);

        std::cout << "Payload généré avec succès : " << outputFile << "\n";
        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "Erreur: " << e.what() << "\n";
        return 1;
    }
}