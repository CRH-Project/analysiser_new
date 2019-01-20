#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>

#include "src/roll.h"
#include "src/HttpTypeSize.h"

std::vector<std::string> types{
    "text", "image", "audio", "video", "application"
};

int main(int argc, char *argv[])
{
    if(argc!=2)
    {
        fprintf(stderr,"Usage %s <pcap_filename>\n", argv[0]);
        exit(-1);
    }

    roll(argv[1], httpTS_roller);

    std::vector<size_t> temp_vec;
    for(auto &type : types)
    {
        std::ofstream fout(std::string(argv[1])+"-"+type+".txt", std::ios::out);
        temp_vec.clear();
        getTypeSizeVector(type, temp_vec);
//        std::sort(temp_vec.begin(), temp_vec.end());
        for(auto s : temp_vec)
            fout<<s<<std::endl;
    }
}



