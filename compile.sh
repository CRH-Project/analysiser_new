mkdir -p build
cd build
cmake -DCMAKE_INSTALL_PREFIX=.. ..
make install -j4
cd ..
touch build.sh
