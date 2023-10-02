set -e
echo "building aes circuit..."
circom circuits/aes/circuit.circom --r1cs --wasm --O2 --inspect -o resources/aes/
mv resources/aes/circuit_js/circuit.wasm resources/aes/circuit.wasm
rm -rf resources/aes/circuit_js
echo "generating verification key..."
npm exec snarkjs -- groth16 setup resources/aes/circuit.r1cs pot/pot_final.ptau resources/aes/circuit_0000.zkey
npm exec snarkjs -- zkey contribute resources/aes/circuit_0000.zkey resources/aes/circuit_0001.zkey --name="1st Contributor" -v -e=$(openssl rand -hex 10240)
npm exec snarkjs -- zkey beacon resources/aes/circuit_0001.zkey resources/aes/circuit_final.zkey $(openssl rand -hex 128) 20
rm -rf resources/aes/circuit_0000.zkey
rm -rf resources/aes/circuit_0001.zkey
rm -rf resources/aes/circuit_0002.zkey
