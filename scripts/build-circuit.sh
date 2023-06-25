set -e
echo "building circuit..."
circom circuits/circuit.circom --r1cs --wasm --sym -o resources
mv resources/circuit_js/circuit.wasm resources/circuit.wasm
rm -rf resources/circuit_js
