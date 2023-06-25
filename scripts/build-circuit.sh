set -e
echo "building circuit..."
# circom circuits/circuit.circom --r1cs --wasm -p bls12381 --O2 --inspect -o resources
circom circuits/circuit.circom --r1cs --wasm --O2 --inspect -o resources
mv resources/circuit_js/circuit.wasm resources/circuit.wasm
rm -rf resources/circuit_js
echo "generating verification key..."
npm exec snarkjs -- groth16 setup resources/circuit.r1cs pot/pot18_final.ptau resources/circuit_0000.zkey
npm exec snarkjs -- zkey contribute resources/circuit_0000.zkey resources/circuit_0001.zkey --name="1st Contributor" -v -e=$(openssl rand -hex 10240)
#npm exec snarkjs -- zkey contribute resources/circuit_0001.zkey resources/circuit_0002.zkey --name="2nd Contributor" -v -e=$(openssl rand -hex 10240)
# last circuit_000x.zkey should go in here
#npm exec snarkjs -- zkey beacon resources/circuit_0000.zkey resources/circuit_final.zkey $(curl https://drand.cloudflare.com/public/latest | jq -r ".randomness") 20
npm exec snarkjs -- zkey beacon resources/circuit_0001.zkey resources/circuit_final.zkey $(openssl rand -hex 128) 20
#npm exec snarkjs -- zkey verify resources/circuit.r1cs pot/pot18_final.ptau resources/circuit_final.zkey
rm -rf resources/circuit_0000.zkey
rm -rf resources/circuit_0001.zkey
rm -rf resources/circuit_0002.zkey
