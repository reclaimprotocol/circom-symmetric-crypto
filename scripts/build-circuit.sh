set -e
echo "building circuit..."
# circom circuits/circuit.circom --r1cs --wasm -p bls12381 --O2 --inspect -o resources/chacha20
circom circuits/circuit.circom --r1cs --wasm --O2 --inspect -o resources/chacha20
mv resources/chacha20/circuit_js/circuit.wasm resources/chacha20/circuit.wasm
rm -rf resources/chacha20/circuit_js
echo "generating verification key..."
npm exec snarkjs -- groth16 setup resources/chacha20/circuit.r1cs pot/pot_final.ptau resources/chacha20/circuit_0000.zkey
npm exec snarkjs -- zkey contribute resources/chacha20/circuit_0000.zkey resources/chacha20/circuit_0001.zkey --name="1st Contributor" -v -e=$(openssl rand -hex 10240)
#npm exec snarkjs -- zkey contribute resources/chacha20/circuit_0001.zkey resources/chacha20/circuit_0002.zkey --name="2nd Contributor" -v -e=$(openssl rand -hex 10240)
# last circuit_000x.zkey should go in here
#npm exec snarkjs -- zkey beacon resources/chacha20/circuit_0000.zkey resources/chacha20/circuit_final.zkey $(curl https://drand.cloudflare.com/public/latest | jq -r ".randomness") 20
npm exec snarkjs -- zkey beacon resources/chacha20/circuit_0001.zkey resources/chacha20/circuit_final.zkey $(openssl rand -hex 128) 20
#npm exec snarkjs -- zkey verify resources/chacha20/circuit.r1cs pot/pot18_final.ptau resources/chacha20/circuit_final.zkey
rm -rf resources/chacha20/circuit_0000.zkey
rm -rf resources/chacha20/circuit_0001.zkey
rm -rf resources/chacha20/circuit_0002.zkey
