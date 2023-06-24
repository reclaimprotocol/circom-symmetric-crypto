set -e
npm exec snarkjs -- powersoftau new bls12-381 18 pot18_0000.ptau -v
npm exec snarkjs -- powersoftau contribute pot18_0000.ptau pot18_0001.ptau --name="First contribution" -v -e=$(openssl rand -hex 10240)
npm exec snarkjs -- powersoftau contribute pot18_0001.ptau pot18_0002.ptau --name="Second contribution" -v -e=$(openssl rand -hex 10240)
npm exec snarkjs -- powersoftau export challenge pot18_0002.ptau challenge_0003
npm exec snarkjs -- powersoftau challenge contribute bls12-381 challenge_0003 response_0003 -e=$(openssl rand -hex 10240)
npm exec snarkjs -- powersoftau import response pot18_0002.ptau response_0003 pot18_0003.ptau -n="Third contribution"
npm exec snarkjs -- powersoftau verify pot18_0003.ptau
npm exec snarkjs -- powersoftau beacon pot18_0003.ptau pot18_beacon.ptau $(curl https://beacon.nist.gov/beacon/2.0/pulse/last | jq -r ".pulse.outputValue") 10 -n="Final Beacon"
npm exec snarkjs -- powersoftau prepare phase2 pot18_beacon.ptau pot18_final.ptau -v
npm exec snarkjs -- powersoftau verify pot18_final.ptau