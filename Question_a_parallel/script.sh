cc encrypter.c -o encrypter -ltfhe-spqlios-avx
cc cloud.c -o cloud -ltfhe-spqlios-avx -fopenmp
cc verifier.c -o verifier -ltfhe-spqlios-avx

./encrypter
echo "-------------------------------------------------"
./cloud
echo "-------------------------------------------------"
./verifier
