#!/bin/bash
#Phillip Wellheuser
#Compiles all otp program

echo Compiling One Time Pad program
echo

gcc -g -std=gnu99 otp_enc.c -o otp_enc
gcc -g -std=gnu99 otp_enc_d.c -o otp_enc_d
gcc -g -std=gnu99 otp_dec.c -o otp_dec
gcc -g -std=gnu99 otp_dec_d.c -o otp_dec_d
gcc -g -std=gnu99 keygen.c -o keygen
chmod +wrx p4gradingscript

echo Done compiling.
echo 

echo Running basic tests to check performance:
echo

echo contents of plaintext1:
cat plaintext1
echo

./otp_enc_d 57171 &
./otp_dec_d 57172 &
./keygen 1024 > mykey
echo mykey:
cat mykey
echo
./otp_enc plaintext1 mykey 57171 > ciphertext1
echo ciphertext1:
cat ciphertext1
echo

./otp_dec ciphertext1 mykey 57172 > plaintext1_a

./keygen 1024 > mykey2
./otp_dec ciphertext1 mykey2 57172 > plaintext1_b

echo plaintext1_a:
cat plaintext1_a
echo
echo plaintext1_b:
cat plaintext1_b
echo

echo comparing plaintext1 plaintext1_a:
cmp plaintext1 plaintext1_a
echo $?
echo

echo comparing plaintext1 plaintext1_b:
cmp plaintext1 plaintext1_b
echo $?
echo

#./otp_enc plaintext5 mykey 57171
#echo $?

#./otp_enc plaintext3 mykey 57172
#echo $?

echo Finished basic testing.